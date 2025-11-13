#pragma once
#include "includes.h"
#include <stdint.h>
#define FUZZER_MAX_PATTERNS 256
#define FUZZER_MAX_PAYLOAD_SIZE 4096
#define FUZZER_MAX_MUTATIONS 1000
#define FUZZ_TYPE_HTTP 1
#define FUZZ_TYPE_TCP 2
#define FUZZ_TYPE_UDP 3
#define FUZZ_TYPE_TELNET 4
#define FUZZ_TYPE_SSH 5
#define MUTATION_OVERFLOW 1
#define MUTATION_FORMAT_STRING 2
#define MUTATION_SQL_INJECTION 3
#define MUTATION_COMMAND_INJECTION 4
#define MUTATION_PATH_TRAVERSAL 5
#define MUTATION_XSS 6
#define MUTATION_BUFFER_OVERFLOW 7
#define MUTATION_INTEGER_OVERFLOW 8
struct fuzz_pattern {
    uint8_t type;
    uint16_t size;
    char *data;
    uint32_t success_count;
    uint32_t crash_count;
};
struct fuzz_result {
    ipv4_t target_ip;
    uint16_t target_port;
    uint8_t protocol;
    uint8_t mutation_type;
    uint16_t payload_size;
    char payload[FUZZER_MAX_PAYLOAD_SIZE];
    uint8_t success;
    uint32_t response_code;
    char response_data[512];
};
struct exploit_template {
    char name[64];
    uint8_t protocol;
    uint16_t port;
    char base_payload[1024];
    uint16_t base_size;
    uint8_t mutation_types[16];
    uint8_t mutation_count;
};
void fuzzer_init(void);
void fuzzer_start(uint8_t fuzz_type, ipv4_t target_ip, uint16_t target_port);
void fuzzer_stop(void);
struct fuzz_result *fuzzer_get_results(uint32_t *count);
void fuzzer_report_result(struct fuzz_result *result);
void exploit_generator_init(void);
char *exploit_generate_from_fuzz(struct fuzz_result *result);
char *exploit_generate_from_template(const char *template_name, ipv4_t target_ip, uint16_t target_port);
void exploit_save_template(struct exploit_template *tmpl);
void patch_diff_init(void);
void patch_diff_analyze(const char *old_binary, const char *new_binary, const char *output_file);
char *patch_diff_extract_exploit(const char *diff_file);
void zeroday_scanner_init(void);
void zeroday_scanner_start(ipv4_t target_ip, uint16_t target_port, uint8_t protocol);
void zeroday_scanner_stop(void);
void fuzzer_clear_results(void);
