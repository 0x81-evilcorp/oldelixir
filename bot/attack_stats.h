#pragma once
#include <stdint.h>
void attack_stats_init(int cnc_fd);
void attack_stats_reinit(void);
void attack_stats_set_method(uint8_t method_id);
int attack_stats_add(uint8_t method_id);
void attack_stats_inc(uint8_t method_id, uint64_t bytes);
void attack_stats_update(uint8_t method_id, uint64_t pps, uint64_t bps);
void attack_stats_tick(void);
void attack_stats_remove(uint8_t method_id);
void attack_stats_send(void);
void attack_stats_get(uint8_t method_id, uint64_t *pps, uint64_t *bps);
