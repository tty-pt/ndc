#ifndef NDC_H
#define NDC_H
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>

#define ENV_KEY_LEN 128
#define ENV_LEN (BUFSIZ * 2)
#define ENV_VALUE_LEN (ENV_LEN - ENV_KEY_LEN - 2)

enum descr_flags {
	DF_CONNECTED = 1,
	// RESERVED = 0x2,
	DF_WEBSOCKET = 4,
	DF_TO_CLOSE = 8,
	DF_ACCEPTED = 16,
	DF_AUTHENTICATED = 32,
	DF_RESERVED = 64,
	// RESERVED = 0x80,
};

enum ndc_srv_flags {
	NDC_WAKE = 1,
	NDC_SSL = 2,
	NDC_ROOT = 4,
	NDC_SSL_ONLY = 8,
	NDC_DETACH = 16,
};

enum ndc_req_flags {
	NDC_POST = 1,
};

typedef void ndc_handler_t(int cfd, char *body);

struct ndc_config {
	char * chroot;
	unsigned flags, port, ssl_port;
	ndc_handler_t *default_handler;
};

typedef void ndc_cb_t(int fd, int argc, char *argv[]);
typedef void (*cmd_cb_t)(int cfd, char *buf, size_t len, int ofd);

struct cmd_slot {
	char *name;
	ndc_cb_t *cb;
	int flags;
};

enum cmd_flags {
	CF_NOAUTH = 1,
	CF_NOTRIM = 2,
};

extern long long ndc_tick;
extern struct ndc_config ndc_config;

void ndc_register(char *name, ndc_cb_t *cb, int flags);
int ndc_main(void);
void ndc_register_handler(char *path, ndc_handler_t handler);

/* define these */
extern void ndc_update(unsigned long long dt) __attribute__((weak));
extern void ndc_vim(int fd, int argc, char *argv[]) __attribute__((weak));
extern int ndc_accept(int fd) __attribute__((weak));
extern int ndc_connect(int fd) __attribute__((weak));
extern void ndc_disconnect(int fd) __attribute__((weak));
extern void ndc_command(int fd, int argc, char *argv[]) __attribute__((weak)); /* will run on any command */
extern void ndc_flush(int fd, int argc, char *argv[]) __attribute__((weak)); /* will run after any command */
extern char *ndc_auth_check(int fd) __attribute__((weak));

/* write to descriptor (might not need) */
int ndc_write(int fd, void *data, size_t len);
#define NDC_TWRITE(fd, msg) ndc_write(fd, msg, strlen(msg))
int ndc_dwritef(int fd, const char *fmt, va_list va);
int ndc_writef(int fd, const char *fmt, ...);
void ndc_wall(const char *msg);

ndc_cb_t do_GET, do_POST, do_sh;

void ndc_pty(int fd, char * const args[]);

int ndc_flags(int fd);
void ndc_close(int fd);
void ndc_set_flags(int fd, int flags);
int ndc_auth(int fd, char *username);
unsigned ndc_env(int fd);
void ndc_cert_add(char *str);
void ndc_certs_add(char *fname);

extern char ndc_execbuf[BUFSIZ * 64];

ssize_t ndc_mmap(char **mapped, char *file);
char *ndc_mmap_iter(char *start, size_t *pos);

void ndc_env_clear(int fd);
int ndc_env_get(int fd, char *target, char *key);
int ndc_env_put(int fd, char *key, char *value);

#endif
