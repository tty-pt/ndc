#ifndef NDC_H
#define NDC_H
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>

enum descr_flags {
	DF_CONNECTED = 1,
	DF_BINARY = 0x2,
	DF_WEBSOCKET = 4,
	DF_TO_CLOSE = 8,
	DF_ACCEPTED = 16,
	DF_AUTHENTICATED = 32,
	DF_RESERVED = 64,
	DF_FIN = 0x80,
};

enum ndc_srv_flags {
	NDC_WAKE = 1,
	NDC_SSL = 2,
	NDC_ROOT = 4,
	/* NDC_CHROOT = 8, */
	NDC_DETACH = 16,
};

struct ndc_config {
	char * chroot,
	     * ssl_crt, 
	     * ssl_key;
	
	unsigned flags, port, ssl_port;
};

typedef void ndc_cb_t(int fd, int argc, char *argv[]);
typedef void (*cmd_cb_t)(char *buf, ssize_t len, int pid, int in, int out, void *arg);

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

void ndc_register(char *name, ndc_cb_t *cb, int flags);
void ndc_move(int fd, unsigned long long loc);
void ndc_init(struct ndc_config *);
int ndc_main();

/* define these */
extern void ndc_update(unsigned long long dt);
extern void ndc_view(int fd, int argc, char *argv[]);
extern void ndc_vim(int fd, int argc, char *argv[]);
extern void ndc_connect(int fd);
extern void ndc_disconnect(int fd);

/* write to descriptor (might not need) */
int ndc_write(int fd, void *data, size_t len);
#define NDC_TWRITE(fd, msg) ndc_write(fd, msg, strlen(msg))
int ndc_dwritef(int fd, const char *fmt, va_list va);
int ndc_writef(int fd, const char *fmt, ...);
void ndc_wall(const char *msg);

ndc_cb_t do_GET, do_POST, do_sh;

void ndc_pty(int fd, char * const args[]);
int ndc_command(char * const args[], cmd_cb_t callback, void *arg, void *input, size_t input_len);

int ndc_flags(int fd);
void ndc_close(int fd);
void ndc_set_flags(int fd, int flags);
void ndc_move(int fd, unsigned long long loc);
void ndc_auth(int fd, char *username);
int ndc_headers(int fd);

#endif
