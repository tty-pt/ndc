#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _XOPEN_SOURCE 600

#include "../include/ndc.h"
#include "../include/iio.h"

#include <arpa/inet.h>
#include <arpa/telnet.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <grp.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>
#include "../include/ws.h"

#include <qmap.h>
#include <qsys.h>

#include "ws.c"

#define CERT_MASK 0x1F
#define MIME_MASK 0x3F
#define CMD_MASK 0x7F
#define HDLR_MASK 0x3F
#define ENV_MASK 0xFF

#define CMD_ARGM 8

#define DESCR_ITER \
	for (register int di_i = 1; di_i < FD_SETSIZE; di_i++) \
		if (!FD_ISSET(di_i, &fds_read) || !(descr_map[di_i].flags & DF_CONNECTED)) continue; \
		else

#define TELNET_CMD(...) { \
	unsigned char command[] = { __VA_ARGS__ }; \
	ndc_write(fd, command, sizeof(command)); \
}

#define FIRST_INPUT_SIZE (BUFSIZ * 2)
#define SELECT_TIMEOUT 10000
#define EXEC_TIMEOUT 1000

struct descr {
	SSL *cSSL;
	int fd, flags, pty, pid, epid;
	char username[BUFSIZ];
	struct winsize wsz;
	struct termios tty;
	char *remaining;
	struct sockaddr_in addr;
	size_t remaining_size, remaining_len;
	time_t sor; // start of request
	int pipes[3], pipes_mask;
	cmd_cb_t callback;
	size_t total;
	struct passwd pw;
	unsigned env_hd;
} descr_map[FD_SETSIZE];

struct cmd {
	int fd;
	int argc;
	char *argv[CMD_ARGM];
};

struct popen {
	int in, out, pid;
};

typedef struct {
	char *crt;
	char *key;
	char *domain;
	SSL_CTX *ctx;
} cert_t;

ndc_cb_t do_GET, do_POST, do_sh;

static unsigned char *input;
static size_t input_size = FIRST_INPUT_SIZE, input_len = 0;
static char *statics_mmap;
static size_t statics_len = 0;
static char *cgi_index = "./index.sh";
struct passwd ndc_pw;

struct timeval select_timeout, exec_timeout;

struct io io[FD_SETSIZE];

struct ndc_config ndc_config;

static int ndc_srv_flags = 0, srv_ssl_fd = -1, srv_fd = -1;
static unsigned cmds_hd;
static fd_set fds_read, fds_active, fds_write, fds_wactive;
long long dt, tack = 0;
SSL_CTX *default_ssl_ctx;
long long ndc_tick;
int do_cleanup = 1;

char *domain_default = NULL;
unsigned cert_hd, mime_hd, hdlr_hd; 

void
ndc_env_clear(int fd)
{
	struct descr *d = &descr_map[fd];
	unsigned cur = qmap_iter(d->env_hd, 0);
	const void *key, *value;

	while (qmap_next(&key, &value, cur))
		qmap_del(d->env_hd, key);
}

void
ndc_close(int fd)
{
	struct descr *d = &descr_map[fd];

	if (d->remaining_size) {
		free(d->remaining);
		d->remaining = NULL;
		d->remaining_len = d->remaining_size = 0;
	}

	if ((d->flags & DF_CONNECTED) && ndc_disconnect)
		ndc_disconnect(fd);

	d->flags = 0;
	if (d->flags & DF_WEBSOCKET)
		ws_close(fd);
	if (d->pty > 0) {
		if (d->pid > 0)
			kill(d->pid, SIGKILL);
		d->pid = -1;
		FD_CLR(d->pty, &fds_active);
		FD_CLR(d->pty, &fds_read);
		descr_map[d->pty].pty = -1;
		close(d->pty);
		d->pty = -1;
	}
	if (d->cSSL) {
		SSL_shutdown(d->cSSL);
		SSL_free(d->cSSL);
		d->cSSL = NULL;
	}
	shutdown(fd, 2);
	close(fd);
	FD_CLR(fd, &fds_active);
	FD_CLR(fd, &fds_read);
	FD_CLR(fd, &fds_wactive);
	FD_CLR(fd, &fds_write);
	ndc_env_clear(fd);
	qmap_close(d->env_hd);
	d->fd = -1;
	memset(d, 0, sizeof(struct descr));
}

static void
cleanup(void)
{
	if (!do_cleanup)
		return;

	DESCR_ITER
		ndc_close(di_i);
}

static void
sig_shutdown(int i UNUSED)
{
	ndc_srv_flags &= ~NDC_WAKE;
}

static int
ssl_accept(int fd)
{
	/* fprintf(stderr, "ssl_accept %d\n", fd); */
	struct descr *d = &descr_map[fd];
	int res = SSL_accept(d->cSSL);

	d->flags &= ~DF_ACCEPTED;

	if (res > 0) {
		d->flags |= DF_ACCEPTED;
		return 0;
	}

	int ssl_err = SSL_get_error(d->cSSL, res);
	if (errno == EAGAIN && ssl_err == SSL_ERROR_WANT_READ)
		return 0;

	ERR("SSL_accept %d %d %d %d %s\n", fd, res,
			ssl_err, errno,
			ERR_error_string(ssl_err, NULL));

	unsigned long openssl_err;
	while ((openssl_err = ERR_get_error()) != 0) {
		char buf[256];
		ERR_error_string_n(openssl_err, buf, sizeof(buf));
		ERR("OpenSSL: %s\n", buf);
	}

	ERR_clear_error();
	ndc_close(fd);
	return 1;
}

static ssize_t
ndc_ssl_low_read(int fd, void *to, size_t len)
{
	return SSL_read(descr_map[fd].cSSL, to, len);
}

static void
cmd_new(int *argc_r, char *argv[CMD_ARGM],
		int fd UNUSED, char *input, size_t len)
{
	register char *p = input;
	int argc = 0;

	p[len] = '\0';

	if (!*p || !isalnum(*p)) {
		argv[0] = "";
		*argc_r = argc;
		return;
	}

	argv[0] = p;
	argc++;

	for (p = input; *p && *p != '\r' && argc < CMD_ARGM; p++) if (isspace(*p)) {
		*p = '\0';
		argv[argc] = p + 1;
		argc ++;
	}

	while (*p && *p != '\r')
		p++;

	for (int i = argc; i < CMD_ARGM; i++)
		argv[i] = "";

	argv[argc] = p + 2;

	*argc_r = argc;
}

static ssize_t
ndc_ssl_lower_write(int fd, void *from, size_t len)
{
	struct descr *d = &descr_map[fd];
	if (!d->cSSL)
		return -1;
	return SSL_write(d->cSSL, from, len);
}

static int
ndc_write_remaining(int fd)
{
	struct descr *d = &descr_map[fd];
	struct io *dio = &io[fd];

	if (!d->remaining_len)
		return 0;

	int ret = dio->lower_write(fd, d->remaining, d->remaining_len);

	if (ret < 0 && errno == EAGAIN)
		return -1;

	d->remaining_len -= ret;
	if (!d->remaining_len && (d->flags & DF_TO_CLOSE))
		ndc_close(fd);
	return ret;
}

inline static void
ndc_rem_may_inc(int fd, size_t len)
{
	struct descr *d = &descr_map[fd];
	d->remaining_len += len;

	while (d->remaining_len >= d->remaining_size) {
		d->remaining_size *= 2;
		d->remaining_size += d->remaining_len;
		d->remaining = realloc(d->remaining, d->remaining_size);
	}
}

static ssize_t
ndc_low_write(int fd, void *from, size_t len)
{
	struct descr *d = &descr_map[fd];
	struct io *dio = &io[fd];

	if (d->remaining_len) {
		size_t olen = d->remaining_len;
		ndc_rem_may_inc(fd, len);
		memcpy(d->remaining + olen, from, len);
		ndc_write_remaining(fd);
		return -1;
	}

	d->remaining_len = 0;
	int ret = dio->lower_write(fd, from, len);

	if (ret < 0 && errno == EAGAIN) {
		ndc_rem_may_inc(fd, len);
		memcpy(d->remaining, from, len);
	}

	return ret;
}

int
ndc_env_put(int fd, char *key, char *value)
{
	if (!value)
		return 1;
	struct descr *d = &descr_map[fd];
	qmap_put(d->env_hd, key, value);
	return 0;
}

static void
descr_new(int ssl)
{
	struct sockaddr_in addr;
	socklen_t addr_len = (socklen_t)sizeof(addr);
	int fd = accept(ssl ? srv_ssl_fd : srv_fd, (struct sockaddr *) &addr, &addr_len);
	struct descr *d;
	struct io *dio;

	if (fd <= 0)
		return;

	FD_SET(fd, &fds_active);

	d = &descr_map[fd];
	dio = &io[fd];
	memset(d, 0, sizeof(struct descr));
	memset(dio, 0, sizeof(struct io));
	d->addr = addr;
	d->fd = fd;
	d->flags = 0;
	d->remaining_size = BUFSIZ * 1024;
	d->remaining = malloc(d->remaining_size);
	d->epid = 0;
	d->env_hd = qmap_open(QM_STR, QM_STR, ENV_MASK, 0);

	dio->write = ndc_low_write;

	char ipstr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &d->addr.sin_addr, ipstr, sizeof(ipstr));
	ndc_env_put(fd, "REMOTE_ADDR", ipstr);

	errno = 0;
	if (ssl) {
		d->cSSL = SSL_new(default_ssl_ctx);
		dio->read = dio->lower_read = ndc_ssl_low_read;
		dio->lower_write = ndc_ssl_lower_write;
		SSL_set_fd(d->cSSL, fd);
		if (ssl_accept(fd))
			return;
	} else {
		d->flags = DF_ACCEPTED;
		dio->read = dio->lower_read = read;
		dio->lower_write = (io_t) write;
	}
	if (ndc_accept)
		ndc_accept(fd);
}

inline static ssize_t
ndc_read(int fd)
{
	char buf[BUFSIZ];
	struct io *dio = &io[fd];
	input_len = 0;
	size_t ret;

	while (1) switch ((ret = dio->read(fd, buf, sizeof(buf)))) {
	case -1:
	case 0: return ret;
	default:
		if (input_len + ret > input_size) {
			input_size *= 2;
			input_size += ret;
			input = realloc(input, input_size);
		}
		memcpy(input + input_len, buf, ret);
		input_len += ret;
		if (ret < sizeof(buf))
			return input_len;
	}
}

int
ndc_write(int fd, void *data, size_t len)
{
	if (fd <= 0)
		return -1;
	struct io *dio = &io[fd];
	/* fprintf(stderr, "ndc_write %d %lu %d\n", fd, len, d->flags); */
	int ret = dio->write(fd, data, len);
	return ret;
}

int
ndc_dwritef(int fd, const char *fmt, va_list args)
{
	static char buf[BUFSIZ];
	ssize_t len = vsnprintf(buf, sizeof(buf), fmt, args);
	return ndc_write(fd, buf, len);
}

int
ndc_writef(int fd, const char *fmt, ...)
{
	if (fd <= 0)
		return -1;
	va_list va;
	va_start(va, fmt);
	int ret = ndc_dwritef(fd, fmt, va);
	va_end(va);
	return ret;
}

void
ndc_wall(const char *msg)
{
	DESCR_ITER NDC_TWRITE(di_i, (char *) msg);
}

static inline void
cmd_proc(int fd, int argc, char *argv[])
{
	if (argc < 1)
		return;

	char *s = argv[0];

	for (s = argv[0]; isalnum(*s); s++);

	int found = 0;

	*s = '\0';
	const struct cmd_slot *cmd
		= qmap_get(cmds_hd, argv[0]);

	if (cmd != NULL)
		found = 1;

	struct descr *d = &descr_map[fd];

	if (!(d->flags & DF_AUTHENTICATED)
			&& (!found || !(cmd->flags & CF_NOAUTH)))
		return;

	if ((!found && argc) || !(cmd->flags & CF_NOTRIM)) {
		// this looks buggy let's fix it, please
		/* fprintf(stderr, "??? %d %p, %d '%s'\n", argc, cmd_i, cmd_i - cmds_hd, argv[0]); */
		char *p = &argv[argc][-2];
		if (*p == '\r') *p = '\0';
		argv[argc] = "";
	}

	if (found) {
		if (ndc_command)
			ndc_command(fd, argc, argv);
		cmd->cb(fd, argc, argv);
	} else if (ndc_vim)
		ndc_vim(fd, argc, argv);
	if (ndc_flush)
		ndc_flush(fd, argc, argv);
}

static void
ndc_tty_update(int fd)
{
	struct descr *d = &descr_map[fd];
	struct termios last = d->tty;
	tcgetattr(d->pty, &d->tty);

	if ((last.c_lflag & ECHO) != (d->tty.c_lflag & ECHO))
		TELNET_CMD(IAC, d->tty.c_lflag & ECHO ? WILL : WONT, TELOPT_ECHO);

	if ((last.c_lflag & ICANON) != (d->tty.c_lflag & ICANON))
		TELNET_CMD(IAC, d->tty.c_lflag & ICANON ? WONT : WILL, TELOPT_SGA);

	tcflush(d->pty, TCIFLUSH);
}

static inline int
cmd_parse(int fd, char *cmd, size_t len)
{
	int argc;
	char *argv[CMD_ARGM];

	cmd_new(&argc, argv, fd, cmd, len);

#if 0
	fprintf(stderr, "CMD_PARSE %d %lu:\n", fd, len);
	for (int i = 0; i < argc; i++)
		fprintf(stderr, " A %s\n", argv[i]);
#endif

	if (!argc)
		return 0;

	cmd_proc(fd, argc, argv);

	if (argc != 3)
		return 0;

	return len;
}

static inline void
pty_open(int fd)
{
	struct descr *d = &descr_map[fd];

	CBUG(fcntl(fd, F_SETFL, O_NONBLOCK) == -1,
			"pty_open fcntl F_SETFL O_NONBLOCK\n");

	d->pty = posix_openpt(O_RDWR | O_NOCTTY);

	/* fprintf(stderr, "pty_open %d %d\n", fd, d->pty); */

	CBUG(d->pty == -1, "pty_open posix_openpt\n");
	CBUG(grantpt(d->pty), "pty_open grantpt\n");
	CBUG(unlockpt(d->pty), "pty_open unlockpt\n");

	TELNET_CMD(IAC, WILL, TELOPT_ECHO);
	TELNET_CMD(IAC, WONT, TELOPT_SGA);
	descr_map[d->pty].fd = fd;
	descr_map[d->pty].pty = -1;

	d->tty.c_lflag = ICANON | ECHO | ECHOK | ECHOCTL;
	d->tty.c_iflag = IGNCR;
	d->tty.c_iflag &= ~ICRNL;
	d->tty.c_iflag &= ~INLCR;
	d->tty.c_oflag |= OPOST | ONLCR;
	d->tty.c_oflag &= ~OCRNL;
	tcsetattr(d->pty, TCSANOW, &d->tty);
	ndc_tty_update(fd);
}

static int
descr_read(int fd)
{
	struct descr *d = &descr_map[fd];
	int ret;

	if (d->fd != fd)
		return 1;

	/* fprintf(stderr, "descr_read %d\n", fd); */

	if (!(d->flags & DF_ACCEPTED))
		return 0;

	ret = ndc_read(fd);
	switch (ret) {
	case -1:
		if (errno == EAGAIN)
			return 0;

		return -1;
	/* case 0: return 0; */
	case 0: return -1;
	}

	/* fprintf(stderr, "descr_read %d %d %s\n", d->fd, ret, input); */

	int i = 0;

	for (; i < ret && input[i] != IAC; i++);

	if (i == ret)
		i = 0;

	while (i < ret && input[i + 0] == IAC) if (input[i + 1] == SB && input[i + 2] == TELOPT_NAWS) {
		unsigned char colsHighByte = input[i + 3];
		unsigned char colsLowByte = input[i + 4];
		unsigned char rowsHighByte = input[i + 5];
		unsigned char rowsLowByte = input[i + 6];
		memset(&d->wsz, 0, sizeof(d->wsz));
		d->wsz.ws_col = (colsHighByte << 8) | colsLowByte;
		d->wsz.ws_row = (rowsHighByte << 8) | rowsLowByte;
		ioctl(d->pty, TIOCSWINSZ, &d->wsz);
		i += 9;
	} else if (input[i + 1] == DO && input[i + 2] == TELOPT_SGA) {
		/* this must change pty tty settings as well. Not just reply */
		/* TELNET_CMD(IAC, WONT, TELOPT_ECHO, IAC, WILL, TELOPT_SGA); */
		i += 3;
	} else if (input[i + 1] == DO) {
		/* TELNET_CMD(IAC, WILL, input[i + 2]); */
		i += 3;
	} else if (input[i + 1] == DONT) {
		/* TELNET_CMD(IAC, WONT, input[i + 2]); */
		i += 3;
	} else if (input[i + 1] == DO || input[i + 1] == DONT || input[i + 1] == WILL)
		i += 3;
	else
		i++;

	if (d->pid > 0 && i < ret) {
		write(d->pty, input + i, ret);
		return 0;
	}

	return cmd_parse(fd, (char *) input, ret);
}

static int
pty_read(int fd)
{
	struct descr *d = &descr_map[fd];
	static char buf[BUFSIZ * 4];
	int ret = -1, status;

	errno = 0;
	/* if (waitpid(d->pid, NULL, WNOHANG) > 0) { */
	/* 	if (errno == EAGAIN) */
	/* 		ret = 0; */
	/* 	else */
	/* 		goto close; */
	/* }; */

	memset(buf, 0, sizeof(buf));
	errno = 0;
	ret = read(d->pty, buf, sizeof(buf));

	switch (ret) {
		case 0:
			if (d->pid > 0 && waitpid(d->pid, &status, WNOHANG) == 0)
				return 0;
			break;
		case -1:
			if (errno == EAGAIN || errno == EIO)
				return 0;
			return -1;
		default:
			buf[ret] = '\0';
			ndc_write(fd, buf, ret);
			ndc_tty_update(fd);
			return ret;
	}

	if (d->pid > 0)
		kill(d->pid, SIGKILL);

	d->pid = -1;
	return ret;
}

int ndc_exec_loop(int cfd);

static inline void
descr_proc_writes(void)
{
	for (register int i = 0; i < FD_SETSIZE; i++) {
		struct descr *d = &descr_map[i];

		if (!(d->flags & DF_ACCEPTED) && d->cSSL)
			ssl_accept(i);

		if (!FD_ISSET(i, &fds_write)
				|| i == srv_fd
				|| i == srv_ssl_fd
				|| d->pty == -2)
			continue;

		if (d->remaining_len)
			ndc_write_remaining(i);

		// i is not a pty fd!
		if (d->epid)
			ndc_exec_loop(i);
	}
}

static inline void
descr_proc_reads(void)
{
	for (register int i = 0; i < FD_SETSIZE; i++) {
		struct descr *d = &descr_map[i];

		if (!FD_ISSET(i, &fds_read))
			continue;

		if (i == srv_fd)
			descr_new(0);
		else if (i == srv_ssl_fd)
			descr_new(1);

		// i is a pty fd
		if (d->pty == -2) {
			if (pty_read(d->fd) < 0)
				FD_CLR(i, &fds_active);
			continue;
		}

		// i is not a pty fd!
		if (!d->epid && descr_read(i) < 0)
			ndc_close(i);
	}
}

static long long
timestamp(void)
{
	struct timeval te;
	gettimeofday(&te, NULL); // get current time
	return te.tv_sec * 1000000LL + te.tv_usec;
}

static void
ndc_bind(int *srv_fd_r, int ssl)
{
	int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	int opt;

	CBUG(srv_fd < 0, "socket\n");

	opt = 1;
	CBUG(setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR,
			(char *) &opt, sizeof(opt)),
			"setsockopt SO_REUSEADDR\n");

	opt = 1;
	CBUG(setsockopt(srv_fd, SOL_SOCKET, SO_KEEPALIVE,
			(char *) &opt, sizeof(opt)),
			"setsockopt SO_KEEPALIVE\n");

	CBUG(fcntl(srv_fd, F_SETFL, O_NONBLOCK) == -1,
			"fcntl F_SETFL O_NONBLOCK\n");

	CBUG(fcntl(srv_fd, F_SETFD, FD_CLOEXEC) == -1,
			"fcntl F_SETFL FD_CLOEXEC\n");

	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(ssl
			? ndc_config.ssl_port
			: ndc_config.port);

	CBUG(bind(srv_fd, (struct sockaddr *) &server,
			sizeof(server)),
			"bind");

	descr_map[srv_fd].fd = srv_fd;

	listen(srv_fd, 32);

	FD_SET(srv_fd, &fds_active);

	*srv_fd_r = srv_fd;
}

static int
ndc_sni(SSL *ssl, int *ad UNUSED, void *arg UNUSED)
{
	const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername)
		return SSL_TLSEXT_ERR_NOACK; // no SNI

	const cert_t *cert = qmap_get(cert_hd, servername);

	if (cert == NULL)
		return SSL_TLSEXT_ERR_NOACK;

	SSL_set_SSL_CTX(ssl, cert->ctx);

	return SSL_TLSEXT_ERR_OK;
}

SSL_CTX *
ndc_ctx_new(char *crt, char *key)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	CBUG(!ctx, "SSL_CTX_new\n");

	CBUG(!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION),
			"set_min_proto_version\n");

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	CBUG(!SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!RC4"),
			"set_cipher_list\n");


	(void)SSL_CTX_set_ciphersuites(ctx,
			"TLS_AES_256_GCM_SHA384:"
			"TLS_AES_128_GCM_SHA256:"
			"TLS_CHACHA20_POLY1305_SHA256");

	CBUG(!SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384"),
			"set1_groups_list\n");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	SSL_CTX_set_ecdh_auto(ctx, 1);
#else
	FILE *fp = fopen("/etc/ssl/dhparam.pem", "r");
	CBUG(!fp, "open dhparam.pem\n");
	DH *dh = PEM_read_DHparams(fp, NULL, NULL, NULL);
	CBUG(!dh, "PEM_read_DHparams\n");
	SSL_CTX_set_tmp_dh(ctx, dh);
#endif


	CBUG(SSL_CTX_use_certificate_chain_file(ctx, crt) <= 0,
			"use_certificate_chain_file\n");
	CBUG(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0,
			"use_privatekey_file\n");
	CBUG(!SSL_CTX_check_private_key(ctx),
			"private key does not match certificate\n");

	return ctx;
}

static int
openssl_error_callback(const char *str, size_t len, void *u)
{
    (void)u;
    ERR("%.*s\n", (int) len, str);
    return 0;
}

void
ndc_register(char *name, ndc_cb_t *cb, int flags)
{
	struct cmd_slot cmd = { .name = name, .cb = cb, .flags = flags };
	qmap_put(cmds_hd, name, &cmd);
}

ssize_t
ndc_mmap(char **mapped, char *file)
{
	int fd = open(file, O_RDONLY);

	if (fd < 0)
		return 0;

	struct stat sb;
	if (fstat(fd, &sb) == -1) {
		close(fd);
		return 0;
	}

	size_t file_size = sb.st_size;
	if (!file_size) {
		close(fd);
		return 0;
	}

	*mapped = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);

	if (*mapped == MAP_FAILED)
		return 0;

	return file_size;
}

char *
ndc_mmap_iter(char *start, size_t *pos_r)
{
	char *line = start + *pos_r;
	char *line_end = strchr(line, '\n');
	if (line_end)
		*line_end = '\0';
	*pos_r += strlen(line) + 1;
	return line;
}

void
pw_copy(struct passwd *target, struct passwd *origin)
{
	*target = *origin;
	target->pw_name = strdup(origin->pw_name);
	target->pw_shell = strdup(origin->pw_shell);
	target->pw_dir = strdup(origin->pw_dir);
	target->pw_passwd = NULL;
}

void
pw_free(struct passwd *target)
{
	free(target->pw_name);
	free(target->pw_shell);
	free(target->pw_dir);
}

static inline void mime_put(char *key, char *value) {
	qmap_put(mime_hd, key, value);
}

static void
ndc_init(void)
{
	char euname[BUFSIZ];
	int euid = 0;

	ndc_srv_flags |= ndc_config.flags | NDC_WAKE;

	strncpy(euname, getpwuid(geteuid())->pw_name, sizeof(euname));
	pw_copy(&ndc_pw, getpwnam(euname));

	if (ndc_srv_flags & NDC_SSL) {

		SSL_load_error_strings();
		SSL_library_init();
		OpenSSL_add_all_algorithms();

		const cert_t *cert
			= qmap_get(cert_hd, domain_default);

		default_ssl_ctx = ndc_ctx_new(cert->crt, cert->key);

		SSL_CTX_set_tlsext_servername_callback(default_ssl_ctx, ndc_sni);

		ERR_print_errors_cb(openssl_error_callback, NULL);
	}

	euid = geteuid();
	if (euid && !ndc_config.chroot)
		ndc_config.chroot = ".";

	if (!ndc_config.chroot) {
		WARN("Running from cwd\n");
	} else if (!geteuid()) {
		CBUG(chroot(ndc_config.chroot), "chroot\n");
		CBUG(chdir("/"), "chdir\n");
	} else
		CBUG(chdir(ndc_config.chroot),
				"ndc_main chdir2\n");

	mime_put("html", "text/html");
	mime_put("txt", "text/plain");
	mime_put("css", "text/css");
	mime_put("js", "application/javascript");
	statics_len = ndc_mmap(&statics_mmap, "./serve.allow");

	atexit(cleanup);
	signal(SIGTERM, sig_shutdown);
	signal(SIGINT, sig_shutdown);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	input = malloc(input_size);

	if (ndc_srv_flags & NDC_SSL)
		ndc_bind(&srv_ssl_fd, 1);

	ndc_bind(&srv_fd, 0);

	exec_timeout.tv_sec = EXEC_TIMEOUT / 1000000;
	exec_timeout.tv_usec = EXEC_TIMEOUT % 1000000;
	select_timeout.tv_sec = SELECT_TIMEOUT / 1000000;
	select_timeout.tv_usec = SELECT_TIMEOUT % 1000000;
	
	if ((ndc_srv_flags & NDC_DETACH) && daemon(1, 1) != 0)
		exit(EXIT_SUCCESS);
}

int
ndc_main(void)
{
	struct timeval timeout;

	ndc_init();

	ndc_tick = timestamp();

	while (ndc_srv_flags & NDC_WAKE) {
		long long last = ndc_tick;
		ndc_tick = timestamp();
		dt = ndc_tick - last;

		if (ndc_update)
			ndc_update(dt);

		if (!(ndc_srv_flags & NDC_WAKE))
			break;

		for (register int i = 0; i < FD_SETSIZE; i++)
			if (descr_map[i].remaining_len)
				ndc_write_remaining(i);

		memcpy(&timeout, &select_timeout, sizeof(timeout));

		fds_read = fds_active;
		fds_write = fds_wactive;
		int select_n = select(FD_SETSIZE, &fds_read, &fds_write, NULL, &timeout);
		descr_proc_writes();

		switch (select_n) {
		case -1:
			switch (errno) {
			case EAGAIN: /* return 0; */
			case EINTR:
			case EBADF: continue;
			}

			ERR("select\n");
			return -1;

		case 0: continue;
		}

		descr_proc_reads();
	}

	return 0;
}

static struct passwd *
drop_priviledges(int fd)
{
	struct descr *d = &descr_map[fd];

	struct passwd *pw = (d->flags & DF_AUTHENTICATED)
		? &d->pw : &ndc_pw;

	if (!ndc_config.chroot) {
		WARN("NOT_CHROOTED - running with %s\n", pw->pw_name);
		return pw;
	}
	
	CBUG(!pw, "getpwnam\n");
	CBUG(setgroups(0, NULL), "setgroups\n");
	CBUG(initgroups(pw->pw_name, pw->pw_gid), "initgroups\n");
	CBUG(setgid(pw->pw_gid), "setgid\n");
	CBUG(setuid(pw->pw_uid), "setuid\n");

	return pw;
}

static inline char **
env_prep(int fd)
{
	struct descr *d = &descr_map[fd];
	char **env = malloc(ENV_MASK * sizeof(char *));
	unsigned cur;
	size_t count = 0;
	const void *key, *value;

	cur = qmap_iter(d->env_hd, NULL);
	while (qmap_next(&key, &value, cur)) {
		char *envstr = malloc(ENV_LEN);
		env[count++] = envstr;
		snprintf(envstr, ENV_LEN, "%s=%s",
				(char *) key,
				(char *) value);
	}

	env[count] = NULL;

	return env;
}

inline static int
command_pty(int cfd, struct winsize *ws, char * const args[])
{
	struct descr *d = &descr_map[cfd];
	pid_t p;

	/* fprintf(stderr, "command_pty WILL EXEC %s\n", args[0]); */
	FD_SET(d->pty, &fds_active);
	descr_map[d->pty].pty = -2;

	p = fork();
	if(p == 0) { /* child */
		do_cleanup = 0;

		struct descr *d = &descr_map[cfd];
		CBUG(setsid() == -1, "setsid\n");

		CBUG(!(d->flags & DF_AUTHENTICATED),
				"NOT AUTHENTICATED\n");

		int slave_fd = open(ptsname(d->pty), O_RDWR);
		CBUG(slave_fd == -1,
				"open %d\n",
				errno);

		struct passwd *pw = drop_priviledges(cfd);

		int pflags = fcntl(slave_fd, F_GETFL, 0);
		CBUG(pflags == -1, "pflags -1\n");

		CBUG(ioctl(slave_fd, TIOCSWINSZ, ws) == -1,
				"ioctl TIOCSWINSZ\n");

		CBUG(ioctl(slave_fd, TIOCSCTTY, NULL) == -1,
				"ioctl TIOCSCTTY\n");

		CBUG(fcntl(slave_fd, F_SETFD, FD_CLOEXEC) == -1,
				"fcntl srv_fd F_SETFL FD_CLOEXEC\n");

		CBUG(dup2(slave_fd, STDIN_FILENO) == -1,
				"dup2 STDIN\n");
		CBUG(dup2(slave_fd, STDOUT_FILENO) == -1,
				"dup2 STDOUT\n");
		CBUG(dup2(slave_fd, STDERR_FILENO) == -1,
				"dup2 STDERR\n");

		char *alt_args[] = { pw->pw_shell, NULL };
		char * const *real_args = args[0] ? args : alt_args;
		char home[BUFSIZ], user[BUFSIZ], shell[BUFSIZ];
		snprintf(home, sizeof(home), "HOME=%s", d->pw.pw_dir);
		snprintf(user, sizeof(user), "USER=%s", d->pw.pw_name);
		snprintf(shell, sizeof(shell), "SHELL=%s", d->pw.pw_shell);

		char * const env[] = {
			"PATH=/bin:/usr/bin:/usr/local/bin",
			"LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib",
			home,
			user,
			shell,
			NULL,
		};

		execve(real_args[0], real_args, env);
		CBUG(1, "execve\n");
	}

	return p;
}


void
ndc_pty(int fd, char * const args[])
{
	struct descr *d = &descr_map[fd];

	/* fprintf(stderr, "ndc_pty %s %d pty %d SGA %d ECHO %d\n", */
	/* 		args[0], fd, d->pty, WONT, WILL); */

	d->pid = command_pty(fd, &d->wsz, args);
	FD_SET(d->pty, &fds_active);

	/* fprintf(stderr, "PTY master fd: %d\n", d->pty); */
}

void
do_sh(int fd, int argc UNUSED, char *argv[] UNUSED)
{
	char *args[] = { NULL, NULL };
	ndc_pty(fd, args);
}

static char *
env_name(char *key)
{
	static char buf[BUFSIZ];
	int i = 0;
	register char *b, *s;
	memset(buf, 0, BUFSIZ);
	strncpy(buf, "HTTP_", sizeof(buf));
	for (s = (char *) key, b = buf + 5; *s; s++, b++, i++)
		if (*s == '-')
			*b = '_';
		else
			*b = toupper(*s);
	return buf;
}

static inline void
headers_get(int fd, size_t *body_start, char *next_lines)
{
	register char *s, *key, *value;

	for (s = next_lines, key = s, value = s; *s; ) switch (*s) {
		case ':':
			*s = '\0';
			value = (s += 2);
			break;
		case '\r':
			*s = '\0';
			if (s != key) {
				if (s - key >= BUFSIZ)
					*(key + BUFSIZ - 1) = '\0';
				ndc_env_put(fd, env_name(key), value);
				key = s += 2;
			} else
				*++s = '\0';

			break;
		default:
			s++;
			break;
	}

	*body_start = s - next_lines;	
}

static inline int
popen2(int cfd, char * const args[])
{
	struct descr *d = &descr_map[cfd];
	pid_t p = -1;
	int pipe_stdin[2], pipe_stdout[2], pipe_stderr[2];

	if (pipe(pipe_stdin) \
			|| pipe(pipe_stdout) \
			|| pipe(pipe_stderr) \
			|| (p = fork()) < 0)
		return p;

	if(p == 0) { /* child */
		drop_priviledges(cfd);
		do_cleanup = 0;
		close(pipe_stdin[1]);
		dup2(pipe_stdin[0], 0);
		close(pipe_stdout[0]);
		dup2(pipe_stdout[1], 1);
		close(pipe_stderr[0]);
		dup2(pipe_stderr[1], 2);
		setpgid(0, 0);

		char * const *env = env_prep(cfd);
		execve(args[0], args, env);
		CBUG(1, "execve\n");
	}

	d->pipes[0] = pipe_stdin[1];
	d->pipes[1] = pipe_stdout[0];
	d->pipes[2] = pipe_stderr[0];
	close(pipe_stdin[0]);
	close(pipe_stdout[1]);
	close(pipe_stderr[1]);
	return p;
}

static inline
ssize_t cb_proc(int fd, int pfd,
		cmd_cb_t callback)
{
	char ndc_execbuf[BUFSIZ * 64];

	struct descr *d = &descr_map[fd];
	memset(ndc_execbuf, 0, sizeof(ndc_execbuf));
	ssize_t len;
	int ofd;

	*ndc_execbuf = '\0';

	ofd = pfd == d->pipes[1];
	len = read(pfd, ndc_execbuf, sizeof(ndc_execbuf) - 1);
	if (len > 0) {
		ndc_execbuf[len] = '\0';
		callback(fd, ndc_execbuf, len, ofd);
	} else if (len < 0) {
		if (errno != EAGAIN)
			ERR("read\n");
		return -1;
	}

	// stop iteration if output receives 0
	return len;
}

int
ndc_exec_loop(int cfd)
{
	struct descr *d = &descr_map[cfd];
	fd_set read_fds;
	int ready_fds, total_timeout = 40 /* should be a config option */, ret = 0;
	ssize_t len = 0;

	d->flags &= ~DF_TO_CLOSE;

	do {
		struct timeval timeout;
		memcpy(&timeout, &exec_timeout, sizeof(timeout));
		int pfd;
		time_t dt;

		if (!d->pipes_mask)
			break;

		dt = time(NULL) - d->sor;

		if (dt >= total_timeout) {
			ndc_writef(cfd, "504 Gateway Timeout\r\n"
					"Content-Type: text/plain\r\n"
					"Content-Length: 26\r\n"
					"\r\n"
					"Code 504: Gateway Timeout\n");
			ERR("Timeout! %u\n", cfd);
			break;
		}

		FD_ZERO(&read_fds);
		if (d->pipes_mask & 1)
			FD_SET(d->pipes[1], &read_fds);
		if (d->pipes_mask & 2)
			FD_SET(d->pipes[2], &read_fds);

		ready_fds = select(d->pipes[1] + 1, &read_fds, NULL, NULL, &timeout);

		if (!ready_fds)
			return 1;

		if (ready_fds == -1) {
			ERR("select %d\n", errno);
			break;
		}

		if (FD_ISSET(d->pipes[1], &read_fds))
			pfd = d->pipes[1];
		else if (FD_ISSET(d->pipes[2], &read_fds))
			pfd = d->pipes[2];
		else
			continue;

		errno = 0;
		len = cb_proc(cfd, pfd, d->callback);

		if (len > 0) {
			d->total += len;
			return 1;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			FD_SET(cfd, &fds_active);
			FD_SET(cfd, &fds_read);
			return 1;
		}

		if (pfd == d->pipes[1]) {
			d->pipes_mask &= ~1;
			break;
		} else
			d->pipes_mask &= ~2;

	} while (d->pipes_mask);

	if (d->total == 0) {
		char ndc_execbuf[BUFSIZ * 64];
		read(d->pipes[2], ndc_execbuf, sizeof(ndc_execbuf) - 1);
		ERR("%s\n", ndc_execbuf);
		ndc_writef(cfd, "500 Internal Server Error\r\n"
				"Content-Type: text/plain\r\n"
				"Content-Length: %ld\r\n"
				"\r\n"
				"Code 500: Internal Server Error:\n%s\n", strlen(ndc_execbuf) + 37, ndc_execbuf);
		ret = -1;
	} else {
		len = cb_proc(cfd, d->pipes[2], d->callback);
	}

	close(d->pipes[1]);
	close(d->pipes[2]);
	kill(-d->epid, SIGKILL);
	waitpid(d->epid, NULL, 0);
	d->epid = 0;
	memset(d->pipes, 0, sizeof(d->pipes));
	FD_CLR(cfd, &fds_wactive);

	d->flags |= DF_TO_CLOSE;
	if (!d->remaining_len)
		ndc_close(cfd);

	return ret;
}

void
ndc_exec(int cfd, char * const args[],
		cmd_cb_t callback, void *input,
		size_t input_len)
{
	struct descr *d = &descr_map[cfd];
	int flags;

	d->epid = popen2(cfd, args); // should assert it doesn't equal 0
	d->pipes_mask = 3;

	flags = fcntl(d->pipes[1], F_GETFL, 0);
	fcntl(d->pipes[1], F_SETFL, flags | O_NONBLOCK);
	flags = fcntl(d->pipes[2], F_GETFL, 0);
	fcntl(d->pipes[2], F_SETFL, flags | O_NONBLOCK);

	if (input)
		write(d->pipes[0], input, input_len);
	close(d->pipes[0]);

	d->sor = time(NULL);
	d->total = 0;
	d->callback = callback;
	FD_SET(cfd, &fds_wactive);
}

void
do_GET_cb(int fd, char *buf, size_t len, int ofd)
{
	if (ofd == 1)
		ndc_write(fd, buf, len);
	else
		ERR("%s\n", buf);
}

static void
url_decode(char *str)
{
    char *src = str, *dst = str;

    while (*src) {
        if (*src == '%' && src[1] && src[2] && isxdigit(src[1]) && isxdigit(src[2])) {
            unsigned value;
            sscanf(src + 1, "%2x", &value);
            *dst++ = (char)value;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }

    *dst = '\0';
}

static char *
env_sane(char *str)
{
	static char buf[BUFSIZ];
	char *b;
	for (b = buf; b - buf - 1 < BUFSIZ && (isalnum(*str) || *str == '/' || *str == '+'
				|| *str == '%' || *str == '&' || *str == '_' || *str == '-'
				|| *str == ' ' || *str == '=' || *str == ';' || *str == '.'); str++, b++)
		*b = *str;
	*b = '\0';
	return buf;
}

static void
ndc_auth_try(int fd)
{
	if (!ndc_auth_check)
		return;
	char *user = ndc_auth_check(fd);
	if (user)
		ndc_auth(fd, user);
}


inline static char *
static_allowed(const char *path, struct stat *stat_buf)
{
	static char output[BUFSIZ];
	char *rstart = statics_mmap, *start, *out = NULL;
	size_t pos = 0;
	if (!statics_mmap)
		return NULL;

	do {
		start = ndc_mmap_iter(rstart, &pos);
		char *glob = strchr(start, ' ');
		if (!glob)
			break;
		if (fnmatch(glob + 1, path, 0) == 0) {
			register char aux = *glob,
				 *aster = strchr(glob + 1, '*');

			CBUG(!aster, "No asterisk on serve.allow\n");

			size_t offset = aster - 1 - glob;
			aux = *glob;
			*glob = '\0';
			size_t len = snprintf(output, sizeof(output), "./%s/%s", start, path + offset);
			*glob = aux;
			if (output[len - 1] != '/') {
				if (stat(output, stat_buf))
					continue;
				out = output;
				break;
			}
		}
	} while (pos < statics_len);

	return out;
}

int
ndc_env_get(int fd, char *target, char *key)
{
	struct descr *d = &descr_map[fd];
	const void *skey = qmap_get(d->env_hd, key);

	if (!skey)
		return 1;

	strcpy(target, skey);
	return 0;
}

static void
_env_prep(int fd, char *document_uri,
		char *param, char *method)
{
	char req_content_type[BUFSIZ];
	if (ndc_env_get(fd, req_content_type, "HTTP_CONTENT_TYPE"))
		strncpy(req_content_type, "text/plain", sizeof(req_content_type));

	ndc_env_put(fd, "CONTENT_TYPE", env_sane(req_content_type));
	ndc_env_put(fd, "CONTENT_TYPE", env_sane(req_content_type));
	ndc_env_put(fd, "DOCUMENT_URI", document_uri);
	ndc_env_put(fd, "QUERY_STRING", env_sane(param));
	ndc_env_put(fd, "REQUEST_METHOD", method);
	ndc_env_put(fd, "DOCUMENT_ROOT", geteuid() ? ndc_config.chroot : "");
	ndc_env_put(fd, "SCRIPT_NAME", cgi_index + 1);
}

static inline void
static_write(int fd, char *status, const char *content_type,
		int want_fd, off_t total)
{
	struct descr *d = &descr_map[fd];
	time_t now = time(NULL);
	struct tm *tm_info = gmtime(&now);
	char date[100];

	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", tm_info);
	ndc_writef(fd, "HTTP/1.1 %s\r\n"
			"Date: %s\r\n"
			"Server: ndc/0.0.1 (Unix)\r\n"
			"Content-Length: %lu\r\n"
			"Content-Type: %s\r\n"
			"Cache-Control: max-age=5184000\r\n"
			"\r\n",
			status, date, total, content_type);


	if (want_fd <= 0) {
		ndc_writef(fd, "%s\r\n", status);
		goto end;
	}

	// static file
	ssize_t len;
	char b[BUFSIZ * 16];

	while ((len = read(want_fd, b, sizeof(b))) > 0)
		ndc_write(fd, b, len);

	close(want_fd);

end:	if ((d->flags & DF_TO_CLOSE) && !d->remaining_len)
		ndc_close(fd);
}

static inline int
request_handle_static(int fd, char *document_uri,
		struct stat *stat_buf)
{
	char buf[BUFSIZ];
	errno = 0;
	char *ext, *s;
	const char *content_type;

	if (document_uri[strlen(document_uri) - 1] == '/')
	{
		snprintf(buf, sizeof(buf), "%sindex.html",
				document_uri);
		document_uri = buf;
	}

	char *filename
		= static_allowed(document_uri, stat_buf);

	if (!filename)
		return 0;

	ext = filename;
	for (s = ext; *s; s++)
		if (*s == '.')
			ext = s + 1;

	content_type = "application/octet-stream";
	if (ext) {
		const void *skey = qmap_get(mime_hd, ext);
		if (skey)
			content_type = skey;
	}

	static_write(fd, "200 OK", content_type,
			open(filename, O_RDONLY),
			stat_buf->st_size);

	return 1;
}

static inline int
request_handle_websocket(int fd)
{
	struct descr *d = &descr_map[fd];
	char buf[ENV_VALUE_LEN];

	if (d->flags & DF_WEBSOCKET)
		return 0;

	if (ndc_env_get(fd, buf, "HTTP_SEC_WEBSOCKET_KEY"))
		return 0;

	struct io *dio = &io[fd];
	if (ws_init(fd, buf))
		return -1;

	d->flags |= DF_WEBSOCKET;
	dio->read = ws_read;
	dio->write = ws_write;
	TELNET_CMD(IAC, DO, TELOPT_NAWS);
	if (!ndc_connect || ndc_connect(fd)) {
		d->flags |= DF_CONNECTED;
		pty_open(fd);
	}

	return 1;
}

static inline void
request_handle_cgi(int fd, struct stat *stat_buf, char *body)
{
	if (stat(cgi_index, stat_buf) || access(cgi_index, X_OK)) {
		char *status = "404 Not Found";
		static_write(fd, status, "text/plain",
				-1, strlen(status));
		return;
	}

	char * args[2] = { cgi_index, NULL };
	ndc_writef(fd, "HTTP/1.1 ");

	ndc_exec(fd, args, do_GET_cb, body, strlen(body));

	ndc_exec_loop(fd);
}

static inline int
request_handle_redirect(int fd, char *document_uri)
{
	struct descr *d = &descr_map[fd];

	if ((ndc_srv_flags & NDC_SSL_ONLY)
			&& (ndc_srv_flags & NDC_SSL)
			&& !d->cSSL)
	{
		char host[ENV_KEY_LEN];
		ndc_env_get(fd, host, "HTTP_HOST");
		char response[8285];
		d->flags |= DF_TO_CLOSE;

		snprintf(response, sizeof(response),
				"HTTP/1.1 301 Moved Permanently\r\n"
				"Location: https://%s%s\r\n"
				"Content-Length: 0\r\n"
				"Connection: close\r\n"
				"\r\n", host, document_uri);
		ndc_writef(fd, "%s", response);

		if (!d->remaining_len)
			ndc_close(fd);

		return 1;
	}

	return 0;
}

static
void request_handle(int fd, int argc, char *argv[], int req_flags)
{
	char *method;
	struct descr *d = &descr_map[fd];
	size_t body_start;
	char document_uri[BUFSIZ], *param;
	struct stat stat_buf;

	if (req_flags & NDC_POST)
		method = "POST";
	else
		method = "GET";

	char ipstr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &d->addr.sin_addr, ipstr, sizeof(ipstr));
	WARN("%d (%s) %s %s\n", fd, ipstr, method, argv[1]);

	if (argc < 2 || argv[1][0] != '/' || strstr(argv[1], "..")) {
		// you wish
		ndc_close(fd);
		return;
	}

	strlcpy(document_uri, argv[1], sizeof(document_uri));
	url_decode(document_uri);

	param = strchr(document_uri, '?');
	if (param)
		*param ++ = '\0';
	else
		param = "";

	headers_get(fd, &body_start, argv[argc]);

	ndc_auth_try(fd);

	if (!(d->flags & DF_WEBSOCKET)) {
		if (request_handle_websocket(fd))
			return;
		d->flags |= DF_TO_CLOSE;
	}

	if (request_handle_static(fd, document_uri, &stat_buf))
		return;

	if (request_handle_redirect(fd, document_uri))
		return;

	char *body = argv[argc] + body_start + 1;

	_env_prep(fd, document_uri, param, method);

	const void *key = qmap_get(hdlr_hd, document_uri);
	ndc_handler_t *hdlr;
	*((const void **) &hdlr) = key;

	if (hdlr) {
		hdlr(fd, body);
		return;
	}

	if (ndc_config.default_handler) {
		ndc_config.default_handler(fd, body);
		return;
	}

	request_handle_cgi(fd, &stat_buf, body);
}

void
ndc_register_handler(char *path, ndc_handler_t *handler)
{
	void **value = (void **) &handler;
	qmap_put(hdlr_hd, path, *value);
}

void
do_GET(int fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, 0);
}

void
do_POST(int fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, NDC_POST);
}

int
ndc_flags(int fd)
{
	return descr_map[fd].flags;
}

void
ndc_set_flags(int fd, int flags)
{
	descr_map[fd].flags = flags;
}

int
ndc_auth(int fd, char *username)
{
	struct descr *d = &descr_map[fd];
	/* syserr(LOG_ERR, "ndc_auth %d %s", fd, username); */
	strncpy(d->username, username, sizeof(d->username));
	d->flags |= DF_AUTHENTICATED;
	struct passwd *pw = getpwnam(d->username);
	if (!pw)
		return 1;
	pw_copy(&d->pw, pw);
	return 0;
}

__attribute__((constructor)) static void
ndc_pre_init(void)
{
	memset(&ndc_config, 0, sizeof(ndc_config));
	ndc_config.port = 80;
	ndc_config.ssl_port = 443;

	if ((ndc_srv_flags & NDC_DETACH))
		qsyslog = syslog;

	unsigned cert_type = qmap_reg(sizeof(cert_t));
	unsigned cmd_type = qmap_reg(sizeof(struct cmd_slot));

	mime_hd = qmap_open(QM_STR, QM_STR, MIME_MASK, 0);
	cert_hd = qmap_open(QM_STR, cert_type, CERT_MASK, 0);
	hdlr_hd = qmap_open(QM_STR, QM_PTR, HDLR_MASK, 0);
	cmds_hd = qmap_open(QM_STR, cmd_type, CMD_MASK, 0);
}

void
_ndc_cert_add(char *domain, char *crt, char *key)
{
	SSL_CTX *ssl_ctx = ndc_ctx_new(crt, key);
	cert_t cert = {
		.crt = crt,
		.key = key,
		.domain = domain,
		.ctx = ssl_ctx,
	};

	unsigned id = qmap_put(cert_hd, domain, &cert);
	WARN("%u '%s' '%s' '%s'\n", id, domain, crt, key);
	if (!domain_default)
		domain_default = domain;
}

void
ndc_cert_add(char *optarg)
{
	char *domain = optarg, *crt, *ioc;
	ioc = strchr(optarg, ':');
	CBUG(!ioc, "Invalid cert info\n");
	*ioc = '\0';
	crt = ioc + 1;
	ioc = strchr(crt, ':');
	CBUG(!ioc, "Invalid cert info\n");
	*ioc = '\0';
	_ndc_cert_add(domain, crt, ioc + 1);
	ndc_srv_flags |= NDC_SSL;
}


void
ndc_certs_add(char *certs_file)
{
	char *mapped;
	size_t file_size = ndc_mmap(&mapped, certs_file);
	size_t pos = 0;

	do
		ndc_cert_add(ndc_mmap_iter(mapped, &pos));
	while (pos < file_size);
}
