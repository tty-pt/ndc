#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _XOPEN_SOURCE 600

#include "ndc.h"
#include <arpa/telnet.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include "qhash.h"
#include "ws.h"

#define CMD_ARGM 8

#define DESCR_ITER \
	for (register int di_i = 1; di_i < FD_SETSIZE; di_i++) \
		if (!FD_ISSET(di_i, &fds_read) || !(descr_map[di_i].flags & DF_CONNECTED)) continue; \
		else

#define TELNET_CMD(...) { \
	unsigned char command[] = { __VA_ARGS__ }; \
	ndc_write(fd, command, sizeof(command)); \
}

struct descr {
	SSL *cSSL;
	int fd, flags, pty, pid;
	unsigned char cmd[BUFSIZ * 2];
	char username[BUFSIZ];
	struct winsize wsz;
	struct termios tty;
	unsigned headers;
	void *remaining;
	size_t remaining_size, remaining_len;
} descr_map[FD_SETSIZE];

struct cmd {
	int fd;
	int argc;
	char *argv[CMD_ARGM];
};


struct popen {
	int in, out, pid;
};

ndc_cb_t do_GET, do_POST, do_sh;

extern struct cmd_slot cmds[];

struct ndc_config config;

static int ndc_srv_flags = 0, srv_ssl_fd = -1, srv_fd = -1;
static unsigned cmds_hd, mime_hd;
static fd_set fds_read, fds_active;
static size_t cmds_len = 0;
long long dt, tack = 0;
SSL_CTX *ssl_ctx;
long long ndc_tick;
int do_cleanup = 1;

void
ndc_close(int fd)
{
	struct descr *d = &descr_map[fd];

	if (d->remaining) {
		free(d->remaining);
		d->remaining = NULL;
		d->remaining_len = d->remaining_size = 0;
	}

	if (d->flags & DF_CONNECTED)
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
	if ((d->flags & DF_ACCEPTED) && d->cSSL) {
		SSL_shutdown(d->cSSL);
		SSL_free(d->cSSL);
		d->cSSL = NULL;
	}
	if (d->headers)
		hash_close(d->headers);
	shutdown(fd, 2);
	close(fd);
	FD_CLR(fd, &fds_active);
	FD_CLR(fd, &fds_read);
	d->fd = -1;
	memset(d, 0, sizeof(struct descr));
}

static void cleanup()
{
	if (!do_cleanup)
		return;

	DESCR_ITER
		ndc_close(di_i);
}

void sig_shutdown(int i)
{
	ndc_srv_flags &= ~NDC_WAKE;
}

static int ssl_accept(int fd) {
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

	fprintf(stderr, "ssl_accept error %d %d %d %d %s\n", fd, res, ssl_err, errno, ERR_error_string(ssl_err, NULL));

	SSL_shutdown(d->cSSL);
	SSL_free(d->cSSL);
	ndc_close(fd);
	return 1;
}

static void descr_new(int ssl) {
	struct sockaddr_in addr;
	socklen_t addr_len = (socklen_t)sizeof(addr);
	int fd = accept(ssl ? srv_ssl_fd : srv_fd, (struct sockaddr *) &addr, &addr_len);
	struct descr *d;

	if (fd <= 0)
		return;

	/* fprintf(stderr, "descr_new %d\n", fd); */

	FD_SET(fd, &fds_active);

	d = &descr_map[fd];
	memset(d, 0, sizeof(struct descr));
	d->fd = fd;
	d->flags = DF_BINARY | DF_FIN | DF_ACCEPTED;
	d->remaining_size = BUFSIZ * 64;
	d->remaining = malloc(d->remaining_size);

	errno = 0;
	if (ssl) {
		d->cSSL = SSL_new(ssl_ctx);
		SSL_set_fd(d->cSSL, fd);
		if (ssl_accept(fd))
			return;
	}
}

static void
cmd_new(int *argc_r, char *argv[CMD_ARGM], int fd, char *input, size_t len)
{
	static unsigned char buf[BUFSIZ * 30];
	struct cmd cmd;
	register char *p = buf;
	int argc = 0;

	memcpy(buf, input, len);

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

static int
ndc_lower_write(int fd, void *from, size_t len)
{
	struct descr *d = &descr_map[fd];

	return d->cSSL
		? SSL_write(d->cSSL, from, len)
		: write(fd, from, len);
}

static int
ndc_write_remaining(int fd) {
	struct descr *d = &descr_map[fd];

	if (!d->remaining_len)
		return 0;

	int ret = ndc_lower_write(fd, d->remaining, d->remaining_len);

	if (ret < 0 && errno == EAGAIN)
		return -1;

	d->remaining_len = 0;
	if (d->flags & DF_TO_CLOSE)
		ndc_close(fd);
	return ret;
}

inline static void
ndc_rem_may_inc(int fd, size_t len) {
	struct descr *d = &descr_map[fd];
	d->remaining_len += len;

	if (d->remaining_len < d->remaining_size)
		return;

	d->remaining_size *= 2;
	d->remaining_size += d->remaining_len;
	d->remaining = realloc(d->remaining, d->remaining_size);
}

int
ndc_low_write(int fd, void *from, size_t len)
{
	struct descr *d = &descr_map[fd];

	if (d->remaining_len) {
		size_t olen = d->remaining_len;
		ndc_rem_may_inc(fd, len);
		memcpy(d->remaining + olen, from, len);
		ndc_write_remaining(fd);
		return -1;
	}

	d->remaining_len = 0;
	int ret = ndc_lower_write(fd, from, len);

	if (ret < 0 && errno == EAGAIN) {
		ndc_rem_may_inc(fd, len);
		memcpy(d->remaining, from, len);
	}

	return ret;
}

int
ndc_low_read(int fd, void *to, size_t len)
{
	struct descr *d = &descr_map[fd];

	return d->cSSL
		? SSL_read(d->cSSL, to, len)
		: read(fd, to, len);
}

static int
ndc_read(int fd, void *data, size_t len)
{
	struct descr *d = &descr_map[fd];
	/* fprintf(stderr, "ndc_read %d %lu\n", fd, len); */
	return d->flags & DF_WEBSOCKET ? ws_read(fd, data, len) : ndc_low_read(fd, data, len);
}

int
ndc_write(int fd, void *data, size_t len)
{
	if (fd <= 0)
		return -1;
	struct descr *d = &descr_map[fd];
	/* fprintf(stderr, "ndc_write %d %lu %d\n", fd, len, d->flags); */
	int ret = d->flags & DF_WEBSOCKET ? ws_write(fd, data, len, d->flags) : ndc_low_write(fd, data, len);
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

static void
cmd_proc(int fd, int argc, char *argv[])
{
	if (argc < 1)
		return;

	char *s = argv[0];

	for (s = argv[0]; isalnum(*s); s++);

	int i;
	struct cmd_slot *cmd_i = NULL;

	if (hash_cget(cmds_hd, &i, argv[0], s - argv[0]) >= 0)
		cmd_i = &cmds[i];

	struct descr *d = &descr_map[fd];

	if (!(d->flags & DF_AUTHENTICATED)) {
		if (!cmd_i || !(cmd_i->flags & CF_NOAUTH))
			return;
		d->flags |= DF_CONNECTED;
	}

	if ((!cmd_i && argc) || !(cmd_i->flags & CF_NOTRIM)) {
		// this looks buggy let's fix it, please
		/* fprintf(stderr, "??? %d %p, %d '%s'\n", argc, cmd_i, cmd_i - cmds_hd, argv[0]); */
		char *p = &argv[argc][-2];
		if (*p == '\r') *p = '\0';
		argv[argc] = "";
	}

	if (cmd_i) {
		ndc_command(fd, argc, argv);
		cmd_i->cb(fd, argc, argv);
	} else
		ndc_vim(fd, argc, argv);
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

static int
cmd_parse(int fd, char *cmd, size_t len) {
	int argc;
	char *argv[CMD_ARGM];

	cmd_new(&argc, argv, fd, cmd, len);
	/* fprintf(stderr, "CMD_PARSE %d %lu: '", fd, len); */
	/* for (int i = 0; i < argc; i++) */
	/* 	fprintf(stderr, "%s", argv[i]); */
	/* fprintf(stderr, "'\n"); */

	if (!argc)
		return 0;

	cmd_proc(fd, argc, argv);

	if (argc != 3)
		return 0;

	return len;
}

static void pty_open(int fd) {
	struct descr *d = &descr_map[fd];

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		err(EXIT_FAILURE, "pty_open fcntl F_SETFL O_NONBLOCK");

	d->pty = posix_openpt(O_RDWR | O_NOCTTY);

	/* fprintf(stderr, "pty_open %d %d\n", fd, d->pty); */

	if (d->pty == -1)
		err(EXIT_FAILURE, "pty_open posix_openpt");

	if (grantpt(d->pty) == -1)
		err(EXIT_FAILURE, "pty_open grantpt");

	if (unlockpt(d->pty) == -1)
		err(EXIT_FAILURE, "pty_open unlockpt");

	int flags = fcntl(d->pty, F_GETFL, 0);
	fcntl(d->pty, F_SETFL, flags | O_NONBLOCK);
	TELNET_CMD(IAC, WILL, TELOPT_ECHO);
	TELNET_CMD(IAC, WONT, TELOPT_SGA);
	descr_map[d->pty].fd = fd;
	descr_map[d->pty].pty = -1;
	FD_SET(d->pty, &fds_active);

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

	if (!(d->flags & DF_ACCEPTED)) {
		if (d->cSSL && ssl_accept(fd))
			return 1;
		if (!(d->flags & DF_ACCEPTED))
			return 0;
	}

	ret = ndc_read(fd, d->cmd, sizeof(d->cmd));
	switch (ret) {
	case -1:
		if (errno == EAGAIN)
			return 0;

		fprintf(stderr, "descr_read: failed - will close");
		return -1;
	/* case 0: return 0; */
	case 0: return -1;
	}

	/* fprintf(stderr, "descr_read %d %d %s\n", d->fd, ret, d->cmd); */

	int i = 0, li = 0;

	for (; i < ret && d->cmd[i] != IAC; i++);

	if (i == ret)
		i = 0;

	while (i < ret && d->cmd[i + 0] == IAC) if (d->cmd[i + 1] == SB && d->cmd[i + 2] == TELOPT_NAWS) {
		unsigned char colsHighByte = d->cmd[i + 3];
		unsigned char colsLowByte = d->cmd[i + 4];
		unsigned char rowsHighByte = d->cmd[i + 5];
		unsigned char rowsLowByte = d->cmd[i + 6];
		memset(&d->wsz, 0, sizeof(d->wsz));
		d->wsz.ws_col = (colsHighByte << 8) | colsLowByte;
		d->wsz.ws_row = (rowsHighByte << 8) | rowsLowByte;
		ioctl(d->pty, TIOCSWINSZ, &d->wsz);
		i += 9;
	} else if (d->cmd[i + 1] == DO && d->cmd[i + 2] == TELOPT_SGA) {
		/* this must change pty tty settings as well. Not just reply */
		/* TELNET_CMD(IAC, WONT, TELOPT_ECHO, IAC, WILL, TELOPT_SGA); */
		i += 3;
	} else if (d->cmd[i + 1] == DO) {
		/* TELNET_CMD(IAC, WILL, d->cmd[i + 2]); */
		i += 3;
	} else if (d->cmd[i + 1] == DONT) {
		/* TELNET_CMD(IAC, WONT, d->cmd[i + 2]); */
		i += 3;
	} else if (d->cmd[i + 1] == DO || d->cmd[i + 1] == DONT || d->cmd[i + 1] == WILL)
		i += 3;
	else
		i++;

	if (d->pid > 0) {
		if (waitpid(d->pid, NULL, WNOHANG)) {
			return 0;
		} else if (i < ret) {
			write(d->pty, d->cmd + i, ret);
			return 0;
		}
	}

	return cmd_parse(fd, (char *) d->cmd, ret);
}

static void
pty_read(int fd)
{
	struct descr *d = &descr_map[fd];
	static char buf[BUFSIZ * 4];
	char pbuf[1];

	errno = 0;
	if (waitpid(d->pid, NULL, WNOHANG)) {
		if (errno == EAGAIN)
			return;
		goto close;
	};

	memset(buf, 0, sizeof(buf));
	errno = 0;
	int ret = read(d->pty, buf, sizeof(buf));

	switch (ret) {
		case 0: return;
		case -1:
			if (errno == EAGAIN || errno == EIO)
				return;
			else
				break;
		default:
			buf[ret] = '\0';
			ndc_write(fd, buf, ret);
			ndc_tty_update(fd);
			return;
	}

close:	if (d->pid > 0)
		kill(d->pid, SIGKILL);

	d->pid = -1;
}

static inline void descr_proc() {
	for (register int i = 0; i < FD_SETSIZE; i++)
		if (descr_map[i].remaining_len)
			ndc_write_remaining(i);
		else if (!FD_ISSET(i, &fds_read))
			;
		else if (i == srv_fd)
			descr_new(0);
		else if (i == srv_ssl_fd)
			descr_new(1);
		else if (descr_map[i].pty == -2)
			pty_read(descr_map[i].fd);
		else if (descr_map[i].pty != -1 && descr_read(i) < 0)
			ndc_close(i);
}

static void
cmds_init() {
	int i;

	cmds_hd = hash_init();

	for (i = 0; cmds[i].name; i++)
		hash_cput(cmds_hd, cmds[i].name, strlen(cmds[i].name), &i, sizeof(i));
}

static long long timestamp() {
	struct timeval te;
	gettimeofday(&te, NULL); // get current time
	return te.tv_sec * 1000000LL + te.tv_usec;
}

static void
ndc_bind(int *srv_fd_r, int ssl) {
	int srv_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (srv_fd < 0)
		err(EXIT_FAILURE, "socket");

	int opt = 1;
	if (setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt)) < 0)
		err(EXIT_FAILURE, "srv_fd setsockopt SO_REUSEADDR");

	opt = 1;
	if (setsockopt(srv_fd, SOL_SOCKET, SO_KEEPALIVE, (char *) &opt, sizeof(opt)) < 0)
		err(EXIT_FAILURE, "srv_fd setsockopt SO_KEEPALIVE");

	if (fcntl(srv_fd, F_SETFL, O_NONBLOCK) == -1)
		err(EXIT_FAILURE, "srv_fd fcntl F_SETFL O_NONBLOCK");

	if (fcntl(srv_fd, F_SETFD, FD_CLOEXEC) == -1)
		err(EXIT_FAILURE, "srv_fd fcntl F_SETFL FD_CLOEXEC");

	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(ssl
			? (config.ssl_port ? config.ssl_port : 443)
			: (config.port ? config.port : 80));

	if (bind(srv_fd, (struct sockaddr *) &server, sizeof(server)))
		err(EXIT_FAILURE, "bind");

	descr_map[srv_fd].fd = srv_fd;

	listen(srv_fd, 32);

	FD_SET(srv_fd, &fds_active);

	*srv_fd_r = srv_fd;
}

void ndc_init(struct ndc_config *config_r) {
	memcpy(&config, config_r, sizeof(config));
	ndc_srv_flags = config.flags | NDC_WAKE;

	if (ndc_srv_flags & NDC_SSL) {
		SSL_load_error_strings();
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		ssl_ctx = SSL_CTX_new(TLS_server_method());
		SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
		SSL_CTX_use_certificate_file(ssl_ctx, config.ssl_crt, SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(ssl_ctx, config.ssl_key, SSL_FILETYPE_PEM);
		ERR_print_errors_fp(stderr);
	}

	if (!config.chroot)
		fprintf(stderr, "Running from cwd\n");
	else if (!geteuid()) {
		if (chroot(config.chroot) != 0)
			err(EXIT_FAILURE, "ndc_main chroot");
		if (chdir("/") != 0)
			err(EXIT_FAILURE, "ndc_main chdir");
	} else if (chdir(config.chroot) != 0)
		err(EXIT_FAILURE, "ndc_main chdir2");

	cmds_init();
	mime_hd = hash_init();
	static char *mime_table[] = {
		"html\0text/html",
		"txt\0text/plain",
		"css\0text/css",
		"js\0application/javascript",
		NULL,
	};
	shash_table(mime_hd, mime_table);

	atexit(cleanup);
	signal(SIGTERM, sig_shutdown);
	signal(SIGINT, sig_shutdown);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	if (config.flags & NDC_SSL)
		ndc_bind(&srv_ssl_fd, 1);

	ndc_bind(&srv_fd, 0);
	
	if ((ndc_srv_flags & NDC_DETACH) && daemon(1, 1) != 0)
		exit(EXIT_SUCCESS);
}

int ndc_main() {
	struct timeval timeout;

	ndc_tick = timestamp();

	while (ndc_srv_flags & NDC_WAKE) {
		long long last = ndc_tick;
		ndc_tick = timestamp();
		dt = ndc_tick - last;

		ndc_update(dt);

		if (!(ndc_srv_flags & NDC_WAKE))
			break;

		for (register int i = 0; i < FD_SETSIZE; i++)
			if (descr_map[i].remaining_len)
				ndc_write_remaining(i);

		timeout.tv_sec = 0;
		timeout.tv_usec = 100;

		fds_read = fds_active;
		int select_n = select(FD_SETSIZE, &fds_read, NULL, NULL, &timeout);

		switch (select_n) {
		case -1:
			switch (errno) {
			case EAGAIN: /* return 0; */
			case EINTR:
			case EBADF: continue;
			}

			perror("select");
			return -1;

		case 0: continue;
		}

		for (; select_n; select_n--)
			descr_proc();
	}

	return 0;
}

static struct passwd *drop_priviledges(int fd) {
	struct descr *d = &descr_map[fd];

	if (!(d->flags & DF_AUTHENTICATED))
		err(EXIT_FAILURE, "NOT AUTHENTICATED");

	struct passwd *pw = getpwnam(d->username);

	if (!config.chroot) {
		fprintf(stderr, "NOT CHROOTED\n");
		return pw;
	}
	
	if (!pw)
		err(EXIT_FAILURE, "drop_priviledges getpwnam");

	uid_t new_uid = pw->pw_uid;
	gid_t new_gid = pw->pw_gid;

	if (setgroups(0, NULL) != 0)
		err(EXIT_FAILURE, "drop_priviledges setgroups");

	if (setgid(new_gid) != 0)
		err(EXIT_FAILURE, "drop_priviledges setgid");

	if (setuid(new_uid) != 0)
		err(EXIT_FAILURE, "drop_priviledges setuid");

	if (setenv("HOME", pw->pw_dir, 1) != 0)
		err(EXIT_FAILURE, "drop_priviledges setenv HOME");

	if (setenv("USER", pw->pw_name, 1) != 0)
		err(EXIT_FAILURE, "drop_priviledges setenv USER");

	if (setenv("SHELL", pw->pw_shell, 1) != 0)
		err(EXIT_FAILURE, "drop_priviledges setenv SHELL");

	if (setenv("PATH", "/bin:/usr/bin:/usr/local/bin", 1) != 0)
		err(EXIT_FAILURE, "drop_priviledges setenv PATH");

	if (setenv("LD_LIBRARY_PATH", "/lib:/usr/lib:/usr/local/lib", 1) != 0)
		err(EXIT_FAILURE, "drop_priviledges setenv LD_LIBRARY_PATH");

	return pw;
}

inline static int
command_pty(int cfd, struct winsize *ws, char * const args[])
{
	struct descr *d = &descr_map[cfd];
	struct termios tty = d->tty;
	pid_t p;

	/* fprintf(stderr, "command_pty WILL EXEC %s\n", args[0]); */
	FD_SET(d->pty, &fds_active);
	descr_map[d->pty].pty = -2;

	p = fork();
	if(p == 0) { /* child */
		do_cleanup = 0;

		struct descr *d = &descr_map[cfd];
		if (setsid() == -1) {
			perror("setsid");
			exit(EXIT_FAILURE);
		}

		if (!(d->flags & DF_AUTHENTICATED))
			err(EXIT_FAILURE, "NOT AUTHENTICATED");

		int slave_fd = open(ptsname(d->pty), O_RDWR);

		struct passwd *pw = drop_priviledges(cfd);
		int pflags = fcntl(slave_fd, F_GETFL, 0);
		if (pflags == -1 || fcntl(slave_fd, F_SETFL, pflags | FD_CLOEXEC) == -1)
			exit(EXIT_FAILURE);

		/* fprintf(stderr, "open pty %s\n", ptsname(d->pty)); */

		if (slave_fd == -1)
			err(EXIT_FAILURE, "command_pty open");

		if (ioctl(slave_fd, TIOCSWINSZ, ws) == -1)
			err(EXIT_FAILURE, "command_pty ioctl TIOCSWINSZ");

		if (ioctl(slave_fd, TIOCSCTTY, NULL) == -1)
			err(EXIT_FAILURE, "command_pty ioctl TIOCSCTTY");

		if (fcntl(slave_fd, F_SETFD, FD_CLOEXEC) == -1)
			err(EXIT_FAILURE, "command_pty fcntl srv_fd F_SETFL FD_CLOEXEC");

		if (
				-1 == dup2(slave_fd, STDIN_FILENO)
				|| -1 == dup2(slave_fd, STDOUT_FILENO)
				|| -1 == dup2(slave_fd, STDERR_FILENO))

			err(EXIT_FAILURE, "command_pty dup2");

		char *alt_args[] = { pw->pw_shell, NULL };
		char * const *real_args = args[0] ? args : alt_args;

		execvp(real_args[0], real_args);
		perror("execvp");
		exit(99);
	}

	return p;
}


void ndc_pty(int fd, char * const args[]) {
	struct descr *d = &descr_map[fd];

	/* fprintf(stderr, "ndc_pty %s %d pty %d SGA %d ECHO %d\n", */
	/* 		args[0], fd, d->pty, WONT, WILL); */

	d->pid = command_pty(fd, &d->wsz, args);

	/* fprintf(stderr, "PTY master fd: %d\n", d->pty); */
}

void
do_sh(int fd, int argc, char *argv[])
{
	uid_t uid = getuid();
	char *args[] = { NULL, NULL };
	ndc_pty(fd, args);
}

static inline unsigned
headers_get(size_t *body_start, char *next_lines)
{
	unsigned req_hd = hash_init();
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
				hash_sput(req_hd, key, value);
				key = s += 2;
			} else
				*++s = '\0';

			break;
		default:
			s++;
			break;
	}

	*body_start = s - next_lines;	

	return req_hd;
}

static inline int
popen2(int *in, int *out, char * const args[])
{
	pid_t p = -1;
	int pipe_stdin[2], pipe_stdout[2];

	if (pipe(pipe_stdin) || pipe(pipe_stdout) || (p = fork()) < 0)
		return p;

	if(p == 0) { /* child */
		do_cleanup = 0;
		close(pipe_stdin[1]);
		dup2(pipe_stdin[0], 0);
		close(pipe_stdout[0]);
		dup2(pipe_stdout[1], 1);
		/* close(pipe_stderr[1]); */
		/* dup2(pipe_stderr[1], 2); */
		execvp(args[0], args);
		perror("popen2: execvp");
		exit(99);
	}

	*in = pipe_stdin[1];
	*out = pipe_stdout[0];
	close(pipe_stdin[0]);
	close(pipe_stdout[1]);
	return p;
}

static inline int
ndc_exec(char * const args[], cmd_cb_t callback, void *arg, void *input, size_t input_len) {
	static char buf[BUFSIZ * 64];
	ssize_t len = 0, total = 0;
	int start = 1, cont = 0;
	int in, out, pid, ret = -1;

	pid = popen2(&in, &out, args); // should assert it equals 0
	callback("", -1, pid, in, out, arg);

	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(out, &read_fds);

	int ready_fds;

	if (input) {
		write(in, input, input_len);
		close(in);
	}

	do {
		ready_fds = select(out + 1, &read_fds, NULL, NULL, NULL);

		if (!ready_fds)
			continue;

		if (ready_fds == -1) {
			perror("Error in select");
			break;
		}

		if (!FD_ISSET(out, &read_fds))
			continue;

		len = read(out, buf, sizeof(buf));

		if (len > 0) {
			buf[len] = '\0';
			callback(buf, len, pid, in, out, arg);
			total += len;
		} else if (len == 0) {
			callback("", 0, pid, in, out, arg);
			ret = 0;
			break;
		} else switch (errno) {
			case EAGAIN:
				continue;
			default:
				perror("Error in read");
				goto out;
		}
	} while (1);

out:	close(in);
	close(out);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return 0;
}

void do_GET_cb(char *buf, ssize_t len, int pid, int in, int out, void *arg) {
	int fd = * (int *) arg;
	if (len <= 0)
		return;
	ndc_write(fd, buf, len);
}

static char *env_name(void *key, size_t key_size) {
	static char buf[BUFSIZ];
	int i = 0;
	register char *b, *s;
	memset(buf, 0, BUFSIZ);
	strcpy(buf, "HTTP_");
	for (s = (char *) key, b = buf + 5; *s && i < key_size; s++, b++, i++)
		if (*s == '-')
			*b = '_';
		else
			*b = toupper(*s);
	return buf;
}

static void url_decode(char *str) {
    char *src = str, *dst = str;

    while (*src) {
        if (*src == '%' && src[1] && src[2] && isxdigit(src[1]) && isxdigit(src[2])) {
            int value;
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

int ndc_headers(int fd) {
	struct descr *d = &descr_map[fd];
	return d->headers;
}

static char *env_sane(char *str) {
	static char buf[BUFSIZ];
	char *b;
	for (b = buf; b - buf - 1 < BUFSIZ && (isalnum(*str) || *str == '/'
				|| *str == '&' || *str == '_' || *str == '-'
				|| *str == ' ' || *str == '=' || *str == ';'); str++, b++)
		*b = *str;
	*b = '\0';
	return buf;
}

static void request_handle(int fd, int argc, char *argv[], int post) {
	char *method = post ? "POST" : "GET";
	struct passwd *pw;
	struct descr *d = &descr_map[fd];
	size_t body_start;
	d->headers = headers_get(&body_start, argv[argc]);
	uid_t uid;
	char *ws_key = hash_sget(d->headers, "Sec-WebSocket-Key");

	if (ws_key) {
		if (ws_init(fd, ws_key))
			return;
		d->flags |= DF_WEBSOCKET;
		TELNET_CMD(IAC, DO, TELOPT_NAWS);
		d->flags |= DF_CONNECTED;
		ndc_connect(fd);
		return;
	} else if (argc < 2 || strstr(argv[1], "..")) {
		ndc_close(fd);
		return;
	}

	d->flags |= DF_TO_CLOSE;

	if (config.flags & NDC_SSL && !d->cSSL) {
		char *host = hash_sget(d->headers, "Host");
		char response[1024];
		snprintf(response, sizeof(response),
				"HTTP/1.1 301 Moved Permanently\r\n"
				"Location: https://%s/%s\r\n"
				"Content-Length: 0\r\n"
				"Connection: close\r\n"
				"\r\n", host, argv[1]);
		ndc_writef(fd, "%s", response);
		if (!d->remaining_len)
			ndc_close(fd);
		return;
	}

	/* fprintf(stderr, "%d %s %s\n", fd, method, argv[1]); */

	chdir("./htdocs");

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		fprintf(stderr, "do_%s: fcntl F_GETFL\n", method);
		goto end;
	}

	flags |= O_SYNC;

	if (fcntl(fd, F_SETFL, flags) == -1) {
		fprintf(stderr, "do_%s: fcntl F_SETFL\n", method);
		goto end;
	}


	static char * common = "HTTP/1.1 ", *content_type = "text/plain";
	char *status = "200 OK";
	struct stat stat_buf;
	char filename[64], *alt = "../.index";
	char *body = argv[argc] + body_start + 1;
	off_t total = 0;
	int want_fd = -1, lost = 1;
	*filename = '\0';

	if (lost)
		sprintf(filename, ".%s", argv[1]);

	url_decode(filename);

	if (!argv[1][1] || stat(filename, &stat_buf)) {
		if (stat(alt, &stat_buf)) {
			status = "404 Not Found";
			total = strlen(status);
		} else if (access(alt, X_OK) != 0) {
			status = "403 Forbidden";
			total = strlen(status);
		} else {
			char * args[2] = { NULL, NULL };
			char uribuf[64];
			char * uri;
			char * query_string = strchr(argv[1], '?');
			char key[BUFSIZ], *value;
			ssize_t key_len;
			struct hash_cursor c;
			memcpy(uribuf, argv[1], sizeof(uribuf));
			query_string = strchr(uribuf, '?');
			if (query_string)
				*query_string++ = '\0';
			else
				query_string = "";
			args[0] = alt + 1;
			c = hash_iter(d->headers);
			while ((key_len = hash_next(key, &value, &c)) >= 0)
				setenv(env_name(key, key_len), value, 1);
			char *req_content_type = hash_sget(d->headers, "Content-Type");
			if (!req_content_type)
				req_content_type = "text/plain";
			setenv("CONTENT_TYPE", env_sane(req_content_type), 1);
			setenv("DOCUMENT_URI", uribuf, 1);
			setenv("QUERY_STRING", env_sane(query_string), 1);
			setenv("SCRIPT_NAME", alt, 1);
			setenv("REQUEST_METHOD", method, 1);
			setenv("DOCUMENT_ROOT", geteuid() ? config.chroot : "", 1);
			chdir("..");
			ndc_writef(fd, "HTTP/1.1 ");
			ndc_exec(args, do_GET_cb, &fd, body, strlen(body));
			c = hash_iter(d->headers);
			while ((key_len = hash_next(key, &value, &c)) >= 0)
				unsetenv(env_name(key, key_len));
			if (!d->remaining_len)
				ndc_close(fd);
			return;
		}
	} else {
		errno = 0;
		char *ext = filename, *s;
		for (s = ext; *s; s++)
			if (*s == '.')
				ext = s + 1;

		content_type = "application/octet-stream";
		if (ext) {
			char *found = hash_sget(mime_hd, ext);
			if (found)
				content_type = found;
		}

		want_fd = open(filename, O_RDONLY);
		total = stat_buf.st_size;

	}

	time_t now = time(NULL);
	struct tm *tm_info = gmtime(&now);
	char date[100];
	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", tm_info);

	ndc_writef(fd, "HTTP/1.1 %s\r\n"
			"Date: %s\r\n"
			"Server: ndc/0.0.1 (Unix)\r\n"
			"Content-Length: %lu\r\n"
			"Content-Type: %s\r\n"
			"\r\n",
			status, date, total, content_type);


	if (want_fd <= 0) {
		ndc_write(fd, status, strlen(status));
		goto end;
	}

	// static file
	ssize_t len;
	char b[BUFSIZ * 16];

	while ((len = read(want_fd, b, sizeof(b))) > 0)
		ndc_write(fd, b, len);

	close(want_fd);

end:
	chdir("..");
	if (!d->remaining_len)
		ndc_close(fd);
}

void
do_GET(int fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, 0);
}

void
do_POST(int fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, 1);
}

int ndc_flags(int fd) {
	return descr_map[fd].flags;
}

void ndc_set_flags(int fd, int flags) {
	descr_map[fd].flags = flags;
}

void ndc_auth(int fd, char *username) {
	struct descr *d = &descr_map[fd];
	/* fprintf(stderr, "ndc_auth %d %s\n", fd, username); */
	strcpy(d->username, username);
	d->flags |= DF_AUTHENTICATED;
	pty_open(fd);
}
