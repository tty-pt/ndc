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
	unsigned long long loc;
	unsigned char cmd[BUFSIZ * 2];
	char username[BUFSIZ];
	struct winsize wsz;
	struct termios tty;
	int headers;
} descr_map[FD_SETSIZE];

struct cmd {
	int fd;
	int argc;
	char *argv[8];
};

ndc_cb_t do_GET, do_POST, do_sh;

extern struct cmd_slot cmds[];

struct ndc_config config;

static int ndc_srv_flags = 0, srv_fd = -1;
static int cmds_hd = -1, mime_hd = -1;
static fd_set fds_read, fds_active, fds_write;
static size_t cmds_len = 0;
long long dt, tack = 0;
SSL_CTX *ssl_ctx;
long long ndc_tick;

static void
pty_close(int fd) {
	struct descr *d = &descr_map[fd];
	fprintf(stderr, "pty_close %d %d\n", fd, d->pty);

	/* if (d->pid <= 0) */
	/* 	return; */

	close(d->pty);
	waitpid(d->pid, NULL, 0);
	FD_CLR(d->pty, &fds_active);
	FD_CLR(d->pty, &fds_read);
	d->pid = -1;
}

void
ndc_close(int fd)
{
	struct descr *d = &descr_map[fd];
	fprintf(stderr, "ndc_close %d\n", fd);

	if (d->flags & DF_CONNECTED)
		ndc_disconnect(fd);

	d->flags = 0;
	if (d->pid > 0)
		kill(d->pid, SIGINT);
	if (d->flags & DF_WEBSOCKET)
		ws_close(fd);
	if (d->pty > 0)
		pty_close(fd);
	if ((d->flags & DF_ACCEPTED) && ndc_srv_flags & NDC_SSL) {
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
	d->pty = -1;
	d->pid = -1;
	memset(d, 0, sizeof(struct descr));
}

static void cleanup()
{
	fprintf(stderr, "Cleanup!\n");
	DESCR_ITER
		ndc_close(di_i);

	DESCR_ITER if (descr_map[di_i].pid > 0)
		waitpid(descr_map[di_i].pid, NULL, 0);
}

void sig_shutdown(int i)
{

	ndc_srv_flags &= ~NDC_WAKE;
}

void ndc_tty_update(int fd);

static void tty_init(int fd) {
	struct descr *d = &descr_map[fd];
	d->tty.c_lflag = ICANON | ECHO | ECHOK;
	d->tty.c_iflag = IGNCR;
	d->tty.c_iflag &= ~ICRNL;
	d->tty.c_iflag &= ~INLCR;
	d->tty.c_oflag |= OPOST | ONLCR;
	d->tty.c_oflag &= ~OCRNL;
	tcsetattr(d->pty, TCSANOW, &d->tty);
	ndc_tty_update(fd);
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

static void descr_new() {
	struct sockaddr_in addr;
	socklen_t addr_len = (socklen_t)sizeof(addr);
	int fd = accept(srv_fd, (struct sockaddr *) &addr, &addr_len);
	struct descr *d;

	if (fd <= 0)
		return;

	fprintf(stderr, "descr_new %d\n", fd);

	FD_SET(fd, &fds_active);

	d = &descr_map[fd];
	memset(d, 0, sizeof(struct descr));
	d->fd = fd;
	d->flags = DF_BINARY | DF_FIN | DF_ACCEPTED;

	errno = 0;
	if (ndc_srv_flags & NDC_SSL) {
		d->cSSL = SSL_new(ssl_ctx);
		SSL_set_fd(d->cSSL, fd);
		if (ssl_accept(fd))
			return;
	}
}

static void
cmd_new(int *argc_r, char *argv[CMD_ARGM], int fd, char *input, size_t len)
{
	static unsigned char buf[BUFSIZ * 2];
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

	for (p = input; *p && *p != '\r'; p++) if (isspace(*p)) {
		*p = '\0';
		argv[argc] = p + 1;
		argc ++;
	}

	for (int i = argc; i < CMD_ARGM; i++)
		argv[i] = "";

	argv[argc] = p + 2;

	*argc_r = argc;
}

int
ndc_low_write(int fd, void *from, size_t len)
{
	if (ndc_srv_flags & NDC_SSL) {
		int ret;
		while ((ret = SSL_write(descr_map[fd].cSSL, from, len)) <= 0) {
			int err = SSL_get_error(descr_map[fd].cSSL, ret);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
				continue;
			break;
		}
		return ret;
	} else
		return write(fd, from, len);
}

int
ndc_low_read(int fd, void *to, size_t len)
{
	return ndc_srv_flags & NDC_SSL
		? SSL_read(descr_map[fd].cSSL, to, len)
		: read(fd, to, len);
}

int
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
	if (d->flags & DF_WERROR)
		return -1;
	int ret = d->flags & DF_WEBSOCKET ? ws_write(fd, data, len, d->flags) : ndc_low_write(fd, data, len);
	if (ret == -1)
		d->flags |= DF_WERROR;
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

void
cmd_proc(int fd, int argc, char *argv[])
{
	if (argc < 1)
		return;

	char *s = argv[0];

	for (s = argv[0]; isalnum(*s); s++);

	struct cmd_slot *cmd_i = hash_get(cmds_hd, argv[0], s - argv[0]);
	struct descr *d = &descr_map[fd];

	if (!(d->flags & DF_CONNECTED)) {
		if (!cmd_i || !(cmd_i->flags & CF_NOAUTH))
			return;
		d->flags |= DF_CONNECTED;
	}

	unsigned long long old = d->loc;
	if ((!cmd_i && argc) || !(cmd_i->flags & CF_NOTRIM)) {
		// this looks buggy let's fix it, please
		/* fprintf(stderr, "??? %d %p, %d '%s'\n", argc, cmd_i, cmd_i - cmds_hd, argv[0]); */
		char *p = &argv[argc][-2];
		if (*p == '\r') *p = '\0';
		argv[argc] = "";
	}

	if (cmd_i)
		cmd_i->cb(fd, argc, argv);
	else
		ndc_vim(fd, argc, argv);

	if (old != d->loc)
		ndc_view(fd, argc, argv);
}

void
ndc_tty_update(int fd)
{
	struct descr *d = &descr_map[fd];
	struct termios last = d->tty;
	tcgetattr(d->pty, &d->tty);

	if ((last.c_lflag & ECHO) != (d->tty.c_lflag & ECHO))
		TELNET_CMD(IAC, d->tty.c_lflag & ECHO ? WILL : WONT, TELOPT_ECHO);

	if ((last.c_lflag & ICANON) != (d->tty.c_lflag & ICANON))
		TELNET_CMD(IAC, d->tty.c_lflag & ICANON ? WONT : WILL, TELOPT_SGA);
}

int
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

	fprintf(stderr, "pty_open %d %d\n", fd, d->pty);

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		err(1, "pty_open fcntl F_SETFL O_NONBLOCK");

	d->pty = posix_openpt(O_RDWR | O_NOCTTY);

	if (d->pty == -1)
		err(1, "pty_open posix_openpt");

	if (grantpt(d->pty) == -1)
		err(1, "pty_open grantpt");

	if (unlockpt(d->pty) == -1)
		err(1, "pty_open unlockpt");

	int flags = fcntl(d->pty, F_GETFL, 0);
	fcntl(d->pty, F_SETFL, flags | O_NONBLOCK);
	tcsetattr(d->pty, TCSANOW, &d->tty);
	ndc_tty_update(fd);
	descr_map[d->pty].fd = fd;
	descr_map[d->pty].pty = -1;
	FD_SET(d->pty, &fds_active);
	tty_init(fd);
}

int
descr_read(int fd)
{
	struct descr *d = &descr_map[fd];
	int ret;

	/* fprintf(stderr, "descr_read %d\n", fd); */

	if (!(d->flags & DF_ACCEPTED)) {
		if (ssl_accept(fd))
			return 1;
		if (!(d->flags & DF_ACCEPTED))
			return 0;
	}

	ret = ndc_read(fd, d->cmd, sizeof(d->cmd));
	switch (ret) {
	case -1:
		if (errno == EAGAIN)
			return 0;

		warn("descr_read: failed - will close");
		return -1;
	/* case 0: return 0; */
	case 0: return -1;
	}

	fprintf(stderr, "descr_read %d %d\n", d->fd, ret);

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
			fprintf(stderr, "descr_read waitpid\n");
			/* pty_close(fd); */
			/* pty_open(fd); */
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
	char buf[BUFSIZ * 4];

	memset(buf, 0, sizeof(buf));

	if (!(FD_ISSET(d->pty, &fds_read) && d->pid > 0))
		return;

	if (waitpid(d->pid, NULL, WNOHANG)) {
		fprintf(stderr, "pty_read %d STOP %d %d %s\n", fd, d->pid, errno, buf);
		d->pid = -1;
		/* pty_close(fd); */
		/* pty_open(fd); */
		return;
	}

	int ret = read(d->pty, buf, sizeof(buf));
	fprintf(stderr, "pty_read %d READ %d %d %d %s\n", fd, d->pid, ret, errno, buf);

	switch (ret) {
		case -1:
			if (errno == EAGAIN || errno == EIO)
				return;
		case 0: 
		case 1:
			 if (d->tty.c_lflag & ICANON)
				 return;
		default:
			buf[ret] = '\0';
			ndc_write(fd, buf, ret);
			ndc_tty_update(fd);
	}
}

void descr_proc() {
	for (register int i = 0; i < FD_SETSIZE; i++)
		if (!FD_ISSET(i, &fds_read))
			;
		else if (i == srv_fd)
			descr_new();
		else if (descr_map[i].flags & DF_WERROR || descr_map[i].pty != -1 && descr_read(i) < 0)
			ndc_close(i);
		else
			pty_read(descr_map[i].fd);
}

static void
cmds_init() {
	int i;

	cmds_hd = hash_init();

	for (i = 0; cmds[i].name; i++)
		SHASH_PUT(cmds_hd, cmds[i].name, &cmds[i]);
}

long long timestamp() {
	struct timeval te;
	gettimeofday(&te, NULL); // get current time
	return te.tv_sec * 1000LL + te.tv_usec / 1000;
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
			err(1, "ndc_main chroot");
		if (chdir("/") != 0)
			err(1, "ndc_main chdir");
	} else if (chdir(config.chroot) != 0)
		err(1, "ndc_main chdir2");

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
}

int ndc_main() {
	struct timeval timeout;

	atexit(cleanup);
	signal(SIGTERM, sig_shutdown);
	signal(SIGINT, sig_shutdown);
	signal(SIGPIPE, SIG_IGN);

	srv_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (srv_fd < 0)
		err(3, "socket");

	int opt = 1;
	if (setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt)) < 0)
		err(1, "srv_fd setsockopt SO_REUSEADDR");

	opt = 1;
	if (setsockopt(srv_fd, SOL_SOCKET, SO_KEEPALIVE, (char *) &opt, sizeof(opt)) < 0)
		err(1, "srv_fd setsockopt SO_KEEPALIVE");

	if (fcntl(srv_fd, F_SETFL, O_NONBLOCK) == -1)
		err(1, "srv_fd fcntl F_SETFL O_NONBLOCK");

	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(config.port ? config.port : (config.flags & NDC_SSL ? 443 : 80));

	if (bind(srv_fd, (struct sockaddr *) &server, sizeof(server)))
		err(4, "bind");

	descr_map[0].fd = srv_fd;

	listen(srv_fd, 5);

	FD_SET(srv_fd, &fds_active);

	if ((ndc_srv_flags & NDC_DETACH) && daemon(1, 1) != 0)
		return 0;

	ndc_tick = timestamp();

	while (ndc_srv_flags & NDC_WAKE) {
		long long last = ndc_tick;
		ndc_tick = timestamp();
		dt = ndc_tick - last;

		ndc_update(dt);

		if (!(ndc_srv_flags & NDC_WAKE))
			break;

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

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

	cleanup();

	return 0;
}

struct popen {
	int in, out, pid;
};

struct {
	struct termios tty;
	int slave_fd;
} clients[FD_SETSIZE];

void cleanup_handler(int sig) {
	for (int i = 0; i < FD_SETSIZE; ++i) if (clients[i].slave_fd != -1) {
		tcsetattr(i, TCSANOW, &clients[i].tty);
		close(clients[i].slave_fd);
		clients[i].slave_fd = -1;
	}
}

void drop_priviledges(int fd) {
	struct descr *d = &descr_map[fd];

	if (!config.chroot)
		return;
	
	if (!(d->flags & DF_AUTHENTICATED))
		exit(1);

	struct passwd *pw = getpwnam(d->username);
	if (!pw) {
		fprintf(stderr, "NO PW INFORMATION\n");
		exit(1);
	}

	uid_t new_uid = pw->pw_uid;
	gid_t new_gid = pw->pw_gid;

	if (setgroups(0, NULL) != 0) {
		perror("drop_priviledges failed to drop supplementary group IDs");
		exit(1);
	}

	if (setgid(new_gid) != 0) {
		perror("drop_priviledges failed to set GID");
		exit(1);
	}

	if (setuid(new_uid) != 0) {
		perror("drop_priviledges failed to set UID");
		exit(1);
	}

	if (setenv("HOME", pw->pw_dir, 1) != 0) {
		perror("drop_priviledges Failed to set HOME environment variable");
		exit(1);
	}

	if (setenv("USER", pw->pw_name, 1) != 0) {
		perror("drop_priviledges Failed to set USER environment variable");
		exit(1);
	}

	if (setenv("SHELL", pw->pw_shell, 1) != 0) {
		perror("drop_priviledges Failed to set SHELL environment variable");
		exit(1);
	}

	if (setenv("PATH", "/bin:/usr/bin", 1) != 0) {
		perror("drop_priviledges Failed to set PATH environment variable");
		exit(1);
	}
}

int
command_pty(int cfd, struct winsize *ws, char * const args[])
{
	struct descr *d = &descr_map[cfd];
	struct termios tty = d->tty;
	pid_t p;

	fprintf(stderr, "command_pty WILL EXEC %s\n", args[0]);
	p = fork();
	if(p == 0) { /* child */
		setsid();

		int slave_fd = open(ptsname(d->pty), O_RDWR);
		if (slave_fd == -1) {
			perror("open slave pty");
			exit(EXIT_FAILURE);
		}

		ioctl(slave_fd, TIOCSWINSZ, ws);

		if (ioctl(slave_fd, TIOCSCTTY, NULL) == -1)
			perror("ioctl TIOCSCTTY");

		int flags;
		flags = fcntl(slave_fd, F_GETFL, 0);
		fcntl(slave_fd, F_SETFL, flags | O_NONBLOCK);

		struct termios tty;
		tcgetattr(slave_fd, &tty); // Get current terminal attributes
		clients[slave_fd].tty = tty;
		clients[slave_fd].slave_fd = slave_fd;
		tcsetattr(slave_fd, TCSANOW, &tty); // Set the attributes to make the changes take effect immediately

		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = cleanup_handler;
		sigaction(SIGTERM, &sa, NULL);

		dup2(slave_fd, STDIN_FILENO);
		dup2(slave_fd, STDOUT_FILENO);
		dup2(slave_fd, STDERR_FILENO);
		/* close(d->pty); */

		drop_priviledges(cfd);

		execvp(args[0], args);
		perror("execvp");
		exit(99);
	}

	return p;
}


void ndc_pty(int fd, char * const args[]) {
	struct descr *d = &descr_map[fd];

	fprintf(stderr, "ndc_pty %s %d pty %d SGA %d ECHO %d\n",
			args[0], fd, d->pty, WONT, WILL);

	d->pid = command_pty(fd, &d->wsz, args);

	int flags = fcntl(d->pty, F_GETFL, 0);

	if (flags == -1)
		err(1, "fcntl F_GETFL");

	flags |= O_NONBLOCK;

	if (fcntl(d->pty, F_SETFL, flags) == -1)
		err(1, "fcntl F_SETFL O_NONBLOCK");
}

void
do_sh(int fd, int argc, char *argv[])
{
	uid_t uid = getuid();
	struct passwd *pw = getpwuid(uid);
	if (!pw)
		return;
	char *args[] = { pw->pw_shell, NULL };
	ndc_pty(fd, args);
}

int
headers_get(size_t *body_start, char *next_lines)
{
	int req_hd = hash_init();
	register char *s, *key, *value;

	for (s = next_lines, key = s, value = s; *s; ) switch (*s) {
		case ':':
			*s = '\0';
			value = (s += 2);
			break;
		case '\r':
			*s = '\0';
			if (s != key) {
				SHASH_PUT(req_hd, key, value);
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

int
popen2(int *in, int *out, char * const args[])
{
	pid_t p = -1;
	int pipe_stdin[2], pipe_stdout[2];

	if (pipe(pipe_stdin) || pipe(pipe_stdout) || (p = fork()) < 0)
		return p;

	if(p == 0) { /* child */
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

int
ndc_command(char * const args[], cmd_cb_t callback, void *arg, void *input, size_t input_len) {
	static char buf[BUFSIZ];
	ssize_t len = 0, total = 0;
	int start = 1, cont = 0;
	int in, out, pid;

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
			return -1;
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
			break;
		} else switch (errno) {
			case EAGAIN:
				continue;
			default:
				perror("Error in read");
				return -1;
		}
	} while (1);

	close(in);
	close(out);
	kill(pid, 0);
	/* return total; */
	return pid;
}

void do_GET_cb(char *buf, ssize_t len, int pid, int in, int out, void *arg) {
	int fd = * (int *) arg;
	if (len <= 0)
		return;
	ndc_write(fd, buf, len);
}

void header_setenv(void *key, size_t key_size, void *data, void *arg) {
	int fd = * (int *) arg;
	char buf[BUFSIZ];
	int i = 0;
	register char *b, *s;
	memset(buf, 0, BUFSIZ);
	strcpy(buf, "HTTP_");
	for (s = (char *) key, b = buf + 5; *s && i < key_size; s++, b++, i++)
		if (*s == '-')
			*b = '_';
		else
			*b = toupper(*s);
	setenv(buf, (char *) data, 1);
}

void url_decode(char *str) {
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

void request_handle(int fd, int argc, char *argv[], int post) {
	char *method = post ? "POST" : "GET";
	struct passwd *pw;
	struct descr *d = &descr_map[fd];
	size_t body_start;
	d->headers = headers_get(&body_start, argv[argc]);
	uid_t uid;
	char *ws_key = SHASH_GET(d->headers, "Sec-WebSocket-Key");

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

	chdir("./htdocs");

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		warn("do_%s: fcntl F_GETFL\n", method);
		goto end;
	}

	flags |= O_SYNC;

	if (fcntl(fd, F_SETFL, flags) == -1) {
		warn("do_%s: fcntl F_SETFL\n", method);
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
			memcpy(uribuf, argv[1], sizeof(uribuf));
			query_string = strchr(uribuf, '?');
			if (query_string)
				*query_string++ = '\0';
			else
				query_string = "";
			args[0] = alt + 1;
			hash_iter(d->headers, header_setenv, &fd);
			char *req_content_type = SHASH_GET(d->headers, "Content-Type");
			if (!req_content_type)
				req_content_type = "text/plain";
			setenv("CONTENT_TYPE", req_content_type, 1);
			setenv("DOCUMENT_URI", uribuf, 1);
			setenv("QUERY_STRING", query_string, 1);
			setenv("SCRIPT_NAME", alt, 1);
			setenv("REQUEST_METHOD", method, 1);
			setenv("DOCUMENT_ROOT", geteuid() ? config.chroot : "", 1);
			chdir("..");
			ndc_writef(fd, "HTTP/1.1 ");
			/* waitpid(ndc_command(args, do_GET_cb, &fd, body, strlen(body)), NULL, 0); */
			ndc_command(args, do_GET_cb, &fd, body, strlen(body));
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
			char *found = SHASH_GET(mime_hd, ext);
			if (found)
				content_type = found;
		}

		want_fd = open(filename, O_RDONLY);
		fprintf(stderr, "STATIC %s %d %lld\n", filename, want_fd, stat_buf.st_size);
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
	} else {
		ssize_t len = 0, rem = total;
		char body[total], *b = body;

		while ((len = read(want_fd, b, rem)) > 0) {
			rem -= len;
			b += len;
		}

		ndc_write(fd, body, total);
		close(want_fd);
	}
end:
	chdir("..");
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

void ndc_move(int fd, unsigned long long loc) {
	descr_map[fd].loc = loc;
}

void ndc_auth(int fd, char *username) {
	struct descr *d = &descr_map[fd];
	fprintf(stderr, "ndc_auth %d %s\n", fd, username);
	strcpy(d->username, username);
	d->flags |= DF_AUTHENTICATED;
	pty_open(fd);
}
