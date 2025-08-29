#include "./../include/ndc.h"
#include "./../include/ndc-ndx.h"

#include <unistd.h>
#include <signal.h>

#include <qsys.h>
#include <qmap.h>
#include <ndc.h>
#include <ndx.h>

#define NDX_AREG(fname) \
	ndx_areg(#fname, & fname ## _adapter)

NDX_DEF(int, on_ndc_init, int, i);
NDX_DEF(int, on_ndc_exit, int, i);
NDX_DEF(int, on_ndc_update, unsigned long long, dt);
NDX_DEF(int, on_ndc_vim, int, fd, int, argc, char **, argv);
NDX_DEF(int, on_ndc_command, int, fd, int, argc, char **, argv);
NDX_DEF(int, on_ndc_connect, int, fd);
NDX_DEF(int, on_ndc_disconnect, int, fd);

static inline void
ndc_ndx_reg(void) {
	on_ndc_init_adapter_reg();
	on_ndc_exit_adapter_reg();
	on_ndc_update_adapter_reg();
	on_ndc_vim_adapter_reg();
	on_ndc_command_adapter_reg();
	on_ndc_connect_adapter_reg();
	on_ndc_disconnect_adapter_reg();
}

void exit_all(int i) {
	// close databases here
	call_on_ndc_exit(i);

	closelog();
	sync();

	if (i)
		exit(i);
}

void
usage(char *prog) {
	fprintf(stderr, "Usage: %s [-dr?] [-C PATH] [-u USER] [-k PATH] [-c PATH] [-p PORT]\n", prog);
	fprintf(stderr, "    Options:\n");
	fprintf(stderr, "        -C PATH   changes directory to PATH before starting up.\n");
	fprintf(stderr, "        -u USER   login as USER before starting up.\n");
	fprintf(stderr, "        -k PATH   specify SSL certificate 'key' file\n");
	fprintf(stderr, "        -c PATH   specify SSL certificate 'crt' file\n");
	fprintf(stderr, "        -p PORT   specify server port\n");
	fprintf(stderr, "        -d        don't detach\n");
	fprintf(stderr, "        -r        root multiplex mode\n");
	fprintf(stderr, "        -?        display this message.\n");
}

int
main(int argc, char *argv[])
{
	register char c;

	openlog("ndc", LOG_PID | LOG_CONS | LOG_NDELAY,
			LOG_DAEMON);

	ndc_config.flags |= NDC_DETACH;

	while ((c = getopt(argc, argv, "?dK:k:C:rp:s:"))
			!= -1) switch (c)
	{
		case 'd': ndc_config.flags &= ~NDC_DETACH; break;
		case 'p': ndc_config.port = atoi(optarg); break;
		case 'C': ndc_config.chroot = optarg; break;
		case 'K':
		case 'k': break;
		case 'r': ndc_config.flags |= NDC_ROOT; break;
		case 's': ndc_config.ssl_port = atoi(optarg);
			  break;
		default:
			  usage(*argv);
			  return 1;
	}

	optind = 1;

	while ((c = getopt(argc, argv, "?dK:k:C:rp:s:"))
			!= -1)
	{
		switch (c) {
		case 'K':
			ndc_certs_add(optarg);
			break;

		case 'k':
			ndc_cert_add(optarg);
			break;
			
		default: break;
		}
	}

	signal(SIGSEGV, exit_all);

	srand(getpid());

	ndc_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("PRI", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);

	ndc_ndx_reg();

	ndx_load("./core.so");
	ndc_main();

	// temporary
	exit_all(0);

	return 0;
}

char *ndc_auth_check(int fd) {
	static char user[BUFSIZ];
	char cookie[ENV_VALUE_LEN], *eq;
	FILE *fp;

	if (ndc_env_get(fd, cookie, "HTTP_COOKIE"))
		return NULL;

	eq = strchr(cookie, '=');
	if (!eq)
		return NULL;

	snprintf(user, sizeof(user), "./sessions/%s", eq + 1);
	fp = fopen(user, "r");

	if (!fp)
		return NULL;

	fscanf(fp, "%s", user);
	fclose(fp);

	return user;
}

void
ndc_update(unsigned long long dt)
{
	call_on_ndc_update(dt);
}

void ndc_vim(int fd, int argc, char *argv[])
{
	if (!(ndc_flags(fd) & DF_AUTHENTICATED))
		return;

	call_on_ndc_vim(fd, argc, argv);
}

void ndc_command(int fd, int argc, char *argv[])
{
	call_on_ndc_command(fd, argc, argv);
}

int ndc_connect(int fd) {
	call_on_ndc_connect(fd);
	return 0;
}

void ndc_disconnect(int fd) {
	if (!(ndc_flags(fd) & DF_AUTHENTICATED))
		return;

	call_on_ndc_disconnect(fd);
}
