#include "./../include/ndc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <qhash.h>

DB_TXN *txnid;

struct cmd_slot cmds[] = {
	{
		.name = "GET", 
		.cb = &do_GET,
		.flags = CF_NOAUTH | CF_NOTRIM,
	}, {
		.name = "POST", 
		.cb = &do_GET,
		.flags = CF_NOAUTH | CF_NOTRIM,
	}, {
		.name = "sh", 
		.cb = &do_sh,
		.flags = CF_NOAUTH,
	}, {
		.name = NULL
	}
};

void
ndc_update(unsigned long long dt __attribute__((unused)))
{
}

void
ndc_command(int fd __attribute__((unused)), int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
}

void
ndc_vim(int fd __attribute__((unused)), int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
}

int
ndc_connect(int fd __attribute__((unused))) {
	return 0;
}

void
ndc_ws_init(int fd __attribute__((unused))) {
}

void
ndc_disconnect(int fd __attribute__((unused))) {
}

char *
ndc_auth_check(int fd __attribute__((unused))) {
	return NULL;
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
	struct ndc_config config = {
		.flags = NDC_DETACH,
	};
	register char c;

	while ((c = getopt(argc, argv, "?dK:k:C:rp:s:")) != -1) {
		switch (c) {
		case 'd':
			config.flags &= ~NDC_DETACH;
			break;

		case 'K':
		case 'k': break;
			
		case 'C':
			config.chroot = strdup(optarg);
			break;

		case 'r':
			config.flags |= NDC_ROOT;
			break;

		case 'p':
			config.port = atoi(optarg);
			break;

		case 's':
			config.ssl_port = atoi(optarg);
			break;

		default:
			usage(*argv);
			return 1;
		}
	}

	qdb_init();
	ndc_pre_init(&config);

	optind = 1;

	while ((c = getopt(argc, argv, "?dK:k:C:rp:s:")) != -1) {
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

	ndc_init();
	return ndc_main();
}
