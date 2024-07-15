#include "ndc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
ndc_update()
{
}

void
ndc_view(int fd, int argc, char *argv[])
{
}

void
ndc_vim(int fd, int argc, char *argv[])
{
}

void
ndc_connect(int fd) {
}

void
ndc_ws_init(int fd) {
}

void
ndc_disconnect(int fd) {
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
	fprintf(stderr, "        -d        daemon mode\n");
	fprintf(stderr, "        -r        root multiplex mode\n");
	fprintf(stderr, "        -?        display this message.\n");
}
int
main(int argc, char *argv[])
{
	struct ndc_config config = {
		.flags = 0,
		.auto_cmd = "sh",
	};
	register char c;

	while ((c = getopt(argc, argv, "?dvk:c:uC:srp:")) != -1) {
		switch (c) {
		case 'd':
			config.flags |= NDC_DETACH;
			break;

		case 'k':
			config.flags |= NDC_SSL;
			config.ssl_key = strdup(optarg);
			break;
			
		case 'c':
			config.flags |= NDC_SSL;
			config.ssl_crt = strdup(optarg);
			break;
			
		case 'C':
			config.chroot = strdup(optarg);
			break;

		case 's':
			config.serve = strdup(optarg);
			break;

		case 'r':
			config.flags |= NDC_ROOT;
			break;

		case 'p':
			config.port = atoi(optarg);
			break;
			
		default:
			usage(*argv);
			return 1;
		}
	}

	return ndc_main(&config);
}
