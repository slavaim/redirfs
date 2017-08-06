/*
 *          Copyright Frantisek Hrbata 2008 - 2010.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <avfltctl.h>

#define CMD_SHOW		0x0001
#define CMD_INCLUDE		0x0002
#define CMD_EXCLUDE		0x0004
#define CMD_REMOVE		0x0008
#define CMD_CLEAN		0x0010
#define CMD_ACTIVATE		0x0020
#define CMD_DEACTIVATE		0x0040
#define CMD_UNREGISTER		0x0080
#define CMD_TIMEOUT		0x0100
#define CMD_CACHE_INVALIDATE	0x0200
#define CMD_CACHE_ENABLE	0x0400
#define CMD_CACHE_DISABLE	0x0800
#define CMD_HELP		0x1000
#define CMD_VERSION		0x2000

static const char *version = "0.2";

static const char *help_rfs =
"-s, --show                      show all available information\n"
"-i, --include <path>            add new included path\n"
"-e, --exclude <path>            add new excluded path\n"
"-r, --remove <id>               remove path specified by <id>\n"
"-c, --clean                     remove all paths\n"
"-a, --activate                  activate\n"
"-d, --deactivate                deactivate\n"
"-u, --unregister                unregister\n"
"-h, --help                      print help\n"
"-v, --version                   print version\n";

static const char *help_avflt =
"-n[id], --cache-invalidate=[id] invalidate cache for path specified by [id]\n"
"                                without [id] invalidate global cache\n"
"-o[id], --cache-enable=[id]     enable cache for path specified by [id]\n"
"                                without [id] enable global cache\n"
"-f[id], --cache-disable=[id]    disable cache for path specifed by [id]\n"
"                                without [id] disable global cache\n"
"-t, --timeout                   set request timeout in millisecond";

static const char *usage =
"avfltctl [-a | -d | -c | -u | -s | -h | -v]\n"
"         [-i | -e] <path>\n"
"         [-n | -o | -f] [id]\n"
"         -r <id>";

static const char *sopts = "si:e:r:cadut:n::o::f::hv";

static struct option lopts[] = {
	{"show", 0, 0, 's'},
	{"include", 1, 0, 'i'},
	{"exclude", 1, 0, 'e'},
	{"remove", 1, 0, 'r'},
	{"clean", 0, 0, 'c'},
	{"activate", 0, 0, 'a'},
	{"deactivate", 0, 0, 'd'},
	{"unregister", 0, 0, 'u'},
	{"timeout", 1, 0, 't'},
	{"cache-invalidate", 2, 0, 'n'},
	{"cache-enable", 2, 0, 'o'},
	{"cache-disable", 2, 0, 'f'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{0, 0, 0, 0}
};

static char *path = NULL;
static int cmd = 0;
static int id = -1;
static int timeout = 0;

static void parse_cmdl(int argc, char *argv[])
{
	int c;

	while ((c = getopt_long(argc, argv, sopts, lopts, NULL)) != -1) {
		switch (c) {
			case 's':
				cmd = CMD_SHOW;
				break;

			case 'i':
				cmd = CMD_INCLUDE;
				path = optarg;
				break;

			case 'e':
				cmd = CMD_EXCLUDE;
				path = optarg;
				break;

			case 'r':
				cmd = CMD_REMOVE;
				id = atoi(optarg);
				break;
				
			case 'c':
				cmd = CMD_CLEAN;
				break;

			case 'a':
				cmd = CMD_ACTIVATE;
				break;

			case 'd':
				cmd = CMD_DEACTIVATE;
				break;

			case 'u':
				cmd = CMD_UNREGISTER;
				break;

			case 't':
				timeout = atoi(optarg);
				cmd = CMD_TIMEOUT;
				break;

			case 'n':
				if (optarg)
					id = atoi(optarg);
				cmd = CMD_CACHE_INVALIDATE;
				break;

			case 'o':
				if (optarg)
					id = atoi(optarg);
				cmd = CMD_CACHE_ENABLE;
				break;

			case 'f':
				if (optarg)
					id = atoi(optarg);
				cmd = CMD_CACHE_DISABLE;
				break;
				
			case 'h':
				cmd = CMD_HELP;
				break;

			case 'v':
				cmd = CMD_VERSION;
				break;

			default:
				cmd = 0;
				return;
		}
	}

	if (optind < argc)
		cmd = 0;
}

static int check_cmdl(void)
{
	int rv;
	switch (cmd) {
		case CMD_HELP:
		case CMD_VERSION:
		case CMD_SHOW:
		case CMD_CLEAN:
		case CMD_ACTIVATE:
		case CMD_DEACTIVATE:
		case CMD_UNREGISTER:
		case CMD_INCLUDE:
		case CMD_EXCLUDE:
		case CMD_REMOVE:
		case CMD_TIMEOUT:
		case CMD_CACHE_INVALIDATE:
		case CMD_CACHE_ENABLE:
		case CMD_CACHE_DISABLE:
			rv = 0;
			break;

		default:
			rv = -1;
	}

	return rv;
}

static int cmd_show(void)
{
	struct avfltctl_filter *flt;
	char *type;
	int i;

	flt = avfltctl_get_filter();
	if (!flt)
		return -1;

	printf("priority   : %d\n", flt->priority);
	printf("status     : %s\n", flt->active ? "active" : "inactive");
	printf("cache      : %s\n", flt->cache ? "active" : "inactive");
	printf("timeout    : %d\n", flt->timeout);

	printf("registered :");
	for (i = 0; flt->registered[i] != -1; i++) {
		printf(" %d", flt->registered[i]);
	}
	printf("\n");

	printf("trusted    :");
	for (i = 0; flt->trusted[i] != -1; i++) {
		printf(" %d", flt->trusted[i]);
	}
	printf("\n");

	printf("paths      :\n");

	for (i = 0; flt->paths[i]; i++) {
		printf("             path : %s\n", flt->paths[i]->name);
		printf("             id   : %d\n", flt->paths[i]->id);
		if (flt->paths[i]->type == AVFLTCTL_PATH_INCLUDE)
		       	type = "include";
		else
			type = "exclude";

		printf("             type : %s\n", type);
		type = flt->paths[i]->cache ? "active" : "inactive";
		printf("             cache: %s\n\n", type);
	}

	avfltctl_put_filter(flt);

	return 0;
}

static void print_usage(void)
{
	printf("%s\n", usage);
}

static void cmd_help(void)
{
	print_usage();
	printf("\n%s", help_rfs);
	printf("%s\n", help_avflt);
}

static void cmd_version(void)
{
	printf("%s\n", version);
}

static int cmd_clean(void)
{
	return avfltctl_del_paths();
}

static int cmd_activate(void)
{
	return avfltctl_activate();
}

static int cmd_deactivate(void)
{
	return avfltctl_deactivate();
}

static int cmd_unregister(void)
{
	return avfltctl_unregister();
}

static int cmd_include(void)
{
	return avfltctl_add_path(path, AVFLTCTL_PATH_INCLUDE);
}

static int cmd_exclude(void)
{
	return avfltctl_add_path(path, AVFLTCTL_PATH_EXCLUDE);
}

static int cmd_remove(void)
{
	return avfltctl_rem_path(id);
}
	
static int cmd_timeout(int timeout)
{
	return avfltctl_set_timeout(timeout);
}

static int cmd_cache_invalidate(int id)
{
	if (id == -1)
		return avfltctl_invalidate_cache();

	return avfltctl_invalidate_path_cache(id);
}

static int cmd_cache_enable(int id)
{
	if (id == -1)
		return avfltctl_enable_cache();

	return avfltctl_enable_path_cache(id);
}

static int cmd_cache_disable(int id)
{
	if (id == -1)
		return avfltctl_disable_cache();

	return avfltctl_disable_path_cache(id);
}

static int process_cmdl(void)
{
	int rv = 0;

	switch (cmd) {
		case CMD_SHOW:
			rv = cmd_show();
			break;

		case CMD_HELP:
			cmd_help();
			break;

		case CMD_VERSION:
			cmd_version();
			break;

		case CMD_CLEAN:
			rv = cmd_clean();
			break;

		case CMD_ACTIVATE:
			rv = cmd_activate();
			break;

		case CMD_DEACTIVATE:
			rv = cmd_deactivate();
			break;

		case CMD_UNREGISTER:
			rv = cmd_unregister();
			break;

		case CMD_INCLUDE:
			rv = cmd_include();
			break;

		case CMD_EXCLUDE:
			rv = cmd_exclude();
			break;

		case CMD_REMOVE:
			rv = cmd_remove();
			break;

		case CMD_TIMEOUT:
			rv = cmd_timeout(timeout);
			break;

		case CMD_CACHE_INVALIDATE:
			rv = cmd_cache_invalidate(id);
			break;

		case CMD_CACHE_ENABLE:
			rv = cmd_cache_enable(id);
			break;

		case CMD_CACHE_DISABLE:
			rv = cmd_cache_disable(id);
			break;

		default:
			rv = -1;
	}

	return rv;
}

int main(int argc, char *argv[])
{

	parse_cmdl(argc, argv);

	if (check_cmdl()) {
		print_usage();
		return 1;
	}

	if (process_cmdl()) {
		perror("error");
		return 1;
	}

	return 0;
}

