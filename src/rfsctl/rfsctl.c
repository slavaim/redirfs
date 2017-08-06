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
#include <rfsctl.h>

#define CMD_LIST	0x001
#define CMD_SHOW	0x002
#define CMD_INCLUDE	0x004
#define CMD_EXCLUDE	0x008
#define CMD_REMOVE	0x010
#define CMD_REMOVE_NAME	0x020
#define CMD_CLEAN	0x040
#define CMD_ACTIVATE	0x080
#define CMD_DEACTIVATE	0x100
#define CMD_UNREGISTER	0x200
#define CMD_HELP	0x400
#define CMD_VERSION	0x800

static const char *version = "0.1";

static const char *help1 =
"-l, --list			list all registered filters\n"
"-s, --show			show all available filter information\n"
"-f, --filter <name>		specify filter by <name>\n"
"-i, --include <path>		add new included path for filter\n"
"-e, --exclude <path>		add new excluded path for filter\n"
"-r, --remove <id>		remove filter path specified by <id>\n"
"-R, --remove-path <path>	remove filter path specified by <path>\n"
"-c, --clean			remove all filter paths\n"
"-a, --activate			activate filter\n";
static const char *help2 =
"-d, --deactivate		deactivate filter\n"
"-u, --unregister		unregister filter\n"
"-h, --help			print help\n"
"-v, --version			print version";

static const char *usage =
"rfsctl -f <name> [-a | -d | -c | -u | -s]\n"
"       -f <name> [-i | -e] <path>\n"
"       -f <name> -r <id>\n"
"       -f <name> -R <path>\n"
"       [-l | -h | -v]";

static const char *sopts = "lsf:i:e:r:R:caduhv";

static struct option lopts[] = {
	{"list", 0, 0, 'l'},
	{"show", 0, 0, 's'},
	{"filter", 1, 0, 'f'},
	{"include", 1, 0, 'i'},
	{"exclude", 1, 0, 'e'},
	{"remove", 1, 0, 'r'},
	{"remove-path", 1, 0, 'R'},
	{"clean", 0, 0, 'c'},
	{"activate", 0, 0, 'a'},
	{"deactivate", 0, 0, 'd'},
	{"unregister", 0, 0, 'u'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{0, 0, 0, 0}
};

static char *fltname = NULL;
static char *path = NULL;
static int cmd = 0;
static int id = -1;

static void parse_cmdl(int argc, char *argv[])
{
	int c;

	while ((c = getopt_long(argc, argv, sopts, lopts, NULL)) != -1) {
		switch (c) {
			case 'l':
				cmd = CMD_LIST;
				break;

			case 's':
				cmd = CMD_SHOW;
				break;

			case 'f':
				fltname = optarg;
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

			case 'R':
				cmd = CMD_REMOVE_NAME;
				path = optarg;
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
	int rv = 0;

	switch (cmd) {
		case CMD_LIST:
		case CMD_HELP:
		case CMD_VERSION:
			break;

		case CMD_SHOW:
		case CMD_CLEAN:
		case CMD_ACTIVATE:
		case CMD_DEACTIVATE:
		case CMD_UNREGISTER:
		case CMD_INCLUDE:
		case CMD_EXCLUDE:
		case CMD_REMOVE:
		case CMD_REMOVE_NAME:
			if (!fltname)
				rv = -1;
			break;

		default:
			rv = -1;
	}

	return rv;
}

static int cmd_list(void)
{
	struct rfsctl_filter **flts;
	int i = 0;

	flts = rfsctl_get_filters();
	if (!flts)
		return -1;

	while (flts[i]) {
		printf("%s\n", flts[i]->name);
		i++;
	}

	rfsctl_put_filters(flts);

	return 0;
}

static int cmd_show(void)
{
	struct rfsctl_filter *flt;
	char *type;
	int i = 0;

	flt = rfsctl_get_filter(fltname);
	if (!flt)
		return -1;

	printf("priority: %d\n", flt->priority);
	printf("status  : %s\n", flt->active ? "active" : "inactive");
	printf("paths   :\n");

	while (flt->paths[i]) {
		printf("          path : %s\n", flt->paths[i]->name);
		printf("          id   : %d\n", flt->paths[i]->id);
		if (flt->paths[i]->type == RFSCTL_PATH_INCLUDE)
		       	type = "include";
		else
			type = "exclude";

		printf("          type : %s\n\n", type);
		i++;
	}

	rfsctl_put_filter(flt);

	return 0;
}

static void print_usage(void)
{
	printf("%s\n", usage);
}

static void cmd_help(void)
{
	print_usage();
	printf("\n%s%s\n", help1, help2);
}

static void cmd_version(void)
{
	printf("%s\n", version);
}

static int cmd_clean(void)
{
	return rfsctl_del_paths(fltname);
}

static int cmd_activate(void)
{
	return rfsctl_activate(fltname);
}

static int cmd_deactivate(void)
{
	return rfsctl_deactivate(fltname);
}

static int cmd_unregister(void)
{
	return rfsctl_unregister(fltname);
}

static int cmd_include(void)
{
	return rfsctl_add_path(fltname, path, RFSCTL_PATH_INCLUDE);
}

static int cmd_exclude(void)
{
	return rfsctl_add_path(fltname, path, RFSCTL_PATH_EXCLUDE);
}

static int cmd_remove(void)
{
	return rfsctl_rem_path(fltname, id);
}

static int cmd_remove_name(void)
{
	return rfsctl_rem_path_name(fltname, path);
}

static int process_cmdl(void)
{
	int rv = 0;

	switch (cmd) {
		case CMD_LIST:
			rv = cmd_list();
			break;

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

		case CMD_REMOVE_NAME:
			rv = cmd_remove_name();
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

