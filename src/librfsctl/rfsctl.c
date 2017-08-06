/*
 *          Copyright Frantisek Hrbata 2008 - 2010.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "rfsctl.h"

static const char *rfsctl_dir = "/sys/fs/redirfs/filters";

static struct rfsctl_path *rfsctl_get_path(const char *buf)
{
	struct rfsctl_path *path = NULL;
	char *name = NULL;
	char type;
	int id;

	path = malloc(sizeof(struct rfsctl_path));
	if (!path)
		return NULL;

	name = malloc(sizeof(char) * strlen(buf));
	if (!name) {
		free(path);
		return NULL;
	}

	if (sscanf(buf, "%c:%d:%s", &type, &id, name) != 3) {
		free(path);
		free(name);
		return NULL;
	}

	if (type == 'i')
		path->type = RFSCTL_PATH_INCLUDE;
	else
		path->type = RFSCTL_PATH_EXCLUDE;

	path->id = id;
	path->name = name;

	return path;
}

static void rfsctl_put_path(struct rfsctl_path *path)
{
	if (!path)
		return;

	free(path->name);
	free(path);
}

static struct rfsctl_filter *rfsctl_alloc_filter(const char *name)
{
	struct rfsctl_filter *flt;
	int size;

	size = strlen(name) + 1;

	flt = malloc(sizeof(struct rfsctl_filter));
	if (!flt)
		return NULL;

	flt->name = malloc(sizeof(char) * size);
	if (!flt->name) {
		free(flt);
		return NULL;
	}

	strncpy(flt->name, name, size);
	flt->paths = NULL;

	return flt;
}

static void rfsctl_free_filter(struct rfsctl_filter *flt)
{
	int i = 0;

	if (flt->paths) {
		while (flt->paths[i]) {
			rfsctl_put_path(flt->paths[i]);
			i++;
		}
	}

	free(flt->paths);
	free(flt->name);
	free(flt);
}

static char *rfsctl_alloc_filename(const char *fltname, const char *filename)
{
	char *fn;
	int size;

	size = strlen(rfsctl_dir) + strlen(fltname) + strlen(filename);
	size += 3; /* / + / + \0 */

	fn = malloc(sizeof(char) * size);
	if (!fn)
		return NULL;

	strncpy(fn, rfsctl_dir, strlen(rfsctl_dir) + 1);
	strncat(fn, "/", 1);
	strncat(fn, fltname, strlen(fltname));
	strncat(fn, "/", 1);
	strncat(fn, filename, strlen(filename));

	return fn;
}

static void rfsctl_free_filename(char *filename)
{
	free(filename);
}

int rfsctl_read_data(const char *fltname, const char *filename, char *buf,
		int size)
{
	char *fn;
	int fd;
	int rb;

	fn = rfsctl_alloc_filename(fltname, filename);
	if (!fn)
		return -1;

	fd = open(fn, O_RDONLY);
	if (fd == -1) {
		rfsctl_free_filename(fn);
		return -1;
	}
	
	memset(buf, 0, size);
	rb = read(fd, buf, size);

	rfsctl_free_filename(fn);
	close(fd);
	return rb;
}

int rfsctl_write_data(const char *fltname, const char *filename, char *buf,
		int size)
{
	struct stat sb;
	char *tmp;
	char *fn;
	int fd;
	int wb;
	int flags;
	int clean;
	long page_size;

	page_size = sysconf(_SC_PAGESIZE);
	fn = rfsctl_alloc_filename(fltname, filename);
	if (!fn)
		return -1;

	if (stat(fn, &sb)) {
		rfsctl_free_filename(fn);
		return -1;
	}

	clean = sb.st_mode & S_IRUSR;

	if (clean)
		flags = O_RDWR;
	else
		flags = O_WRONLY;

	fd = open(fn, flags);
	if (fd == -1) {
		rfsctl_free_filename(fn);
		return -1;
	}

	if (clean) {
		tmp = malloc(sizeof(char) * page_size);
		if (!tmp) {
			rfsctl_free_filename(fn);
			close(fd);
			return -1;
		}

		if (read(fd, tmp, page_size) == -1) {
			rfsctl_free_filename(fn);
			close(fd);
			free(tmp);
			return -1;
		}

		free(tmp);
	}

	wb = write(fd, buf, size);

	rfsctl_free_filename(fn);
	close(fd);
	return wb;
}

static int rfsctl_set_filter_priority(struct rfsctl_filter *flt)
{
	char buf[256];
	int rv;

	rv = rfsctl_read_data(flt->name, "priority", buf, 256);
	if (rv == -1)
		return rv;

	if (sscanf(buf, "%d", &flt->priority) != 1)
		return -1;

	return 0;
}

static int rfsctl_set_filter_active(struct rfsctl_filter *flt)
{
	char buf[256];
	int rv;

	rv = rfsctl_read_data(flt->name, "active", buf, 256);
	if (rv == -1)
		return rv;

	if (sscanf(buf, "%d", &flt->active) != 1)
		return -1;

	return 0;
}

static int rfsctl_set_filter_paths(struct rfsctl_filter *flt)
{
	struct rfsctl_path *path;
	struct rfsctl_path **paths;
	int off = 0;
	int rv = -1;
	int i = 0;
	char *buf;
	int rb;
	long page_size;

	page_size = sysconf(_SC_PAGESIZE);
	buf = malloc(sizeof(char) * page_size);
	if (!buf)
		return -1;

	rb = rfsctl_read_data(flt->name, "paths", buf, page_size);
	if (rb == -1)
		goto exit;

	flt->paths = malloc(sizeof(struct rfsctl_path *));
	if (!flt->paths)
		goto exit;

	flt->paths[0] = NULL;

	if (rb == 0) {
		rv = 0;
		goto exit;
	}

	while (off < rb) {
		path = rfsctl_get_path(buf + off);
		if (!path)
			goto exit;

		paths = realloc(flt->paths,
				sizeof(struct rfsctl_path *) * (i + 2));
		if (!paths) {
			rfsctl_put_path(path);
			goto exit;;
		}

		flt->paths = paths;
		flt->paths[i++] = path;
		flt->paths[i] = NULL;
		
		off += strlen(buf + off) + 1;
	}

	rv = 0;
exit:
	free(buf);
	return rv;
}

struct rfsctl_filter *rfsctl_get_filter(const char *name)
{
	struct rfsctl_filter *flt;
	int rv = 0;

	if (!name) {
		errno = EINVAL;
		return NULL;
	}

	flt = rfsctl_alloc_filter(name);
	if (!flt)
		return NULL;

	rv = rfsctl_set_filter_priority(flt);
	if (rv)
		goto error;

	rv = rfsctl_set_filter_active(flt);
	if (rv)
		goto error;

	rv = rfsctl_set_filter_paths(flt);
	if (rv)
		goto error;

	return flt;
error:
	rfsctl_put_filter(flt);
	return NULL;
}

void rfsctl_put_filter(struct rfsctl_filter *filter)
{
	if (!filter)
		return;

	rfsctl_free_filter(filter);
}

struct rfsctl_filter **rfsctl_get_filters(void)
{
	struct rfsctl_filter **flts = NULL;
	struct rfsctl_filter *flt;
	struct dirent *dirent;
	DIR *dir;
	int i = 0;

	dir = opendir(rfsctl_dir);
	if (!dir) 
		return NULL;

	flts = malloc(sizeof(struct rfsctl_filter *));
	if (!flts) {
		closedir(dir);
		return NULL;
	}

	*flts = NULL;

	while ((dirent = readdir(dir))) {
		if (!strcmp(dirent->d_name, "."))
			continue;

		if (!strcmp(dirent->d_name, ".."))
			continue;

		flt = rfsctl_get_filter(dirent->d_name);
		if (!flt)
			continue;

		flts = realloc(flts, sizeof(struct rfsctl_filter *) * (i + 2));
		if (!flts) {
			closedir(dir);
			rfsctl_put_filter(flt);
			rfsctl_put_filters(flts);
			return NULL;
		}

		flts[i++] = flt;
		flts[i] = NULL;
	}

	return flts;
}

void rfsctl_put_filters(struct rfsctl_filter **filters)
{
	int i = 0;

	if (!filters)
		return;

	while (filters[i]) {
		rfsctl_put_filter(filters[i]);
		i++;
	}

	free(filters);
}

int rfsctl_add_path(const char *name, const char *path, int type)
{
	char *buf;
	int size;
	char t;
	long page_size;

	if (!name || !path) {
		errno = EINVAL;
		return -1;
	}

	if (type != RFSCTL_PATH_INCLUDE && type != RFSCTL_PATH_EXCLUDE) {
		errno = EINVAL;
		return -1;
	}

	if (type == RFSCTL_PATH_INCLUDE)
		t = 'i';
	else 
		t = 'e';

	page_size = sysconf(_SC_PAGESIZE);
	buf = malloc(sizeof(char) * page_size);
	if (!buf)
		return -1;

	size = snprintf(buf, page_size, "a:%c:%s", t, path);
	if (size < 0) {
		free(buf);
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data(name, "paths", buf, size + 1) == -1) {
		free(buf);
		return -1;
	}

	free(buf);
	return 0;
}

int rfsctl_rem_path(const char *name, int id)
{
	char buf[256];
	int size;

	if (!name) {
		errno = EINVAL;
		return -1;
	}

	size = snprintf(buf, 256, "r:%d", id);
	if (size < 0) {
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data(name, "paths", buf, size + 1) == -1)
		return -1;

	return 0;
}

int rfsctl_rem_path_name(const char *name, const char *path)
{
	char *buf;
	int size;
	long page_size;

	if (!name) {
		errno = EINVAL;
		return -1;
	}

	page_size = sysconf(_SC_PAGESIZE);
	buf = malloc(sizeof(char) * page_size);
	if (!buf)
		return -1;

	size = snprintf(buf, page_size, "R:%s", path);
	if (size < 0) {
		free(buf);
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data(name, "paths", buf, size + 1) == -1) {
		free(buf);
		return -1;
	}

	free(buf);
	return 0;
}

int rfsctl_del_paths(const char *name)
{
	if (!name) {
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data(name, "paths", "c", 2) == -1)
		return -1;

	return 0;
}

int rfsctl_unregister(const char *name)
{
	if (!name) {
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data(name, "unregister", "1", 2) == -1)
		return -1;

	return 0;
}

int rfsctl_activate(const char *name)
{
	if (!name) {
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data(name, "active", "1", 2) == -1)
		return -1;

	return 0;
}

int rfsctl_deactivate(const char *name)
{
	if (!name) {
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data(name, "active", "0", 2) == -1)
		return -1;

	return 0;
}

