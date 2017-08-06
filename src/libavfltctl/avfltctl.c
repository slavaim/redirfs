/*
 *          Copyright Frantisek Hrbata 2008 - 2010.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/user.h>
#include <unistd.h>
#include "avfltctl.h"

struct avfltctl_path_cache {
	int id;
	int cache;
};

static struct avfltctl_path_cache *avfltctl_get_path_cache(const char *buf)
{
	struct avfltctl_path_cache *cache;
	int id;
	char state;

	cache = malloc(sizeof(struct avfltctl_path_cache));
	if (!cache)
		return NULL;

	if (sscanf(buf, "%d:%c", &id, &state) != 2) {
		free(cache);
		return NULL;
	}

	cache->id = id;

	if (state == 'a')
		cache->cache = 1;
	else
		cache->cache = 0;

	return cache;
}

static void avfltctl_put_path_cache(struct avfltctl_path_cache *cache)
{
	if (!cache)
		return;

	free(cache);
}

static void avfltctl_put_path_caches(struct avfltctl_path_cache **caches)
{
	int i;

	if (!caches)
		return;

	for (i = 0; caches[i]; i++)
		avfltctl_put_path_cache(caches[i]);

	free(caches);
}

static struct avfltctl_path_cache **avfltctl_get_path_caches(void)
{
	struct avfltctl_path_cache **caches;
	struct avfltctl_path_cache **caches_new;
	struct avfltctl_path_cache *cache;
	char *buf;
	int off = 0;
	int i = 0;
	int rb;
	long page_size;

	page_size = sysconf(_SC_PAGESIZE);
	buf = malloc(sizeof(char) * page_size);
	if (!buf)
		return NULL;

	rb = rfsctl_read_data("avflt", "cache_paths", buf, page_size);
	if (rb == -1) {
		free(buf);
		return NULL;
	}

	caches = malloc(sizeof(struct avfltctl_path_cache *));
	if (!caches) {
		free(buf);
		return NULL;
	}

	caches[0] = NULL;

	if (rb == 0) {
		free(buf);
		return caches;
	}

	while (off < rb) {
		cache = avfltctl_get_path_cache(buf + off);
		if (!cache) {
			free(buf);
			avfltctl_put_path_caches(caches);
			return NULL;
		}

		caches_new = realloc(caches,
				sizeof(struct avfltctl_path_cache *) * (i + 2));

		if (!caches_new) {
			free(buf);
			avfltctl_put_path_cache(cache);
			avfltctl_put_path_caches(caches);
			return NULL;
		}

		caches = caches_new;
		caches[i++] = cache;
		caches[i] = NULL;

		off += strlen(buf + off) + 1;
	}

	free(buf);

	return caches;
}

static struct avfltctl_path *avfltctl_get_path(struct rfsctl_path *rpath)
{
	struct avfltctl_path *path;
	size_t fn_size;
	char *fn;

	fn_size = strlen(rpath->name) + 1;
	fn = malloc(sizeof(char) * fn_size);
	if (!fn)
		return NULL;

	path = malloc(sizeof(struct avfltctl_path));
	if (!path) {
		free(fn);
		return NULL;
	}

	strncpy(fn, rpath->name, fn_size);
	path->type = rpath->type;
	path->id = rpath->id;
	path->name = fn;

	return path;
}

static void avfltctl_put_path(struct avfltctl_path *path)
{
	if (!path)
		return;

	free(path->name);
	free(path);
}


static struct avfltctl_filter *avfltctl_alloc_filter(struct rfsctl_filter *rflt)
{
	struct avfltctl_filter *flt;
	size_t fn_size;
	char *fn;

	fn_size = strlen(rflt->name) + 1;
	fn = malloc(fn_size);
	if (!fn)
		return NULL;

	strncpy(fn, rflt->name, fn_size);
	flt = malloc(sizeof(struct avfltctl_filter));
	if (!flt) {
		free(fn);
		rfsctl_put_filter(rflt);
		return NULL;
	}

	flt->paths = NULL;
	flt->registered = NULL;
	flt->trusted = NULL;
	flt->name = fn;
	flt->priority = rflt->priority;
	flt->active = rflt->active;

	return flt;
}

static void avfltctl_free_filter(struct avfltctl_filter *flt)
{
	int i;

	if (flt->paths) {
		for (i = 0; flt->paths[i]; i++) {
			avfltctl_put_path(flt->paths[i]);
		}
	}

	free(flt->paths);
	free(flt->registered);
	free(flt->trusted);
	free(flt->name);
	free(flt);
}

static int avfltctl_set_path_cache(struct avfltctl_path *path,
		struct avfltctl_path_cache **caches)
{
	int i;

	for (i = 0; caches[i]; i++) {
		if (caches[i]->id == path->id) {
			path->cache = caches[i]->cache;
			return 0;
		}
	}

	return -1;
}

static int avfltctl_set_filter_paths(struct avfltctl_filter *flt,
		struct rfsctl_path **rpaths)
{
	struct avfltctl_path_cache **caches;
	struct avfltctl_path **paths;
	struct avfltctl_path *path;
	int i = 0;
	int j = 0;

	caches = avfltctl_get_path_caches();
	if (!caches)
		return -1;

	while (rpaths[i])
		i++;

	flt->paths = malloc(sizeof(struct avfltctl_path *) * (i + 1));
	if (!flt->paths) {
		avfltctl_put_path_caches(caches);
		return -1; 
	}

	flt->paths[0] = NULL;

	for (i = 0; rpaths[i]; i++) {
		path = avfltctl_get_path(rpaths[i]);
		if (!path) {
			avfltctl_put_path_caches(caches);
			return -1;
		}

		if (avfltctl_set_path_cache(path, caches)) {
			avfltctl_put_path(path);
			continue;
		}

		paths = realloc(flt->paths,
				sizeof(struct avfltctl_path *) * (j + 2));

		if (!paths) {
			avfltctl_put_path_caches(caches);
			avfltctl_put_path(path);
			return -1;
		}

		flt->paths = paths;
		flt->paths[j++] = path;
		flt->paths[j] = NULL;
	}

	avfltctl_put_path_caches(caches);
	return 0;
}

static int avfltctl_set_filter_timeout(struct avfltctl_filter *flt)
{
	char buf[256];
	int rv;

	rv = rfsctl_read_data(flt->name, "timeout", buf, 256);
	if (rv == -1)
		return rv;

	if (sscanf(buf, "%d", &flt->timeout) != 1)
		return -1;

	return 0;
}

static int avfltctl_set_filter_cache(struct avfltctl_filter *flt)
{
	char buf[256];
	char cache;
	int rv;

	rv = rfsctl_read_data(flt->name, "cache", buf, 256);
	if (rv == -1)
		return rv;

	if (sscanf(buf, "%c", &cache) != 1)
		return -1;

	if (cache == 'a')
		flt->cache = 1;
	else
		flt->cache = 0;

	return 0;
}

static pid_t *avfltctl_get_pids(const char *file)
{
	char *buf;
	long page_size;
	int rb;
	int off = 0;
	int i = 0;
	pid_t *pids;
	pid_t *pids_new;

	page_size = sysconf(_SC_PAGESIZE);
	buf = malloc(sizeof(char) * page_size);
	if (!buf)
		return NULL;

	rb = rfsctl_read_data("avflt", file, buf, page_size);
	if (rb == -1)
		goto err_buf;

	pids = malloc(sizeof(pid_t));
	if (!pids) 
		goto err_buf;

	pids[0] = (pid_t)-1;

	while (off < rb) {
		pids_new = realloc(pids, sizeof(pid_t) * (i + 2));
		if (!pids_new)
			goto err_pids;

		pids = pids_new;

		if (sscanf(buf + off, "%d", &pids[i++]) != 1)
			goto err_pids;

		pids[i] = (pid_t)-1;

		off += strlen(buf + off) + 1;
	}

	free(buf);
	return pids;

err_pids:
	free(pids);
err_buf:
	free(buf);
	return NULL;
}

static int avfltctl_set_filter_registered(struct avfltctl_filter *flt)
{
	flt->registered = avfltctl_get_pids("registered");
	if (!flt->registered)
		return -1;

	return 0;
}

static int avfltctl_set_filter_trusted(struct avfltctl_filter *flt)
{
	flt->trusted = avfltctl_get_pids("trusted");
	if (!flt->trusted)
		return -1;

	return 0;
}

struct avfltctl_filter *avfltctl_get_filter(void)
{
	struct avfltctl_filter *flt = NULL;
	struct rfsctl_filter *rflt = NULL;
	int rv;

	rflt = rfsctl_get_filter("avflt");
	if (!rflt)
		return NULL;

	flt = avfltctl_alloc_filter(rflt);
	if (!flt)
		goto error;

	rv = avfltctl_set_filter_paths(flt, rflt->paths);
	if (rv)
		goto error;

	rv = avfltctl_set_filter_timeout(flt);
	if (rv)
		goto error;

	rv = avfltctl_set_filter_cache(flt);
	if (rv)
		goto error;

	rv = avfltctl_set_filter_registered(flt);
	if (rv)
		goto error;

	rv = avfltctl_set_filter_trusted(flt);
	if (rv)
		goto error;

	rfsctl_put_filter(rflt);
	return flt;
error:
	rfsctl_put_filter(rflt);
	avfltctl_put_filter(flt);
	return NULL;
}

void avfltctl_put_filter(struct avfltctl_filter *filter)
{
	if (!filter)
		return;

	avfltctl_free_filter(filter);
}

int avfltctl_add_path(const char *path, int type)
{
	return  rfsctl_add_path("avflt", path, type);
}

int avfltctl_rem_path(int id)
{
	return rfsctl_rem_path("avflt", id);
}

int avfltctl_del_paths(void)
{
	return rfsctl_del_paths("avflt");
}

int avfltctl_unregister(void)
{
	return rfsctl_unregister("avflt");
}

int avfltctl_activate(void)
{
	return rfsctl_activate("avflt");
}

int avfltctl_deactivate(void)
{
	return rfsctl_deactivate("avflt");
}

int avfltctl_invalidate_cache(void)
{
	if (rfsctl_write_data("avflt", "cache", "i", 2) == -1)
		return -1;

	return 0;
}

int avfltctl_enable_cache(void)
{
	if (rfsctl_write_data("avflt", "cache", "a", 2) == -1)
		return -1;

	return 0;
}

int avfltctl_disable_cache(void)
{
	if (rfsctl_write_data("avflt", "cache", "d", 2) == -1)
		return -1;

	return 0;
}

int avfltctl_invalidate_path_cache(int id)
{
	char buf[256];
	int size;

	size = snprintf(buf, 256, "i:%d", id);
	if (size < 0) {
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data("avflt", "cache_paths", buf, size + 1) == -1)
		return -1;

	return 0;

}

int avfltctl_enable_path_cache(int id)
{
	char buf[256];
	int size;

	size = snprintf(buf, 256, "a:%d", id);
	if (size < 0) {
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data("avflt", "cache_paths", buf, size + 1) == -1)
		return -1;

	return 0;
}

int avfltctl_disable_path_cache(int id)
{
	char buf[256];
	int size;

	size = snprintf(buf, 256, "d:%d", id);
	if (size < 0) {
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data("avflt", "cache_paths", buf, size + 1) == -1)
		return -1;

	return 0;
}

int avfltctl_set_timeout(int timeout)
{
	char buf[256];
	int size;

	size = snprintf(buf, 256, "%d", timeout);
	if (size < 0) {
		errno = EINVAL;
		return -1;
	}

	if (rfsctl_write_data("avflt", "timeout", buf, size + 1) == -1)
		return -1;

	return 0;
}

