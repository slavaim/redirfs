/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * Copyright 2008 - 2010 Frantisek Hrbata
 * All rights reserved.
 *
 * This file is part of RedirFS.
 *
 * RedirFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RedirFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with RedirFS. If not, see <http://www.gnu.org/licenses/>.
 */

#include "rfs.h"

struct rfs_dcache_data *rfs_dcache_data_alloc(struct dentry *dentry,
		struct rfs_info *rinfo, struct rfs_flt *rflt)
{
	struct rfs_dcache_data *rdata;

	rdata = kzalloc(sizeof(struct rfs_dcache_data), GFP_KERNEL);
	if (!rdata)
		return ERR_PTR(-ENOMEM);

	rdata->rinfo = rinfo;
	rdata->rflt = rflt;
	rdata->droot = dentry;

	return rdata;
}

void rfs_dcache_data_free(struct rfs_dcache_data *rdata)
{
	if (!rdata || IS_ERR(rdata))
		return;

	kfree(rdata);
}

static struct rfs_dcache_entry *rfs_dcache_entry_alloc_locked(
		struct dentry *dentry, struct list_head *list)
{
	struct rfs_dcache_entry *entry;

	entry = kzalloc(sizeof(struct rfs_dcache_entry), GFP_ATOMIC);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&entry->list);
	entry->dentry = rfs_dget_locked(dentry);
	list_add_tail(&entry->list, list);

	return entry;
}

static struct rfs_dcache_entry *rfs_dcache_entry_alloc(struct dentry *dentry,
		struct list_head *list)
{
	struct rfs_dcache_entry *entry;

	entry = kzalloc(sizeof(struct rfs_dcache_entry), GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&entry->list);
	entry->dentry = dget(dentry);
	list_add_tail(&entry->list, list);

	return entry;
}

static void rfs_dcache_entry_free(struct rfs_dcache_entry *entry)
{
	if (!entry)
		return;

	list_del_init(&entry->list);
	dput(entry->dentry);
	kfree(entry);
}

static int rfs_dcache_get_subs_atomic(struct dentry *dir,
		struct list_head *sibs)
{
	struct rfs_dcache_entry *sib;
	struct dentry *dentry;
	int rv = 0;

	rfs_dcache_lock(dir);

	rfs_for_each_d_child(dentry, &dir->d_subdirs) {

		sib = rfs_dcache_entry_alloc_locked(dentry, sibs);
		if (IS_ERR(sib)) {
			rv = PTR_ERR(sib);
			break;
		}
	}

	rfs_dcache_unlock(dir);

	return rv;
}

static int rfs_dcache_get_subs_kernel(struct dentry *dir,
		struct list_head *sibs)
{
	LIST_HEAD(pool);
	int pool_size = 32;
	int pool_small;
	struct rfs_dcache_entry *sib;
	struct dentry *dentry;
	int i;

again:
	pool_small = 0;

	for (i = 0; i < pool_size; i++) {
		sib = rfs_dcache_entry_alloc(NULL, &pool);
		if (IS_ERR(sib)) {
			rfs_dcache_entry_free_list(&pool);
			return PTR_ERR(sib);
		}
	}

	rfs_dcache_lock(dir);

	rfs_for_each_d_child(dentry, &dir->d_subdirs) {
		if (list_empty(&pool)) {
			pool_small = 1;
			break;
		}
		
		sib = list_entry(pool.next, struct rfs_dcache_entry, list);
		sib->dentry = rfs_dget_locked(dentry);
		list_move(&sib->list, sibs);
	}

	rfs_dcache_unlock(dir);

	rfs_dcache_entry_free_list(&pool);

	if (pool_small) {
		rfs_dcache_entry_free_list(sibs);
		pool_size *= 2;
		goto again;
	}

	return 0;
}

int rfs_dcache_get_subs(struct dentry *dir, struct list_head *sibs)
{
	int rv;

	rv = rfs_dcache_get_subs_atomic(dir, sibs);
	if (!rv)
		return rv;

	rfs_dcache_entry_free_list(sibs);
	
	rv = rfs_dcache_get_subs_kernel(dir, sibs);

	return rv;
}

void rfs_dcache_entry_free_list(struct list_head *head)
{
	struct rfs_dcache_entry *entry;
	struct rfs_dcache_entry *tmp;

	list_for_each_entry_safe(entry, tmp, head, list) {
		rfs_dcache_entry_free(entry);
	}
}

static int rfs_dcache_get_subs_mutex(struct dentry *dir, struct list_head *sibs)
{
	int rv = 0;

	if (!dir || !dir->d_inode)
		return 0;

	rfs_inode_mutex_lock(dir->d_inode);
	rv = rfs_dcache_get_subs(dir, sibs);
	rfs_inode_mutex_unlock(dir->d_inode);

	return rv;
}

static int rfs_dcache_get_dirs(struct list_head *dirs, struct list_head *sibs)
{
	struct rfs_dcache_entry *entry;
	struct rfs_dcache_entry *dir;
	struct rfs_dcache_entry *tmp;

	list_for_each_entry_safe(entry, tmp, sibs, list) {
		if (!entry->dentry->d_inode)
			continue;

		if (!S_ISDIR(entry->dentry->d_inode->i_mode))
			continue;

		dir = rfs_dcache_entry_alloc(entry->dentry, dirs);
		if (IS_ERR(dir))
			return PTR_ERR(dir);

		rfs_dcache_entry_free(entry);
	}

	return 0;
}

int rfs_dcache_walk(struct dentry *root, int (*cb)(struct dentry *, void *),
		void *data)
{
	LIST_HEAD(dirs);
	LIST_HEAD(sibs);
	struct rfs_dcache_entry *dir;
	struct rfs_dcache_entry *sib;
	int rv = 0;

	dir = rfs_dcache_entry_alloc(root, &dirs);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	while (!list_empty(&dirs)) {
		dir = list_entry(dirs.next, struct rfs_dcache_entry, list);

		rv = cb(dir->dentry, data);
		if (rv < 0)
			goto exit;

		if (rv > 0 || !dir->dentry->d_inode) {
			rfs_dcache_entry_free(dir);
			rv = 0;
			continue;
		}

		rv = rfs_dcache_get_subs_mutex(dir->dentry, &sibs);
		if (rv)
			goto exit;

		rv = rfs_dcache_get_dirs(&dirs, &sibs);
		if (rv)
			goto exit;

		list_for_each_entry(sib, &sibs, list) {
			rv = cb(sib->dentry, data);
			if (rv < 0)
				goto exit;
		}
		rfs_dcache_entry_free_list(&sibs);
		rfs_dcache_entry_free(dir);
	}
exit:
	list_splice(&sibs, &dirs);
	rfs_dcache_entry_free_list(&dirs);

	return rv;
}

static int rfs_dcache_skip(struct dentry *dentry, struct rfs_dcache_data *rdata)
{
	struct rfs_dentry *rdentry = NULL;
	int rv = 0;

	if (dentry == rdata->droot)
		return 0;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return 0;

	if (!rdentry->rinfo)
		goto exit;

	if (!rdentry->rinfo->rroot)
		goto exit;

	if (rdentry->rinfo->rroot->dentry != dentry)
		goto exit;

	rv = 1;
exit:
	rfs_dentry_put(rdentry);
	return rv;
}

int rfs_dcache_rdentry_add(struct dentry *dentry, struct rfs_info *rinfo)
{
	struct rfs_dentry *rdentry = NULL;
	int rv = 0;

	rdentry = rfs_dentry_add(dentry, rinfo);
	if (IS_ERR(rdentry))
		return PTR_ERR(rdentry);

	rfs_dentry_set_rinfo(rdentry, rinfo);

	rv = rfs_dentry_add_rinode(rdentry, rinfo);
	if (rv)
		goto exit;

	rv = rfs_inode_set_rinfo(rdentry->rinode);
	if (rv)
		goto exit;

	rfs_dentry_set_ops(rdentry);
exit:
	rfs_dentry_put(rdentry);
	return rv;
}

int rfs_dcache_rinode_del(struct rfs_dentry *rdentry, struct inode *inode)
{
	struct rfs_inode *rinode = NULL;
	int rv = 0;

	rfs_dentry_rem_rinode(rdentry);

	rinode = rfs_inode_find(inode);
	if (!rinode)
		return 0;

	rv = rfs_inode_set_rinfo(rinode);
	if (rv) {
		rfs_inode_put(rinode);
		return rv;
	}

	rfs_inode_set_ops(rinode);
	rfs_inode_put(rinode);

	return 0;
}

static int rfs_dcache_rdentry_del(struct dentry *dentry, struct rfs_info *rinfo)
{
	struct rfs_dentry *rdentry = NULL;
	int rv = 0;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return 0;

	rfs_dentry_set_rinfo(rdentry, rinfo);
	rv = rfs_inode_set_rinfo(rdentry->rinode);
	if (rv)
		goto exit;

	rfs_dentry_set_ops(rdentry);
exit:
	rfs_dentry_put(rdentry);
	return rv;
}

int rfs_dcache_add_dir(struct dentry *dentry, void *data)
{
	if (!dentry->d_inode)
		return 0;

	if (!S_ISDIR(dentry->d_inode->i_mode))
		return 0;

	return rfs_dcache_rdentry_add(dentry, rfs_info_none);
}

int rfs_dcache_add(struct dentry *dentry, void *data)
{
	struct rfs_dcache_data *rdata = data;

	if (rfs_dcache_skip(dentry, rdata)) {
		rfs_root_add_walk(dentry);
		return 1;
	}

	return rfs_dcache_rdentry_add(dentry, rdata->rinfo);
}

int rfs_dcache_rem(struct dentry *dentry, void *data)
{
	struct rfs_dcache_data *rdata = data;
	int rv;

	if (rfs_dcache_skip(dentry, rdata)) {
		rfs_root_add_walk(dentry);
		return 1;
	}

	if (rdata->rinfo->rchain)
		return rfs_dcache_rdentry_add(dentry, rdata->rinfo);

	rv = rfs_dcache_rdentry_del(dentry, rfs_info_none);
	if (rv)
		return rv;

	rfs_dentry_rem_data(dentry, rdata->rflt);
	return 0;
}

int rfs_dcache_set(struct dentry *dentry, void *data)
{
	struct rfs_dcache_data *rdata = data;
	struct rfs_dentry *rdentry = NULL;
	struct rfs_root *rroot = NULL;
	int rv = 0;

	if (rfs_dcache_skip(dentry, rdata))
		return 1;

	if (!rdata->rinfo->rchain)
		return rfs_dcache_rdentry_del(dentry, rfs_info_none);

	rdentry = rfs_dentry_find(dentry);
	if (rdentry)
		rroot = rfs_root_get(rdentry->rinfo->rroot);

	rv = rfs_dcache_rdentry_add(dentry, rdata->rinfo);
	if (rv)
		goto exit;

	if (!rroot)
		goto exit;

	if (rroot == rdata->rinfo->rroot)
		goto exit;

	rv = rfs_dentry_move(dentry, rdata->rflt, rroot, rdata->rinfo->rroot);
exit:
	rfs_dentry_put(rdentry);
	rfs_root_put(rroot);
	return rv;
}

int rfs_dcache_reset(struct dentry *dentry, void *data)
{
	struct rfs_dcache_data *rdata = data;

	if (rfs_dcache_skip(dentry, rdata))
		return 1;

	if (!rdata->rinfo->rchain)
		return rfs_dcache_rdentry_del(dentry, rfs_info_none);

	return rfs_dcache_rdentry_add(dentry, rdata->rinfo);
}

