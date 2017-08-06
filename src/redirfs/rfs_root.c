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

LIST_HEAD(rfs_root_list);
LIST_HEAD(rfs_root_walk_list);

static struct rfs_root *rfs_root_alloc(struct dentry *dentry)
{
	struct rfs_root *rroot;

	rroot = kzalloc(sizeof(struct rfs_root), GFP_KERNEL);
	if (!rroot)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rroot->list);
	INIT_LIST_HEAD(&rroot->walk_list);
	INIT_LIST_HEAD(&rroot->rpaths);
	INIT_LIST_HEAD(&rroot->data);
	rroot->dentry = dentry;
	rroot->paths_nr = 0;
	spin_lock_init(&rroot->lock);
	atomic_set(&rroot->count, 1);

	return rroot;
}

struct rfs_root *rfs_root_get(struct rfs_root *rroot)
{
	if (!rroot || IS_ERR(rroot))
		return NULL;

	BUG_ON(!atomic_read(&rroot->count));
	atomic_inc(&rroot->count);

	return rroot;
}

void rfs_root_put(struct rfs_root *rroot)
{
	if (!rroot || IS_ERR(rroot))
		return;

	BUG_ON(!atomic_read(&rroot->count));
	if (!atomic_dec_and_test(&rroot->count))
		return;

	rfs_chain_put(rroot->rinch);
	rfs_chain_put(rroot->rexch);
	rfs_data_remove(&rroot->data);
	kfree(rroot);
}

static struct rfs_root *rfs_root_find(struct dentry *dentry)
{
	struct rfs_root *rroot = NULL;
	struct rfs_root *found = NULL;

	list_for_each_entry(rroot, &rfs_root_list, list) {
		if (rroot->dentry != dentry)
			continue;

		found = rfs_root_get(rroot);
		break;
	}

	return found;
}

static void rfs_root_list_add(struct rfs_root *rroot)
{
	list_add_tail(&rroot->list, &rfs_root_list);
	rfs_root_get(rroot);
}

static void rfs_root_list_rem(struct rfs_root *rroot)
{
	list_del_init(&rroot->list);
	rfs_root_put(rroot);
}

void rfs_root_add_rpath(struct rfs_root *rroot, struct rfs_path *rpath)
{
	rroot->paths_nr++;
	list_add_tail(&rpath->rroot_list, &rroot->rpaths);
	rfs_path_get(rpath);
}

void rfs_root_rem_rpath(struct rfs_root *rroot, struct rfs_path *rpath)
{
	rroot->paths_nr--;
	list_del_init(&rpath->rroot_list);

	if (!list_empty(&rroot->rpaths)) {
		rfs_path_put(rpath);
		return;
	}

	rfs_path_put(rpath);
	rfs_root_list_rem(rroot);
}

struct rfs_root *rfs_root_add(struct dentry *dentry)
{
	struct rfs_root *rroot;

	rroot = rfs_root_find(dentry);
	if (rroot)
		return rroot;

	rroot = rfs_root_alloc(dentry);
	if (IS_ERR(rroot))
		return rroot;

	rfs_root_list_add(rroot);

	return rroot;
}

static int rfs_root_flt_num(struct rfs_root *rroot, struct rfs_flt *rflt,
		int type)
{
	struct rfs_chain *rchain;
	struct rfs_path *rpath;
	int num = 0;

	list_for_each_entry(rpath, &rroot->rpaths, rroot_list) {
		if (type & REDIRFS_PATH_INCLUDE)
			rchain = rpath->rinch;
		else
			rchain = rpath->rexch;

		if (rfs_chain_find(rchain, rflt) != -1)
			num++;
	}

	return num;
}

int rfs_root_add_include(struct rfs_root *rroot, struct rfs_flt *rflt)
{
	struct rfs_chain *rinch;
	int rv;

	if (rfs_chain_find(rroot->rinch, rflt) != -1)
		return 0;

	if (rfs_chain_find(rroot->rexch, rflt) != -1)
		return -EEXIST;

	rinch = rfs_chain_add(rroot->rinch, rflt);
	if (IS_ERR(rinch))
		return PTR_ERR(rinch);

	rv = rfs_info_add_include(rroot, rflt);
	if (rv) {
		rfs_chain_put(rinch);
		return rv;
	}

	spin_lock(&rroot->lock);
	rfs_chain_put(rroot->rinch);
	rroot->rinch = rinch;
	spin_unlock(&rroot->lock);
	return 0;
}

int rfs_root_add_exclude(struct rfs_root *rroot, struct rfs_flt *rflt)
{
	struct rfs_chain *rexch ;
	int rv;

	if (rfs_chain_find(rroot->rexch, rflt) != -1)
		return 0;

	if (rfs_chain_find(rroot->rinch, rflt) != -1)
		return -EEXIST;

	rexch = rfs_chain_add(rroot->rexch, rflt);
	if (IS_ERR(rexch))
		return PTR_ERR(rexch);

	rv = rfs_info_add_exclude(rroot, rflt);
	if (rv) {
		rfs_chain_put(rexch);
		return rv;
	}

	spin_lock(&rroot->lock);
	rfs_chain_put(rroot->rexch);
	rroot->rexch = rexch;
	spin_unlock(&rroot->lock);
	return 0;
}

int rfs_root_rem_include(struct rfs_root *rroot, struct rfs_flt *rflt)
{
	struct rfs_chain *rinch;
	struct redirfs_data *data;
	int rv;

	if (rfs_root_flt_num(rroot, rflt, REDIRFS_PATH_INCLUDE) > 1)
		return 0;

	rinch = rfs_chain_rem(rroot->rinch, rflt);
	if (IS_ERR(rinch))
		return PTR_ERR(rinch);

	rv = rfs_info_rem_include(rroot, rflt);
	if (rv) {
		rfs_chain_put(rinch);
		return rv;
	}

	spin_lock(&rroot->lock);
	rfs_chain_put(rroot->rinch);
	rroot->rinch = rinch;
	spin_unlock(&rroot->lock);
	data = redirfs_detach_data_root(rflt, rroot);
	if (data && data->detach)
		data->detach(data);
	redirfs_put_data(data);
	return 0;
}

int rfs_root_rem_exclude(struct rfs_root *rroot, struct rfs_flt *rflt)
{
	struct rfs_chain *rexch;
	struct redirfs_data *data;
	int rv;

	if (rfs_root_flt_num(rroot, rflt, REDIRFS_PATH_EXCLUDE) > 1)
		return 0;

	rexch = rfs_chain_rem(rroot->rexch, rflt);
	if (IS_ERR(rexch))
		return PTR_ERR(rexch);

	rv = rfs_info_rem_exclude(rroot, rflt);
	if (rv) {
		rfs_chain_put(rexch);
		return rv;
	}

	spin_lock(&rroot->lock);
	rfs_chain_put(rroot->rexch);
	rroot->rexch = rexch;
	spin_unlock(&rroot->lock);
	data = redirfs_detach_data_root(rflt, rroot);
	if (data && data->detach)
		data->detach(data);
	redirfs_put_data(data);
	return 0;
}

int rfs_root_add_flt(struct rfs_root *rroot, void *data)
{
	struct rfs_chain *rchain = NULL;
	struct rfs_info *rinfo = NULL;
	struct rfs_dcache_data *rdata = NULL;
	struct rfs_flt *rflt = (struct rfs_flt *)data;
	int rv = 0;

	if (rfs_chain_find(rroot->rinch, rflt) != -1)
		return 0;

	if (rfs_chain_find(rroot->rexch, rflt) != -1)
		return 0;

	if (rfs_chain_find(rroot->rinfo->rchain, rflt) != -1)
		return 0;

	rchain = rfs_chain_add(rroot->rinfo->rchain, rflt);
	if (IS_ERR(rchain))
		return PTR_ERR(rchain);

	rinfo = rfs_info_alloc(rroot, rchain);
	if (IS_ERR(rinfo)) {
		rv = PTR_ERR(rinfo);
		goto exit;
	}

	rdata = rfs_dcache_data_alloc(rroot->dentry, rinfo, rflt);
	if (IS_ERR(rdata)) {
		rv = PTR_ERR(rdata);
		goto exit;
	}

	rv = rfs_dcache_walk(rroot->dentry, rfs_dcache_add, rdata);
	if (rv)
		goto exit;

	rfs_root_set_rinfo(rroot, rinfo);
exit:
	rfs_dcache_data_free(rdata);
	rfs_chain_put(rchain);
	rfs_info_put(rinfo);
	return rv;
}

int rfs_root_rem_flt(struct rfs_root *rroot, void *data)
{
	struct rfs_chain *rchain = NULL;
	struct rfs_info *rinfo = NULL;
	struct rfs_dcache_data *rdata = NULL;
	struct rfs_flt *rflt = (struct rfs_flt *)data;
	int rv = 0;

	if (rfs_chain_find(rroot->rinch, rflt) != -1)
		return 0;

	if (rfs_chain_find(rroot->rexch, rflt) != -1)
		return 0;

	if (rfs_chain_find(rroot->rinfo->rchain, rflt) == -1)
		return 0;

	rchain = rfs_chain_rem(rroot->rinfo->rchain, rflt);
	if (IS_ERR(rchain))
		return PTR_ERR(rchain);

	rinfo = rfs_info_alloc(rroot, rchain);
	if (IS_ERR(rinfo)) {
		rv = PTR_ERR(rinfo);
		goto exit;
	}

	rdata = rfs_dcache_data_alloc(rroot->dentry, rinfo, rflt);
	if (IS_ERR(rdata)) {
		rv = PTR_ERR(rdata);
		goto exit;
	}

	rv = rfs_dcache_walk(rroot->dentry, rfs_dcache_rem, rdata);
	if (rv)
		goto exit;

	rfs_root_set_rinfo(rroot, rinfo);
exit:
	rfs_dcache_data_free(rdata);
	rfs_chain_put(rchain);
	rfs_info_put(rinfo);
	return rv;
}

int rfs_root_walk(int (*cb)(struct rfs_root *, void *), void *data)
{
	struct rfs_root *rroot;
	struct rfs_root *tmp;
	int rv = 0;

	while (!list_empty(&rfs_root_walk_list)) {
		rroot = list_entry(rfs_root_walk_list.next, struct rfs_root,
				walk_list);
		rv = cb(rroot, data);
		if (rv)
			break;

		list_del_init(&rroot->walk_list);
	}

	list_for_each_entry_safe(rroot, tmp, &rfs_root_walk_list, walk_list) {
		list_del_init(&rroot->walk_list);
	}

	return rv;
}

void rfs_root_add_walk(struct dentry *dentry)
{
	struct rfs_dentry *rdentry = NULL;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		goto error;

	if (!rdentry->rinfo)
		goto error;

	if (rdentry->rinfo->rroot->dentry != dentry)
		goto error;

	list_add_tail(&rdentry->rinfo->rroot->walk_list, &rfs_root_walk_list);

error:
	rfs_dentry_put(rdentry);
	return;
}

static struct rfs_root *rfs_get_root_flt(struct rfs_flt *rflt,
		struct rfs_info *rinfo_start)
{
	struct rfs_root *rroot = NULL;
	struct rfs_info *rinfo;

	rinfo = rfs_info_get(rinfo_start);

	while (rinfo) {
		if (rfs_chain_find(rinfo->rchain, rflt) == -1)
			goto exit;

		rroot = rfs_root_get(rinfo->rroot);
		if (!rroot)
			goto exit;

		spin_lock(&rroot->lock);

		if (rfs_chain_find(rroot->rinch, rflt) != -1) {
			spin_unlock(&rroot->lock);
			goto exit;

		}

		spin_unlock(&rroot->lock);

		rfs_info_put(rinfo);
		rinfo = rfs_info_parent(rroot->dentry);
		rfs_root_put(rroot);
		rroot = NULL;
	}

exit:
	rfs_info_put(rinfo);
	return rroot;
}

redirfs_root redirfs_get_root_file(redirfs_filter filter, struct file *file)
{
	struct rfs_root *rroot;
	struct rfs_file *rfile;
	struct rfs_info *rinfo;

	if (!filter || IS_ERR(filter) || !file)
		return NULL;

	rfile = rfs_file_find(file);
	if (!rfile)
		return NULL;

	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);

	rroot = rfs_get_root_flt(filter, rinfo);

	rfs_info_put(rinfo);
	rfs_file_put(rfile);
	return rroot;
}

redirfs_root redirfs_get_root_dentry(redirfs_filter filter,
		struct dentry *dentry)
{
	struct rfs_root *rroot;
	struct rfs_dentry *rdentry;
	struct rfs_info *rinfo;

	if (!filter || IS_ERR(filter) || !dentry)
		return NULL;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return NULL;

	rinfo = rfs_dentry_get_rinfo(rdentry);

	rroot = rfs_get_root_flt(filter, rinfo);

	rfs_info_put(rinfo);
	rfs_dentry_put(rdentry);
	return rroot;
}

redirfs_root redirfs_get_root_inode(redirfs_filter filter, struct inode *inode)
{
	struct rfs_root *rroot;
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;

	if (!filter || IS_ERR(filter) || !inode)
		return NULL;

	rinode = rfs_inode_find(inode);
	if (!rinode)
		return NULL;

	rinfo = rfs_inode_get_rinfo(rinode);

	rroot = rfs_get_root_flt(filter, rinfo);

	rfs_info_put(rinfo);
	rfs_inode_put(rinode);
	return rroot;
}

redirfs_root redirfs_get_root_path(redirfs_path path)
{
	struct rfs_path *rpath = path;

	if (!path)
		return NULL;

	return rfs_root_get(rpath->rroot);
}

redirfs_root redirfs_get_root(redirfs_root root)
{
	return rfs_root_get(root);
}

void redirfs_put_root(redirfs_root root)
{
	rfs_root_put(root);
}

void rfs_root_set_rinfo(struct rfs_root *rroot, struct rfs_info *rinfo)
{
	rfs_info_put(rroot->rinfo);
	rroot->rinfo = rfs_info_get(rinfo);
}

EXPORT_SYMBOL(redirfs_get_root_file);
EXPORT_SYMBOL(redirfs_get_root_dentry);
EXPORT_SYMBOL(redirfs_get_root_inode);
EXPORT_SYMBOL(redirfs_get_root_path);
EXPORT_SYMBOL(redirfs_get_root);
EXPORT_SYMBOL(redirfs_put_root);

