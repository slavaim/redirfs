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

void rfs_data_remove(struct list_head *head)
{
	struct redirfs_data *data;
	struct redirfs_data *tmp;

	list_for_each_entry_safe(data, tmp, head, list) {
		list_del_init(&data->list);
		if (data->detach)
			data->detach(data);
		redirfs_put_data(data);
	}
}

int redirfs_init_data(struct redirfs_data *data, redirfs_filter filter,
		void (*free)(struct redirfs_data *),
		void (*detach)(struct redirfs_data *))
{
	if (!data || !filter || IS_ERR(filter) || !free)
		return -EINVAL;

	INIT_LIST_HEAD(&data->list);
	atomic_set(&data->cnt, 1);
	data->free = free;
	data->detach = detach;
	data->filter = rfs_flt_get(filter);

	return 0;
}

struct redirfs_data *redirfs_get_data(struct redirfs_data *data)
{
	if (!data || IS_ERR(data))
		return NULL;
	
	BUG_ON(!atomic_read(&data->cnt));

	atomic_inc(&data->cnt);

	return data;
}

void redirfs_put_data(struct redirfs_data *data)
{
	if (!data || IS_ERR(data))
		return;

	BUG_ON(!atomic_read(&data->cnt));
	
	if (!atomic_dec_and_test(&data->cnt))
		return;

	rfs_flt_put(data->filter);
	data->free(data);
}

static struct redirfs_data *rfs_find_data(struct list_head *head,
		redirfs_filter filter)
{
	struct redirfs_data *data;

	list_for_each_entry(data, head, list) {
		if (data->filter == filter)
			return redirfs_get_data(data);
	}

	return NULL;
}

struct redirfs_data *redirfs_attach_data_file(redirfs_filter filter,
		struct file *file, struct redirfs_data *data)
{
	struct rfs_file *rfile;
	struct redirfs_data *rv = NULL;

	if (!filter || IS_ERR(filter) || !file || !data)
		return NULL;

	rfile = rfs_file_find(file);
	if (!rfile)
		return NULL;

	spin_lock(&rfile->rdentry->lock);
	spin_lock(&rfile->lock);

	if (rfs_chain_find(rfile->rdentry->rinfo->rchain, filter) == -1)
		goto exit;

	rv = rfs_find_data(&rfile->data, filter);
	if (rv)
		goto exit;

	list_add_tail(&data->list, &rfile->data); 
	redirfs_get_data(data);
	rv = redirfs_get_data(data);
exit:
	spin_unlock(&rfile->lock);
	spin_unlock(&rfile->rdentry->lock);
	rfs_file_put(rfile);
	return rv;
}

struct redirfs_data *redirfs_detach_data_file(redirfs_filter filter,
		struct file *file)
{
	struct rfs_file *rfile;
	struct redirfs_data *data;

	if (!filter || IS_ERR(filter) || !file)
		return NULL;

	rfile = rfs_file_find(file);
	if (!rfile)
		return NULL;

	spin_lock(&rfile->lock);

	data = rfs_find_data(&rfile->data, filter);
	if (data)
		list_del(&data->list);

	spin_unlock(&rfile->lock);
	redirfs_put_data(data);
	rfs_file_put(rfile);
	return data;
}

struct redirfs_data *redirfs_get_data_file(redirfs_filter filter,
		struct file *file)
{
	struct rfs_file *rfile;
	struct redirfs_data *data;

	if (!filter || IS_ERR(filter) || !file)
		return NULL;

	rfile = rfs_file_find(file);
	if (!rfile)
		return NULL;

	spin_lock(&rfile->lock);

	data = rfs_find_data(&rfile->data, filter);

	spin_unlock(&rfile->lock);
	rfs_file_put(rfile);
	return data;
}

struct redirfs_data *redirfs_attach_data_dentry(redirfs_filter filter,
		struct dentry *dentry, struct redirfs_data *data)
{
	struct rfs_dentry *rdentry;
	struct redirfs_data *rv = NULL;

	if (!filter || IS_ERR(filter) || !dentry || !data)
		return NULL;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return NULL;

	spin_lock(&rdentry->lock);

	if (rfs_chain_find(rdentry->rinfo->rchain, filter) == -1)
		goto exit;

	rv = rfs_find_data(&rdentry->data, filter);
	if (rv)
		goto exit;

	list_add_tail(&data->list, &rdentry->data); 
	redirfs_get_data(data);
	rv = redirfs_get_data(data);
exit:
	spin_unlock(&rdentry->lock);
	rfs_dentry_put(rdentry);
	return rv;
}

struct redirfs_data *redirfs_detach_data_dentry(redirfs_filter filter,
		struct dentry *dentry)
{
	struct rfs_dentry *rdentry;
	struct redirfs_data *data;

	if (!filter || IS_ERR(filter) || !dentry)
		return NULL;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return NULL;

	spin_lock(&rdentry->lock);

	data = rfs_find_data(&rdentry->data, filter);
	if (data)
		list_del(&data->list);

	spin_unlock(&rdentry->lock);
	redirfs_put_data(data);
	rfs_dentry_put(rdentry);
	return data;
}

struct redirfs_data *redirfs_get_data_dentry(redirfs_filter filter,
		struct dentry *dentry)
{
	struct rfs_dentry *rdentry;
	struct redirfs_data *data;

	if (!filter || IS_ERR(filter) || !dentry)
		return NULL;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return NULL;

	spin_lock(&rdentry->lock);

	data = rfs_find_data(&rdentry->data, filter);

	spin_unlock(&rdentry->lock);
	rfs_dentry_put(rdentry);
	return data;
}

struct redirfs_data *redirfs_attach_data_inode(redirfs_filter filter,
		struct inode *inode, struct redirfs_data *data)
{
	struct rfs_inode *rinode;
	struct redirfs_data *rv = NULL;

	if (!filter || IS_ERR(filter) || !inode || !data)
		return NULL;

	rinode = rfs_inode_find(inode);
	if (!rinode)
		return NULL;

	spin_lock(&rinode->lock);

	if (rfs_chain_find(rinode->rinfo->rchain, filter) == -1)
		goto exit;

	rv = rfs_find_data(&rinode->data, filter);
	if (rv)
		goto exit;

	list_add_tail(&data->list, &rinode->data); 
	redirfs_get_data(data);
	rv = redirfs_get_data(data);
exit:
	spin_unlock(&rinode->lock);
	rfs_inode_put(rinode);
	return rv;
}

struct redirfs_data *redirfs_detach_data_inode(redirfs_filter filter,
		struct inode *inode)
{
	struct rfs_inode *rinode;
	struct redirfs_data *data;

	if (!filter || IS_ERR(filter) || !inode)
		return NULL;

	rinode = rfs_inode_find(inode);
	if (!rinode)
		return NULL;

	spin_lock(&rinode->lock);

	data = rfs_find_data(&rinode->data, filter);
	if (data)
		list_del(&data->list);

	spin_unlock(&rinode->lock);
	redirfs_put_data(data);
	rfs_inode_put(rinode);
	return data;
}

struct redirfs_data *redirfs_get_data_inode(redirfs_filter filter,
		struct inode *inode)
{
	struct rfs_inode *rinode;
	struct redirfs_data *data;

	if (!filter || IS_ERR(filter) || !inode)
		return NULL;

	rinode = rfs_inode_find(inode);
	if (!rinode)
		return NULL;

	spin_lock(&rinode->lock);

	data = rfs_find_data(&rinode->data, filter);

	spin_unlock(&rinode->lock);
	rfs_inode_put(rinode);
	return data;
}

void rfs_context_init(struct rfs_context *rcont, int start)
{
	INIT_LIST_HEAD(&rcont->data);
	rcont->idx_start = start;
	rcont->idx = 0;
}

void rfs_context_deinit(struct rfs_context *rcont)
{
	rfs_data_remove(&rcont->data);
}

struct redirfs_data *redirfs_attach_data_context(redirfs_filter filter,
		redirfs_context context, struct redirfs_data *data)
{
	struct rfs_context *rcont = (struct rfs_context *)context;
	struct redirfs_data *rv;

	if (!filter || IS_ERR(filter) || !context || !data)
		return NULL;

	rv = rfs_find_data(&rcont->data, filter);
	if (rv)
		return rv;

	list_add_tail(&data->list, &rcont->data); 
	redirfs_get_data(data);

	return redirfs_get_data(data);
}

struct redirfs_data *redirfs_detach_data_context(redirfs_filter filter,
		redirfs_context context)
{
	struct rfs_context *rcont = (struct rfs_context *)context;
	struct redirfs_data *data;

	if (!filter || IS_ERR(filter) || !context)
		return NULL;

	data = rfs_find_data(&rcont->data, filter);
	if (data)
		list_del(&data->list);

	redirfs_put_data(data);
	return data;
}

struct redirfs_data *redirfs_get_data_context(redirfs_filter filter,
		redirfs_context context)
{
	struct rfs_context *rcont = (struct rfs_context *)context;
	struct redirfs_data *data;

	if (!filter || IS_ERR(filter)|| !context)
		return NULL;

	data = rfs_find_data(&rcont->data, filter);

	return data;
}

struct redirfs_data *redirfs_attach_data_root(redirfs_filter filter,
		redirfs_root root, struct redirfs_data *data)
{
	struct rfs_root *rroot = (struct rfs_root *)root;
	struct redirfs_data *rv = NULL;
	int found = 0;

	if (!filter || IS_ERR(filter) || !root || !data)
		return NULL;

	spin_lock(&rroot->lock);

	if (rfs_chain_find(rroot->rinch, filter) != -1)
		found = 1;

	else if (rfs_chain_find(rroot->rexch, filter) != -1)
		found = 1;

	if (!found)
		goto exit;

	rv = rfs_find_data(&rroot->data, filter);
	if (rv)
		goto exit;

	list_add_tail(&data->list, &rroot->data); 
	redirfs_get_data(data);
	rv = redirfs_get_data(data);
exit:
	spin_unlock(&rroot->lock);
	return rv;
}

struct redirfs_data *redirfs_detach_data_root(redirfs_filter filter,
		redirfs_root root)
{
	struct rfs_root *rroot = (struct rfs_root *)root;
	struct redirfs_data *data;

	if (!filter || IS_ERR(filter) || !root)
		return NULL;

	spin_lock(&rroot->lock);

	data = rfs_find_data(&rroot->data, filter);
	if (data)
		list_del(&data->list);

	spin_unlock(&rroot->lock);
	redirfs_put_data(data);

	return data;
}

struct redirfs_data *redirfs_get_data_root(redirfs_filter filter,
		redirfs_root root)
{
	struct rfs_root *rroot = (struct rfs_root *)root;
	struct redirfs_data *data;

	if (!filter || IS_ERR(filter) || !root)
		return NULL;

	spin_lock(&rroot->lock);

	data = rfs_find_data(&rroot->data, filter);

	spin_unlock(&rroot->lock);

	return data;
}

EXPORT_SYMBOL(redirfs_init_data);
EXPORT_SYMBOL(redirfs_get_data);
EXPORT_SYMBOL(redirfs_put_data);
EXPORT_SYMBOL(redirfs_attach_data_file);
EXPORT_SYMBOL(redirfs_detach_data_file);
EXPORT_SYMBOL(redirfs_get_data_file);
EXPORT_SYMBOL(redirfs_attach_data_dentry);
EXPORT_SYMBOL(redirfs_detach_data_dentry);
EXPORT_SYMBOL(redirfs_get_data_dentry);
EXPORT_SYMBOL(redirfs_attach_data_inode);
EXPORT_SYMBOL(redirfs_detach_data_inode);
EXPORT_SYMBOL(redirfs_get_data_inode);
EXPORT_SYMBOL(redirfs_attach_data_context);
EXPORT_SYMBOL(redirfs_detach_data_context);
EXPORT_SYMBOL(redirfs_get_data_context);
EXPORT_SYMBOL(redirfs_attach_data_root);
EXPORT_SYMBOL(redirfs_detach_data_root);
EXPORT_SYMBOL(redirfs_get_data_root);

