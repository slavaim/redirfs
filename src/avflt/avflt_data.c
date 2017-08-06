/*
 * AVFlt: Anti-Virus Filter
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

#include "avflt.h"

static struct kmem_cache *avflt_inode_data_cache = NULL;

static void avflt_root_data_free(struct redirfs_data *rfs_data)
{
	struct avflt_root_data *data = rfs_to_root_data(rfs_data);

	kfree(data);
}

static struct avflt_root_data *avflt_root_data_alloc(void)
{
	struct avflt_root_data *data;
	int err;

	data = kzalloc(sizeof(struct avflt_root_data), GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	err = redirfs_init_data(&data->rfs_data, avflt, avflt_root_data_free,
			NULL);
	if (err) {
		kfree(data);
		return ERR_PTR(err);
	}

	atomic_set(&data->cache_enabled, 1);
	atomic_set(&data->cache_ver, 0);

	return data;
}

struct avflt_root_data *avflt_get_root_data_root(redirfs_root root)
{
	struct redirfs_data *rfs_data;

	rfs_data = redirfs_get_data_root(avflt, root);
	if (!rfs_data)
		return NULL;

	return rfs_to_root_data(rfs_data);
}

struct avflt_root_data *avflt_get_root_data_inode(struct inode *inode)
{
	struct avflt_root_data *data;
	redirfs_root root;

	root = redirfs_get_root_inode(avflt, inode);
	if (!root)
		return NULL;

	data = avflt_get_root_data_root(root);
	redirfs_put_root(root);

	return data;
}

struct avflt_root_data *avflt_get_root_data(struct avflt_root_data *data)
{
	struct redirfs_data *rfs_data;

	if (!data || IS_ERR(data))
		return NULL;

	rfs_data = redirfs_get_data(&data->rfs_data);
	if (!rfs_data)
		return NULL;

	return data;
}

void avflt_put_root_data(struct avflt_root_data *data)
{
	if (!data || IS_ERR(data))
		return;

	redirfs_put_data(&data->rfs_data);
}

struct avflt_root_data *avflt_attach_root_data(redirfs_root root)
{
	struct avflt_root_data *data = NULL;
	struct avflt_root_data *rv = NULL;
	struct redirfs_data *rfs_data = NULL;

	data = avflt_get_root_data_root(root);
	if (data)
		return data;

	data = avflt_root_data_alloc();
	if (!data)
		return data;

	rfs_data = redirfs_attach_data_root(avflt, root, &data->rfs_data);
	if (!rfs_data)
		goto exit;

	if (rfs_data != &data->rfs_data)
		rv = rfs_to_root_data(rfs_data);
	else
		rv = data;
exit:
	avflt_put_root_data(data);
	return rv;
}

static void avflt_inode_data_free(struct redirfs_data *rfs_data)
{
	struct avflt_inode_data *data = rfs_to_inode_data(rfs_data);

	avflt_put_root_data(data->root_data);
	kmem_cache_free(avflt_inode_data_cache, data);
}

static struct avflt_inode_data *avflt_inode_data_alloc(void)
{
	struct avflt_inode_data *data;
	int err;

	data = kmem_cache_zalloc(avflt_inode_data_cache, GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	err = redirfs_init_data(&data->rfs_data, avflt, avflt_inode_data_free,
			NULL);
	if (err) {
		 kmem_cache_free(avflt_inode_data_cache, data);
		 return ERR_PTR(err);
	}

	spin_lock_init(&data->lock);
	return data;
}

struct avflt_inode_data *avflt_get_inode_data_inode(struct inode *inode)
{
	struct redirfs_data *rfs_data;

	rfs_data = redirfs_get_data_inode(avflt, inode);
	if (!rfs_data)
		return NULL;

	return rfs_to_inode_data(rfs_data);
}

struct avflt_inode_data *avflt_get_inode_data(struct avflt_inode_data *data)
{
	struct redirfs_data *rfs_data;

	if (!data || IS_ERR(data))
		return NULL;

	rfs_data = redirfs_get_data(&data->rfs_data);
	if (!rfs_data)
		return NULL;

	return data;
}

void avflt_put_inode_data(struct avflt_inode_data *data)
{
	if (!data || IS_ERR(data))
		return;

	redirfs_put_data(&data->rfs_data);
}

struct avflt_inode_data *avflt_attach_inode_data(struct inode *inode)
{
	struct redirfs_data *rfs_data = NULL;
	struct avflt_inode_data *data = NULL;
	struct avflt_inode_data *rv = NULL;

	data = avflt_get_inode_data_inode(inode);
	if (data)
		return data;

	data = avflt_inode_data_alloc();
	if (!data) 
		return data;

	rfs_data = redirfs_attach_data_inode(avflt, inode,
			&data->rfs_data);
	if (!rfs_data)
		goto exit;

	if (rfs_data != &data->rfs_data)
		rv = rfs_to_inode_data(rfs_data);
	else
		rv = data;
exit:
	avflt_put_inode_data(data);
	return rv;
}

int avflt_data_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
	avflt_inode_data_cache = kmem_cache_create("avflt_inode_data_cache",
			sizeof(struct avflt_inode_data),
			0, SLAB_RECLAIM_ACCOUNT, NULL, NULL);
#else
	avflt_inode_data_cache = kmem_cache_create("avflt_inode_data_cache",
			sizeof(struct avflt_inode_data),
			0, SLAB_RECLAIM_ACCOUNT, NULL);
#endif

	if (!avflt_inode_data_cache)
		return -ENOMEM;

	return 0;
}

void avflt_data_exit(void)
{
	kmem_cache_destroy(avflt_inode_data_cache);
}

