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

static LIST_HEAD(rfs_flt_list);
RFS_DEFINE_MUTEX(rfs_flt_list_mutex);

struct rfs_flt *rfs_flt_alloc(struct redirfs_filter_info *flt_info)
{
	struct rfs_flt *rflt;
	char *name;
	int len;
	
	len = strlen(flt_info->name);
	name = kzalloc(len + 1, GFP_KERNEL);
	if (!name)
		return ERR_PTR(-ENOMEM);

	strncpy(name, flt_info->name, len);

	rflt = kzalloc(sizeof(struct rfs_flt), GFP_KERNEL);
	if (!rflt) {
		kfree(name);
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&rflt->list);
	rflt->name = name;
	rflt->priority = flt_info->priority;
	rflt->owner = flt_info->owner;
	rflt->ops = flt_info->ops;
	atomic_set(&rflt->count, 1);
	spin_lock_init(&rflt->lock);
	try_module_get(rflt->owner);

	if (flt_info->active)
		atomic_set(&rflt->active, 1);
	else
		atomic_set(&rflt->active, 0);

	return rflt;
}

struct rfs_flt *rfs_flt_get(struct rfs_flt *rflt)
{
	if (!rflt || IS_ERR(rflt))
		return NULL;

	BUG_ON(!atomic_read(&rflt->count));
	atomic_inc(&rflt->count);

	return rflt;
}

void rfs_flt_put(struct rfs_flt *rflt)
{
	if (!rflt || IS_ERR(rflt))
		return;

	BUG_ON(!atomic_read(&rflt->count));
	if (!atomic_dec_and_test(&rflt->count))
		return;

	kfree(rflt->name);
	kfree(rflt);
}

void rfs_flt_release(struct kobject *kobj)
{
	struct rfs_flt *rflt = rfs_kobj_to_rflt(kobj);

	rfs_flt_put(rflt);
}

static int rfs_flt_exist(const char *name, int priority)
{
	struct rfs_flt *rflt;

	list_for_each_entry(rflt, &rfs_flt_list, list) {
		if (rflt->priority == priority)
			return 1;

		if (!strcmp(rflt->name, name))
			return 1;
	}

	return 0;
}

redirfs_filter redirfs_register_filter(struct redirfs_filter_info *info)
{
	struct rfs_flt *rflt;
	int rv;

	might_sleep();

	if (!info)
		return ERR_PTR(-EINVAL);

	rfs_mutex_lock(&rfs_flt_list_mutex);

	if (rfs_flt_exist(info->name, info->priority)) {
		rfs_mutex_unlock(&rfs_flt_list_mutex);
		return ERR_PTR(-EEXIST);
	}

	rflt = rfs_flt_alloc(info);
	if (IS_ERR(rflt)) {
		rfs_mutex_unlock(&rfs_flt_list_mutex);
		return (redirfs_filter)rflt;
	}

	rv = rfs_flt_sysfs_init(rflt);
	if (rv) {
		rfs_flt_put(rflt);
		rfs_mutex_unlock(&rfs_flt_list_mutex);
		return ERR_PTR(rv);
	}

	list_add_tail(&rflt->list, &rfs_flt_list);
	rfs_flt_get(rflt);

	rfs_mutex_unlock(&rfs_flt_list_mutex);

	return (redirfs_filter)rflt;
}

int redirfs_unregister_filter(redirfs_filter filter)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	might_sleep();

	if (!rflt || IS_ERR(rflt))
		return -EINVAL;

	spin_lock(&rflt->lock);

	/*
	 * Check if the unregistration is already in progress.
	 */
	if (atomic_read(&rflt->count) < 3) {
		spin_unlock(&rflt->lock);
		return 0;
	}

	/*
	 * Filter can be unregistered only if the reference counter is equal to
	 * three. This means no one else is using it except the following.
	 *
	 *    - sysfs interface
	 *    - internal filter list
	 *    - handler returned to filter after registration
	 */
	if (atomic_read(&rflt->count) != 3) {
		spin_unlock(&rflt->lock);
		return -EBUSY;
	}

	rfs_flt_put(rflt);
	spin_unlock(&rflt->lock);

	rfs_mutex_lock(&rfs_flt_list_mutex);
	list_del_init(&rflt->list);
	rfs_mutex_unlock(&rfs_flt_list_mutex);

	module_put(rflt->owner);

	return 0;
}

void redirfs_delete_filter(redirfs_filter filter)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	if (!rflt || IS_ERR(rflt))
		return;

	BUG_ON(atomic_read(&rflt->count) != 2);

	rfs_flt_sysfs_exit(rflt);
	rfs_flt_put(rflt);
}

static int rfs_flt_set_ops(struct rfs_flt *rflt)
{
	struct rfs_root *rroot;
	struct rfs_info *rinfo;
	int rv;

	list_for_each_entry(rroot, &rfs_root_list, list) {
		if (rfs_chain_find(rroot->rinfo->rchain, rflt) == -1)
			continue;

		rinfo = rfs_info_alloc(rroot, rroot->rinfo->rchain);
		if (IS_ERR(rinfo))
			return PTR_ERR(rinfo);

		rv = rfs_info_reset(rroot->dentry, rinfo);
		if (rv) {
			rfs_info_put(rinfo);
			return rv;
		}

		rfs_info_put(rroot->rinfo);
		rroot->rinfo = rinfo;
	}

	return 0;
}

int redirfs_set_operations(redirfs_filter filter, struct redirfs_op_info ops[])
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	int i = 0;
	int rv = 0;

	might_sleep();

	if (!rflt || IS_ERR(rflt))
		return -EINVAL;

	while (ops[i].op_id != REDIRFS_OP_END) {
		rflt->cbs[ops[i].op_id].pre_cb = ops[i].pre_cb;
		rflt->cbs[ops[i].op_id].post_cb = ops[i].post_cb;
		i++;
	}

	rfs_mutex_lock(&rfs_path_mutex);
	rv = rfs_flt_set_ops(rflt);
	rfs_mutex_unlock(&rfs_path_mutex);

	return rv;
}

int redirfs_activate_filter(redirfs_filter filter)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	if (!rflt || IS_ERR(rflt))
		return -EINVAL;

	atomic_set(&rflt->active, 1);

	return 0;
}

int redirfs_deactivate_filter(redirfs_filter filter)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	if (!rflt || IS_ERR(rflt))
		return -EINVAL;

	atomic_set(&rflt->active, 0);

	return 0;
}

EXPORT_SYMBOL(redirfs_register_filter);
EXPORT_SYMBOL(redirfs_unregister_filter);
EXPORT_SYMBOL(redirfs_delete_filter);
EXPORT_SYMBOL(redirfs_set_operations);
EXPORT_SYMBOL(redirfs_activate_filter);
EXPORT_SYMBOL(redirfs_deactivate_filter);

