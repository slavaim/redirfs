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

static int avflt_should_check(struct file *file)
{
	if (avflt_is_stopped())
		return 0;

	if (avflt_proc_allow(current->tgid))
		return 0;

	if (avflt_trusted_allow(current->tgid))
		return 0;
	
	if (!file->f_dentry->d_inode)
		return 0;

	if (!i_size_read(file->f_dentry->d_inode))
		return 0;

	return 1;
}

static int avflt_check_cache(struct file *file, int type)
{
	struct avflt_root_data *root_data;
	struct avflt_inode_data *inode_data;
	int state = 0;
	int wc;

	if (!atomic_read(&avflt_cache_enabled))
		return 0;

	root_data = avflt_get_root_data_inode(file->f_dentry->d_inode);
	if (!root_data)
		return 0;

	if (!atomic_read(&root_data->cache_enabled)) {
		avflt_put_root_data(root_data);
		return 0;
	}

	inode_data = avflt_get_inode_data_inode(file->f_dentry->d_inode);
	if (!inode_data) {
		avflt_put_root_data(root_data);
		return 0;
	}

	wc = atomic_read(&file->f_dentry->d_inode->i_writecount);

	spin_lock(&inode_data->lock);

	if (wc == 1) {
		if (!(file->f_mode & FMODE_WRITE))
			inode_data->inode_cache_ver++;

		else if (type == AVFLT_EVENT_CLOSE)
			inode_data->inode_cache_ver++;

	} else if (wc > 1)
		inode_data->inode_cache_ver++;

	if (inode_data->root_data != root_data)
		goto exit;

	if (inode_data->root_cache_ver != atomic_read(&root_data->cache_ver))
		goto exit;

	if (inode_data->cache_ver != inode_data->inode_cache_ver)
		goto exit;

	state = inode_data->state;
exit:
	spin_unlock(&inode_data->lock);
	avflt_put_inode_data(inode_data);
	avflt_put_root_data(root_data);
	return state;
}

static enum redirfs_rv avflt_eval_res(int rv, struct redirfs_args *args)
{
	if (rv < 0) {
		args->rv.rv_int = rv;
		return REDIRFS_STOP;
	} 

	if (rv == AVFLT_FILE_INFECTED) {
		args->rv.rv_int = -EPERM;
		return REDIRFS_STOP;
	}

	return REDIRFS_CONTINUE;
}

static enum redirfs_rv avflt_check_file(struct file *file, int type,
		struct redirfs_args *args)
{
	int rv;

	if (!avflt_should_check(file))
		return REDIRFS_CONTINUE;

	rv = avflt_check_cache(file, type);
	if (rv)
		return avflt_eval_res(rv, args);

	rv = avflt_process_request(file, type);
	if (rv)
		return avflt_eval_res(rv, args);

	return REDIRFS_CONTINUE;
}

static enum redirfs_rv avflt_pre_open(redirfs_context context,
		struct redirfs_args *args)
{
	struct file *file = args->args.f_open.file;

	return avflt_check_file(file, AVFLT_EVENT_OPEN, args);
}

static enum redirfs_rv avflt_post_release(redirfs_context context,
		struct redirfs_args *args)
{
	struct file *file = args->args.f_release.file;

	return avflt_check_file(file, AVFLT_EVENT_CLOSE, args);
}

static int avflt_activate(void)
{
	avflt_invalidate_cache();
	return redirfs_activate_filter(avflt);
}

static int avflt_add_path(struct redirfs_path_info *info)
{
	struct avflt_root_data *data;
	redirfs_path path;
	redirfs_root root;

	path = redirfs_add_path(avflt, info);
	if (IS_ERR(path))
		return PTR_ERR(path);

	root = redirfs_get_root_path(path);
	redirfs_put_path(path);
	if (!root)
		return 0;

	data = avflt_attach_root_data(root);

	redirfs_put_root(root);
	avflt_put_root_data(data);
	
	return 0;
}

redirfs_filter avflt;

static struct redirfs_filter_operations avflt_ops = {
	.activate = avflt_activate,
	.add_path = avflt_add_path
};

static struct redirfs_filter_info avflt_info = {
	.owner = THIS_MODULE,
	.name = "avflt",
	.priority = 850000000,
	.active = 1,
	.ops = &avflt_ops
};

static struct redirfs_op_info avflt_op_info[] = {
	{REDIRFS_REG_FOP_OPEN, avflt_pre_open, NULL},
	{REDIRFS_REG_FOP_RELEASE, avflt_post_release, NULL},
	{REDIRFS_OP_END, NULL, NULL}
};

int avflt_rfs_init(void)
{
	int err;
	int rv;

	avflt = redirfs_register_filter(&avflt_info);
	if (IS_ERR(avflt)) {
		rv = PTR_ERR(avflt);
		printk(KERN_ERR "avflt: register filter failed(%d)\n", rv);
		return rv;
	}

	rv = redirfs_set_operations(avflt, avflt_op_info);
	if (rv) {
		printk(KERN_ERR "avflt: set operations failed(%d)\n", rv);
		goto error;
	}

	return 0;
error:
	err = redirfs_unregister_filter(avflt);
	if (err) {
		printk(KERN_ERR "avflt: unregister filter failed(%d)\n", err);
		return 0;
	}

	redirfs_delete_filter(avflt);
	return rv;
}

void avflt_rfs_exit(void)
{
	redirfs_delete_filter(avflt);
}

