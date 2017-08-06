/*
 * ROFlt: Read-Only Filter
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

#include <redirfs.h>

#define ROFLT_VERSION "0.1"

static redirfs_filter roflt;

static struct redirfs_filter_info roflt_info = {
	.owner = THIS_MODULE,
	.name = "roflt",
	.priority = 660000000,
	.active = 1
};

static enum redirfs_rv roflt_pre_open(redirfs_context context,
		struct redirfs_args *args)
{
	struct file *file = args->args.f_open.file;

	if (file->f_mode & FMODE_WRITE) {
		args->rv.rv_int = -EROFS;
		return REDIRFS_STOP;
	}

	return REDIRFS_CONTINUE;
}

static enum redirfs_rv roflt_rofs(redirfs_context context,
		struct redirfs_args *args)
{
	args->rv.rv_int = -EROFS;
	return REDIRFS_STOP;
}

static struct redirfs_op_info roflt_op_info[] = {
	{REDIRFS_REG_FOP_OPEN, roflt_pre_open, NULL},
	{REDIRFS_DIR_IOP_CREATE, roflt_rofs, NULL},
	{REDIRFS_DIR_IOP_LINK, roflt_rofs, NULL},
	{REDIRFS_DIR_IOP_UNLINK, roflt_rofs, NULL},
	{REDIRFS_DIR_IOP_SYMLINK, roflt_rofs, NULL},
	{REDIRFS_DIR_IOP_MKDIR, roflt_rofs, NULL},
	{REDIRFS_DIR_IOP_RMDIR, roflt_rofs, NULL},
	{REDIRFS_DIR_IOP_MKNOD, roflt_rofs, NULL},
	{REDIRFS_DIR_IOP_RENAME, roflt_rofs, NULL},
	{REDIRFS_REG_IOP_SETATTR, roflt_rofs, NULL},
	{REDIRFS_DIR_IOP_SETATTR, roflt_rofs, NULL},
	{REDIRFS_LNK_IOP_SETATTR, roflt_rofs, NULL},
	{REDIRFS_CHR_IOP_SETATTR, roflt_rofs, NULL},
	{REDIRFS_BLK_IOP_SETATTR, roflt_rofs, NULL},
	{REDIRFS_FIFO_IOP_SETATTR, roflt_rofs, NULL},
	{REDIRFS_SOCK_IOP_SETATTR, roflt_rofs, NULL},
	{REDIRFS_OP_END, NULL, NULL}
};

static int __init roflt_init(void)
{
	int err;
	int rv;

	roflt = redirfs_register_filter(&roflt_info);
	if (IS_ERR(roflt)) {
		rv = PTR_ERR(roflt);
		printk(KERN_ERR "roflt: register filter failed(%d)\n", rv);
		return rv;
	}

	rv = redirfs_set_operations(roflt, roflt_op_info);
	if (rv) {
		printk(KERN_ERR "roflt: set operations failed(%d)\n", rv);
		goto error;
	}

	printk(KERN_INFO "Read-Only Filter Version "
			ROFLT_VERSION " <www.redirfs.org>\n");
	return 0;

error:
	err = redirfs_unregister_filter(roflt);
	if (err) {
		printk(KERN_ERR "roflt: unregister filter "
				"failed(%d)\n", err);
		return 0;
	}

	redirfs_delete_filter(roflt);

	return rv;
}

static void __exit roflt_exit(void)
{
	redirfs_delete_filter(roflt);
}

module_init(roflt_init);
module_exit(roflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <frantisek.hrbata@redirfs.org>");
MODULE_DESCRIPTION("Read-Only Filter for the RedirFS Framework");

