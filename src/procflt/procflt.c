/*
 * ProcFlt: Read-Only Filter
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


#include "../redirfs/redirfs.h"

static rfs_filter procflt;
static struct rfs_path_info path_info;
static filldir_t filldir_orig = NULL;
static char *pidstr = "-1";

enum rfs_retv procflt_readdir(rfs_context context, struct rfs_args *args);

static struct rfs_filter_info flt_info = {"procflt", 99, 0};

static struct rfs_op_info op_info[] = {
	{RFS_DIR_FOP_READDIR, procflt_readdir, NULL},
	{RFS_OP_END, NULL, NULL}
};

static int procflt_filldir(void *__buf, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	int len;

	len = strlen(pidstr);
	if (len != namlen)
		return filldir_orig(__buf, name, namlen, offset, ino, d_type);

	if (!strncmp(pidstr, name, namlen))
		return 0;

	return filldir_orig(__buf, name, namlen, offset, ino, d_type);
}

enum rfs_retv procflt_readdir(rfs_context context, struct rfs_args *args)
{
	filldir_orig = args->args.f_readdir.filldir;
	args->args.f_readdir.filldir = procflt_filldir;

	return RFS_CONTINUE;
}

static int __init procflt_init(void)
{
	enum rfs_err err;

	err = rfs_register_filter(&procflt, &flt_info);
	if (err != RFS_ERR_OK) {
		printk(KERN_ERR "procflt: register filter failed: error %d\n", err);
		goto error;
	}

	err = rfs_set_operations(procflt, op_info); 
	if (err != RFS_ERR_OK) {
		printk(KERN_ERR "procflt: set operations failed: error %d\n", err);
		goto error;
	}

	path_info.path = "/proc";
	path_info.flags = RFS_PATH_INCLUDE | RFS_PATH_SINGLE;

	err = rfs_set_path(procflt, &path_info); 
	if (err != RFS_ERR_OK) {
		printk(KERN_ERR "procflt: set path failed: error %d\n", err);
		goto error;
	}

	err = rfs_activate_filter(procflt); 
	if (err != RFS_ERR_OK) {
		printk(KERN_ERR "procflt: activate filter failed: error %d\n", err);
		goto error;
	}

	return 0;

error:
	if (rfs_unregister_filter(procflt))
		printk(KERN_ERR "procflt: unregister filter failed: error %d\n", err);

	return err;
}

static void __exit procflt_exit(void)
{
	enum rfs_err err;
	
	err = rfs_unregister_filter(procflt);
	if (err != RFS_ERR_OK)
		printk(KERN_ERR "procflt: unregistration failed: error %d\n", err);
}

module_init(procflt_init);
module_exit(procflt_exit);

module_param(pidstr, charp, 0000);
MODULE_PARM_DESC(pidstr, "pid string to hide");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <franta@redirfs.org>");
MODULE_DESCRIPTION("Filter for process hiding");
