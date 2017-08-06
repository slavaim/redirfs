/*
 * MvFlt: Move/Rename Filter
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

#include <linux/slab.h>
#include <redirfs.h>

#define MVFLT_VERSION "0.0"

static redirfs_filter mvflt;

enum redirfs_rv mvflt_rename_out(redirfs_context context,
		struct redirfs_args *args)
{
	char *filename;
	char *call;
	redirfs_root root;
	redirfs_path path;
	redirfs_path* paths;
	struct redirfs_path_info *path_info;
	int rv;

	filename = NULL;
	path_info = NULL;
	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	root = redirfs_get_root_dentry(mvflt, args->args.i_rename.old_dentry);
	if (!root) {
		printk(KERN_WARNING "mvflt: redirfs_get_root_dentry: NULL\n");
		return REDIRFS_CONTINUE;
	}

	paths = redirfs_get_paths_root(mvflt, root);
	path = paths[0];
	if (!path) {
		printk(KERN_WARNING "mvflt: redirfs_get_paths_root: NULL\n");
		goto exit;
	}

	path_info = redirfs_get_path_info(mvflt, path);
	if (IS_ERR(path_info)) {
		printk(KERN_ERR "mvflt: redirfs_get_path_info failed(%ld)\n",
				PTR_ERR(path_info));
		goto exit;
	}

	filename = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!filename) {
		printk(KERN_WARNING "mvflt: filename allocation failed\n");
		goto exit;
	}

	rv = redirfs_get_filename(path_info->mnt,
			args->args.i_rename.old_dentry, filename, PAGE_SIZE);
	if (rv) {
		printk(KERN_ERR "mvflt: redirfs_get_filename failed(%d)\n", rv);
		goto exit;
	}

	printk(KERN_ALERT "mvflt: move out: %s: %s\n", call, filename);
exit:
	kfree(filename);
	redirfs_put_path_info(path_info);
	redirfs_put_paths(paths);
	redirfs_put_root(root);
	return REDIRFS_CONTINUE;
}

enum redirfs_rv mvflt_rename_in(redirfs_context context,
		struct redirfs_args *args)
{
	char *filename;
	char *call;
	redirfs_root root;
	redirfs_path path;
	redirfs_path* paths;
	struct redirfs_path_info *path_info;
	int rv;

	filename = NULL;
	path_info = NULL;
	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	root = redirfs_get_root_dentry(mvflt, args->args.i_rename.new_dentry);
	if (!root) {
		printk(KERN_WARNING "mvflt: redirfs_get_root_dentry: NULL\n");
		return REDIRFS_CONTINUE;
	}

	paths = redirfs_get_paths_root(mvflt, root);
	path = paths[0];
	if (!path) {
		printk(KERN_WARNING "mvflt: redirfs_get_paths_root: NULL\n");
		goto exit;
	}

	path_info = redirfs_get_path_info(mvflt, path);
	if (IS_ERR(path_info)) {
		printk(KERN_ERR "mvflt: redirfs_get_path_info failed(%ld)\n",
				PTR_ERR(path_info));
		goto exit;
	}

	filename = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!filename) {
		printk(KERN_WARNING "mvflt: filename allocation failed\n");
		goto exit;
	}

	rv = redirfs_get_filename(path_info->mnt,
			args->args.i_rename.new_dentry, filename, PAGE_SIZE);
	if (rv) {
		printk(KERN_ERR "mvflt: redirfs_get_filename failed(%d)\n", rv);
		goto exit;
	}

	printk(KERN_ALERT "mvflt: move in: %s: %s\n", call, filename);
exit:
	kfree(filename);
	redirfs_put_path_info(path_info);
	redirfs_put_paths(paths);
	redirfs_put_root(root);
	return REDIRFS_CONTINUE;

}

struct redirfs_filter_operations mvflt_ops = {
	.pre_rename = mvflt_rename_in,
	.post_rename = mvflt_rename_in
};

static struct redirfs_filter_info mvflt_info = {
	.owner = THIS_MODULE,
	.name = "mvflt",
	.priority = 600000000,
	.active = 1,
	.ops = &mvflt_ops
};

static struct redirfs_op_info mvflt_op_info[] = {
	{REDIRFS_DIR_IOP_RENAME, mvflt_rename_out, mvflt_rename_out},
	{REDIRFS_OP_END, NULL, NULL}
};

static int __init mvflt_init(void)
{
	int err;
	int rv;

	mvflt = redirfs_register_filter(&mvflt_info);
	if (IS_ERR(mvflt)) {
		rv = PTR_ERR(mvflt);
		printk(KERN_ERR "mvflt: register filter failed(%d)\n", rv);
		return rv;
	}

	rv = redirfs_set_operations(mvflt, mvflt_op_info);
	if (rv) {
		printk(KERN_ERR "mvflt: set operations failed(%d)\n", rv);
		goto error;
	}

	printk(KERN_INFO "Move/Rename Filter Version "
			MVFLT_VERSION " <www.redirfs.org>\n");
	return 0;
error:
	err = redirfs_unregister_filter(mvflt);
	if (err) {
		printk(KERN_ERR "mvflt: unregister filter "
				"failed(%d)\n", err);
		return 0;
	}
	redirfs_delete_filter(mvflt);
	return rv;
}

static void __exit mvflt_exit(void)
{
	redirfs_delete_filter(mvflt);
}

module_init(mvflt_init);
module_exit(mvflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <frantisek.hrbata@redirfs.org>");
MODULE_DESCRIPTION("Move/Rename Filter Version " MVFLT_VERSION "<www.redirfs.org>");

