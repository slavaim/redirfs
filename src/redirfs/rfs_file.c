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

static rfs_kmem_cache_t *rfs_file_cache = NULL;

struct file_operations rfs_file_ops = {
	.open = rfs_open
};

static struct rfs_file *rfs_file_alloc(struct file *file)
{
	struct rfs_file *rfile;

	rfile = kmem_cache_zalloc(rfs_file_cache, GFP_KERNEL);
	if (!rfile)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rfile->rdentry_list);
	INIT_LIST_HEAD(&rfile->data);
	rfile->file = file;
	spin_lock_init(&rfile->lock);
	atomic_set(&rfile->count, 1);
	rfile->op_old = fops_get(file->f_op);

	if (rfile->op_old)
		memcpy(&rfile->op_new, rfile->op_old,
				sizeof(struct file_operations));

	rfile->op_new.open = rfs_open;

	return rfile;
}

struct rfs_file *rfs_file_get(struct rfs_file *rfile)
{
	if (!rfile || IS_ERR(rfile))
		return NULL;

	BUG_ON(!atomic_read(&rfile->count));
	atomic_inc(&rfile->count);

	return rfile;
}

void rfs_file_put(struct rfs_file *rfile)
{
	if (!rfile || IS_ERR(rfile))
		return;

	BUG_ON(!atomic_read(&rfile->count));
	if (!atomic_dec_and_test(&rfile->count))
		return;

	rfs_dentry_put(rfile->rdentry);
	fops_put(rfile->op_old);

	rfs_data_remove(&rfile->data);
	kmem_cache_free(rfs_file_cache, rfile);
}

static struct rfs_file *rfs_file_add(struct file *file)
{
	struct rfs_file *rfile;

	rfile = rfs_file_alloc(file);
	if (IS_ERR(rfile))
		return rfile;

	rfile->rdentry = rfs_dentry_find(file->f_dentry);
	rfs_dentry_add_rfile(rfile->rdentry, rfile);
	fops_put(file->f_op);
	file->f_op = &rfile->op_new;
	rfs_file_get(rfile);
	spin_lock(&rfile->rdentry->lock);
	rfs_file_set_ops(rfile);
	spin_unlock(&rfile->rdentry->lock);

	return rfile;
}

static void rfs_file_del(struct rfs_file *rfile)
{
	rfs_dentry_rem_rfile(rfile);
	rfile->file->f_op = fops_get(rfile->op_old);
	rfs_file_put(rfile);
}

int rfs_file_cache_create(void)
{
	rfs_file_cache = rfs_kmem_cache_create("rfs_file_cache",
			sizeof(struct rfs_file));

	if (!rfs_file_cache)
		return -ENOMEM;

	return 0;
}

void rfs_file_cache_destory(void)
{
	kmem_cache_destroy(rfs_file_cache);
}

int rfs_open(struct inode *inode, struct file *file)
{
	struct rfs_file *rfile;
	struct rfs_dentry *rdentry;
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rinode = rfs_inode_find(inode);
	fops_put(file->f_op);
	file->f_op = fops_get(rinode->fop_old);

	rdentry = rfs_dentry_find(file->f_dentry);
	if (!rdentry) {
		rfs_inode_put(rinode);
		if (file->f_op && file->f_op->open)
			return file->f_op->open(inode, file);

		return 0;
	}

	rinfo = rfs_dentry_get_rinfo(rdentry);
	rfs_dentry_put(rdentry);
	rfs_context_init(&rcont, 0);

	if (S_ISREG(inode->i_mode))
		rargs.type.id = REDIRFS_REG_FOP_OPEN;
	else if (S_ISDIR(inode->i_mode))
		rargs.type.id = REDIRFS_DIR_FOP_OPEN;
	else if (S_ISLNK(inode->i_mode))
		rargs.type.id = REDIRFS_LNK_FOP_OPEN;
	else if (S_ISCHR(inode->i_mode))
		rargs.type.id = REDIRFS_CHR_FOP_OPEN;
	else if (S_ISBLK(inode->i_mode))
		rargs.type.id = REDIRFS_BLK_FOP_OPEN;
	else if (S_ISFIFO(inode->i_mode))
		rargs.type.id = REDIRFS_FIFO_FOP_OPEN;

	rargs.args.f_open.inode = inode;
	rargs.args.f_open.file = file;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->fop_old && rinode->fop_old->open)
			rargs.rv.rv_int = rinode->fop_old->open(
					rargs.args.f_open.inode,
					rargs.args.f_open.file);
		else
			rargs.rv.rv_int = 0;
	}

	if (!rargs.rv.rv_int) {
		rfile = rfs_file_add(file);
		if (IS_ERR(rfile))
			BUG();
		rfs_file_put(rfile);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

static int rfs_release(struct inode *inode, struct file *file)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

	if (S_ISREG(inode->i_mode))
		rargs.type.id = REDIRFS_REG_FOP_RELEASE;
	else if (S_ISDIR(inode->i_mode))
		rargs.type.id = REDIRFS_DIR_FOP_RELEASE;
	else if (S_ISLNK(inode->i_mode))
		rargs.type.id = REDIRFS_LNK_FOP_RELEASE;
	else if (S_ISCHR(inode->i_mode))
		rargs.type.id = REDIRFS_CHR_FOP_RELEASE;
	else if (S_ISBLK(inode->i_mode))
		rargs.type.id = REDIRFS_BLK_FOP_RELEASE;
	else if (S_ISFIFO(inode->i_mode))
		rargs.type.id = REDIRFS_FIFO_FOP_RELEASE;

	rargs.args.f_release.inode = inode;
	rargs.args.f_release.file = file;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->release)
			rargs.rv.rv_int = rfile->op_old->release(
					rargs.args.f_release.inode,
					rargs.args.f_release.file);
		else
			rargs.rv.rv_int = 0;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_del(rfile);
	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

static int rfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	LIST_HEAD(sibs);
	struct rfs_dcache_entry *sib;
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct rfs_dentry *rdentry;
	struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(file->f_dentry->d_inode->i_mode))
		rargs.type.id = REDIRFS_DIR_FOP_READDIR;

	rargs.args.f_readdir.file = file;
	rargs.args.f_readdir.dirent = dirent;
	rargs.args.f_readdir.filldir = filldir;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->readdir) 
			rargs.rv.rv_int = rfile->op_old->readdir(
					rargs.args.f_readdir.file,
					rargs.args.f_readdir.dirent,
					rargs.args.f_readdir.filldir);
		else
			rargs.rv.rv_int = -ENOTDIR;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (rargs.rv.rv_int)
		goto exit;

	if (rfs_dcache_get_subs(file->f_dentry, &sibs)) {
		BUG();
		goto exit;
	}

	list_for_each_entry(sib, &sibs, list) {
		rdentry = rfs_dentry_find(sib->dentry);
		if (rdentry) {
			rfs_dentry_put(rdentry);
			continue;
		}

		if (!rinfo->rops) {
			if (!sib->dentry->d_inode)
				continue;

			if (!S_ISDIR(sib->dentry->d_inode->i_mode))
				continue;
		}

		if (rfs_dcache_rdentry_add(sib->dentry, rinfo)) {
			BUG();
			goto exit;
		}
	}

exit:
	rfs_dcache_entry_free_list(&sibs);
	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

static void rfs_file_set_ops_reg(struct rfs_file *rfile)
{
}

static void rfs_file_set_ops_dir(struct rfs_file *rfile)
{
	rfile->op_new.readdir = rfs_readdir;
}

static void rfs_file_set_ops_lnk(struct rfs_file *rfile)
{
}

static void rfs_file_set_ops_chr(struct rfs_file *rfile)
{
}

static void rfs_file_set_ops_blk(struct rfs_file *rfile)
{
}

static void rfs_file_set_ops_fifo(struct rfs_file *rfile)
{
}

void rfs_file_set_ops(struct rfs_file *rfile)
{
	umode_t mode;

	if (!rfile->rdentry->rinode)
		return;

	mode = rfile->rdentry->rinode->inode->i_mode;

	if (S_ISREG(mode))
		rfs_file_set_ops_reg(rfile);

	else if (S_ISDIR(mode))
		rfs_file_set_ops_dir(rfile);

	else if (S_ISLNK(mode))
		rfs_file_set_ops_lnk(rfile);

	else if (S_ISCHR(mode))
		rfs_file_set_ops_chr(rfile);

	else if (S_ISBLK(mode))
		rfs_file_set_ops_blk(rfile);

	else if (S_ISFIFO(mode))
		rfs_file_set_ops_fifo(rfile);

	rfile->op_new.release = rfs_release;
}

