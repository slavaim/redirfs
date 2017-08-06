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

static rfs_kmem_cache_t *rfs_dentry_cache = NULL;

static struct rfs_dentry *rfs_dentry_alloc(struct dentry *dentry)
{
	struct rfs_dentry *rdentry;

	rdentry = kmem_cache_zalloc(rfs_dentry_cache, GFP_KERNEL);
	if (!rdentry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rdentry->rinode_list);
	INIT_LIST_HEAD(&rdentry->rfiles);
	INIT_LIST_HEAD(&rdentry->data);
	rdentry->dentry = dentry;
	rdentry->op_old = dentry->d_op;
	spin_lock_init(&rdentry->lock);
	atomic_set(&rdentry->count, 1);

	if (dentry->d_op)
		memcpy(&rdentry->op_new, dentry->d_op,
				sizeof(struct dentry_operations));

	rdentry->op_new.d_iput = rfs_d_iput;

	return rdentry;
}

struct rfs_dentry *rfs_dentry_get(struct rfs_dentry *rdentry)
{
	if (!rdentry || IS_ERR(rdentry))
		return NULL;

	BUG_ON(!atomic_read(&rdentry->count));
	atomic_inc(&rdentry->count);

	return rdentry;
}

void rfs_dentry_put(struct rfs_dentry *rdentry)
{
	if (!rdentry || IS_ERR(rdentry))
		return;

	BUG_ON(!atomic_read(&rdentry->count));
	if (!atomic_dec_and_test(&rdentry->count))
		return;

	rfs_inode_put(rdentry->rinode);
	rfs_info_put(rdentry->rinfo);

	rfs_data_remove(&rdentry->data);
	kmem_cache_free(rfs_dentry_cache, rdentry);
}

struct rfs_dentry *rfs_dentry_add(struct dentry *dentry, struct rfs_info *rinfo)
{
	struct rfs_dentry *rd_new;
	struct rfs_dentry *rd;

	if (!dentry)
		return NULL;

	rd_new = rfs_dentry_alloc(dentry);
	if (IS_ERR(rd_new))
		return rd_new;

	spin_lock(&dentry->d_lock);

	rd = rfs_dentry_find(dentry);

	/*
	 * Workaround for the isofs_lookup function. It assigns
	 * dentry operations for the new dentry from the root dentry.
	 * This leads to the situation when one rdentry object can be
	 * found for more dentry objects.
	 *
	 * isofs_lookup: dentry->d_op = dir->i_sb->s_root->d_op;
	 */
	if (rd && (rd->dentry != dentry)) {
		rd_new->op_old = rd->op_old;
		rfs_dentry_put(rd);
		rd = NULL;
	}

	if (!rd) {
		rd_new->rinfo = rfs_info_get(rinfo);
		dentry->d_op = &rd_new->op_new;
		rfs_dentry_get(rd_new);
		rd = rfs_dentry_get(rd_new);
	}

	spin_unlock(&dentry->d_lock);

	rfs_dentry_put(rd_new);

	return rd;
}

void rfs_dentry_del(struct rfs_dentry *rdentry)
{
	rdentry->dentry->d_op = rdentry->op_old;
	rfs_dentry_put(rdentry);
}

int rfs_dentry_add_rinode(struct rfs_dentry *rdentry, struct rfs_info *rinfo)
{
	struct rfs_inode *rinode;

	if (!rdentry->dentry->d_inode)
		return 0;

	spin_lock(&rdentry->lock);
	if (rdentry->rinode) {
		spin_unlock(&rdentry->lock);
		return 0;
	}
	spin_unlock(&rdentry->lock);

	rinode = rfs_inode_add(rdentry->dentry->d_inode, rinfo);
	if (IS_ERR(rinode))
		return PTR_ERR(rinode);

	spin_lock(&rdentry->lock);
	if (rdentry->rinode) {
		spin_unlock(&rdentry->lock);
		rfs_inode_del(rinode);
		rfs_inode_put(rinode);
		return 0;
	}

	rdentry->rinode = rfs_inode_get(rinode);
	spin_unlock(&rdentry->lock);

	rfs_inode_add_rdentry(rinode, rdentry);
	rfs_inode_put(rinode);
	return 0;
}

void rfs_dentry_rem_rinode(struct rfs_dentry *rdentry)
{
	if (!rdentry->rinode)
		return;

	rfs_inode_rem_rdentry(rdentry->rinode, rdentry);
	rfs_inode_del(rdentry->rinode);
	rfs_inode_put(rdentry->rinode);
	rdentry->rinode = NULL;
}

struct rfs_info *rfs_dentry_get_rinfo(struct rfs_dentry *rdentry)
{
	struct rfs_info *rinfo;

	spin_lock(&rdentry->lock);
	rinfo = rfs_info_get(rdentry->rinfo);
	spin_unlock(&rdentry->lock);

	return rinfo;
}

void rfs_dentry_set_rinfo(struct rfs_dentry *rdentry, struct rfs_info *rinfo)
{
	spin_lock(&rdentry->lock);
	rfs_info_put(rdentry->rinfo);
	rdentry->rinfo = rfs_info_get(rinfo);
	spin_unlock(&rdentry->lock);
}

void rfs_dentry_add_rfile(struct rfs_dentry *rdentry, struct rfs_file *rfile)
{
	spin_lock(&rdentry->lock);
	list_add_tail(&rfile->rdentry_list, &rdentry->rfiles);
	spin_unlock(&rdentry->lock);
	rfs_file_get(rfile);
}

void rfs_dentry_rem_rfile(struct rfs_file *rfile)
{
	spin_lock(&rfile->rdentry->lock);
	list_del_init(&rfile->rdentry_list);
	spin_unlock(&rfile->rdentry->lock);
	rfs_file_put(rfile);
}

int rfs_dentry_cache_create(void)
{
	rfs_dentry_cache = rfs_kmem_cache_create("rfs_dentry_cache",
			sizeof(struct rfs_dentry));

	if (!rfs_dentry_cache)
		return -ENOMEM;

	return 0;
}

void rfs_dentry_cache_destory(void)
{
	kmem_cache_destroy(rfs_dentry_cache);
}

void rfs_d_iput(struct dentry *dentry, struct inode *inode)
{
	struct rfs_dentry *rdentry;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rdentry = rfs_dentry_find(dentry);
	rinfo = rfs_dentry_get_rinfo(rdentry);
	rfs_context_init(&rcont, 0);

	if (S_ISREG(inode->i_mode))
		rargs.type.id = REDIRFS_REG_DOP_D_IPUT;
	else if (S_ISDIR(inode->i_mode))
		rargs.type.id = REDIRFS_DIR_DOP_D_IPUT;
	else if (S_ISLNK(inode->i_mode))
		rargs.type.id = REDIRFS_LNK_DOP_D_IPUT;
	else if (S_ISCHR(inode->i_mode))
		rargs.type.id = REDIRFS_CHR_DOP_D_IPUT;
	else if (S_ISBLK(inode->i_mode))
		rargs.type.id = REDIRFS_BLK_DOP_D_IPUT;
	else if (S_ISFIFO(inode->i_mode))
		rargs.type.id = REDIRFS_FIFO_DOP_D_IPUT;
	else
		rargs.type.id = REDIRFS_SOCK_DOP_D_IPUT;

	rargs.args.d_iput.dentry = dentry;
	rargs.args.d_iput.inode = inode;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		BUG_ON(rfs_dcache_rinode_del(rdentry, inode));

		if (rdentry->op_old && rdentry->op_old->d_iput)
			rdentry->op_old->d_iput(rargs.args.d_iput.dentry,
					rargs.args.d_iput.inode);
		else
			iput(inode);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_dentry_put(rdentry);
	rfs_info_put(rinfo);
}

static void rfs_d_release(struct dentry *dentry)
{
	struct rfs_dentry *rdentry;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rdentry = rfs_dentry_find(dentry);
	rinfo = rfs_dentry_get_rinfo(rdentry);
	rfs_context_init(&rcont, 0);
	rargs.type.id = REDIRFS_NONE_DOP_D_RELEASE;
	rargs.args.d_release.dentry = dentry;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rdentry->op_old && rdentry->op_old->d_release)
			rdentry->op_old->d_release(rargs.args.d_release.dentry);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_dentry_del(rdentry);
	rfs_dentry_put(rdentry);
	rfs_info_put(rinfo);
}

static inline int rfs_d_compare_default(const struct qstr *name1,
		const struct qstr *name2)
{
	if (name1->len != name2->len)
		return 1;
	if (memcmp(name1->name, name2->name, name1->len))
		return 1;

	return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38))

static int rfs_d_compare(struct dentry *dentry, struct qstr *name1,
		struct qstr *name2)
{
	struct rfs_dentry *rdentry;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rdentry = rfs_dentry_find(dentry);
	rinfo = rfs_dentry_get_rinfo(rdentry);
	rfs_context_init(&rcont, 0);

	if (dentry->d_inode) {
		if (S_ISREG(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_REG_DOP_D_COMPARE;
		else if (S_ISDIR(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_DIR_DOP_D_COMPARE;
		else if (S_ISLNK(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_LNK_DOP_D_COMPARE;
		else if (S_ISCHR(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_CHR_DOP_D_COMPARE;
		else if (S_ISBLK(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_BLK_DOP_D_COMPARE;
		else if (S_ISFIFO(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_FIFO_DOP_D_COMPARE;
		else
			rargs.type.id = REDIRFS_SOCK_DOP_D_COMPARE;
	} else
		rargs.type.id = REDIRFS_NONE_DOP_D_COMPARE;

	rargs.args.d_compare.dentry = dentry;
	rargs.args.d_compare.name1 = name1;
	rargs.args.d_compare.name2 = name2;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rdentry->op_old && rdentry->op_old->d_compare)
			rargs.rv.rv_int = rdentry->op_old->d_compare(
					rargs.args.d_compare.dentry,
					rargs.args.d_compare.name1,
					rargs.args.d_compare.name2);
		else
			rargs.rv.rv_int = rfs_d_compare_default(
					rargs.args.d_compare.name1,
					rargs.args.d_compare.name2);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_dentry_put(rdentry);
	rfs_info_put(rinfo);

	return rargs.rv.rv_int;
}

#else

static int rfs_d_compare(const struct dentry *parent, const struct inode *inode,
		const struct dentry *dentry, const struct inode *d_inode,
		unsigned int tlen, const char *tname,
		const struct qstr *name)
{
	struct rfs_dentry *rdentry;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rdentry = rfs_dentry_find(dentry);
	rinfo = rfs_dentry_get_rinfo(rdentry);
	rfs_context_init(&rcont, 0);

	if (dentry->d_inode) {
		if (S_ISREG(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_REG_DOP_D_COMPARE;
		else if (S_ISDIR(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_DIR_DOP_D_COMPARE;
		else if (S_ISLNK(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_LNK_DOP_D_COMPARE;
		else if (S_ISCHR(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_CHR_DOP_D_COMPARE;
		else if (S_ISBLK(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_BLK_DOP_D_COMPARE;
		else if (S_ISFIFO(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_FIFO_DOP_D_COMPARE;
		else
			rargs.type.id = REDIRFS_SOCK_DOP_D_COMPARE;
	} else
		rargs.type.id = REDIRFS_NONE_DOP_D_COMPARE;

	rargs.args.d_compare.parent = parent;
	rargs.args.d_compare.inode = inode;
	rargs.args.d_compare.dentry = dentry;
	rargs.args.d_compare.d_inode = d_inode;
	rargs.args.d_compare.tlen = tlen;
	rargs.args.d_compare.tname = tname;
	rargs.args.d_compare.name = name;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rdentry->op_old && rdentry->op_old->d_compare)
			rargs.rv.rv_int = rdentry->op_old->d_compare(
					rargs.args.d_compare.parent,
					rargs.args.d_compare.inode,
					rargs.args.d_compare.dentry,
					rargs.args.d_compare.d_inode,
					rargs.args.d_compare.tlen,
					rargs.args.d_compare.tname,
					rargs.args.d_compare.name);
		else
			rargs.rv.rv_int = rfs_d_compare_default(
					&rargs.args.d_compare.dentry->d_name,
					rargs.args.d_compare.name);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_dentry_put(rdentry);
	rfs_info_put(rinfo);

	return rargs.rv.rv_int;
}

#endif

static int rfs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	struct rfs_dentry *rdentry;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rdentry = rfs_dentry_find(dentry);
	rinfo = rfs_dentry_get_rinfo(rdentry);
	rfs_context_init(&rcont, 0);

	if (dentry->d_inode) {
		if (S_ISREG(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_REG_DOP_D_REVALIDATE;
		else if (S_ISDIR(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_DIR_DOP_D_REVALIDATE;
		else if (S_ISLNK(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_LNK_DOP_D_REVALIDATE;
		else if (S_ISCHR(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_CHR_DOP_D_REVALIDATE;
		else if (S_ISBLK(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_BLK_DOP_D_REVALIDATE;
		else if (S_ISFIFO(dentry->d_inode->i_mode))
			rargs.type.id = REDIRFS_FIFO_DOP_D_REVALIDATE;
		else
			rargs.type.id = REDIRFS_SOCK_DOP_D_REVALIDATE;
	} else
		rargs.type.id = REDIRFS_NONE_DOP_D_REVALIDATE;

	rargs.args.d_revalidate.dentry = dentry;
	rargs.args.d_revalidate.nd = nd;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rdentry->op_old && rdentry->op_old->d_revalidate)
			rargs.rv.rv_int = rdentry->op_old->d_revalidate(
					rargs.args.d_revalidate.dentry,
					rargs.args.d_revalidate.nd);
		else
			rargs.rv.rv_int = 1;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_dentry_put(rdentry);
	rfs_info_put(rinfo);

	return rargs.rv.rv_int;
}

static void rfs_dentry_set_ops_none(struct rfs_dentry *rdentry)
{
	RFS_SET_DOP(rdentry, REDIRFS_NONE_DOP_D_COMPARE, d_compare);
	RFS_SET_DOP(rdentry, REDIRFS_NONE_DOP_D_REVALIDATE, d_revalidate);
}

static void rfs_dentry_set_ops_reg(struct rfs_dentry *rdentry)
{
	RFS_SET_DOP(rdentry, REDIRFS_REG_DOP_D_COMPARE, d_compare);
	RFS_SET_DOP(rdentry, REDIRFS_REG_DOP_D_REVALIDATE, d_revalidate);
}

static void rfs_dentry_set_ops_dir(struct rfs_dentry *rdentry)
{
	RFS_SET_DOP(rdentry, REDIRFS_DIR_DOP_D_COMPARE, d_compare);
	RFS_SET_DOP(rdentry, REDIRFS_DIR_DOP_D_REVALIDATE, d_revalidate);
}

static void rfs_dentry_set_ops_lnk(struct rfs_dentry *rdentry)
{
	RFS_SET_DOP(rdentry, REDIRFS_LNK_DOP_D_COMPARE, d_compare);
	RFS_SET_DOP(rdentry, REDIRFS_LNK_DOP_D_REVALIDATE, d_revalidate);
}

static void rfs_dentry_set_ops_chr(struct rfs_dentry *rdentry)
{
	RFS_SET_DOP(rdentry, REDIRFS_CHR_DOP_D_COMPARE, d_compare);
	RFS_SET_DOP(rdentry, REDIRFS_CHR_DOP_D_REVALIDATE, d_revalidate);
}

static void rfs_dentry_set_ops_blk(struct rfs_dentry *rdentry)
{
	RFS_SET_DOP(rdentry, REDIRFS_BLK_DOP_D_COMPARE, d_compare);
	RFS_SET_DOP(rdentry, REDIRFS_BLK_DOP_D_REVALIDATE, d_revalidate);
}

static void rfs_dentry_set_ops_fifo(struct rfs_dentry *rdentry)
{
	RFS_SET_DOP(rdentry, REDIRFS_FIFO_DOP_D_COMPARE, d_compare);
	RFS_SET_DOP(rdentry, REDIRFS_FIFO_DOP_D_REVALIDATE, d_revalidate);
}

static void rfs_dentry_set_ops_sock(struct rfs_dentry *rdentry)
{
	RFS_SET_DOP(rdentry, REDIRFS_SOCK_DOP_D_COMPARE, d_compare);
	RFS_SET_DOP(rdentry, REDIRFS_SOCK_DOP_D_REVALIDATE, d_revalidate);
}

void rfs_dentry_set_ops(struct rfs_dentry *rdentry)
{
	struct rfs_file *rfile;
	umode_t mode;

	spin_lock(&rdentry->lock);

	rdentry->op_new.d_release = rfs_d_release;

	if (!rdentry->rinode) {
		rfs_dentry_set_ops_none(rdentry);
		spin_unlock(&rdentry->lock);
		return;
	}

	list_for_each_entry(rfile, &rdentry->rfiles, rdentry_list) {
		rfs_file_set_ops(rfile);
	}

	mode = rdentry->rinode->inode->i_mode;

	if (S_ISREG(mode))
		rfs_dentry_set_ops_reg(rdentry);

	else if (S_ISDIR(mode))
		rfs_dentry_set_ops_dir(rdentry);

	else if (S_ISLNK(mode))
		rfs_dentry_set_ops_lnk(rdentry);

	else if (S_ISCHR(mode))
		rfs_dentry_set_ops_chr(rdentry);

	else if (S_ISBLK(mode))
		rfs_dentry_set_ops_blk(rdentry);

	else if (S_ISFIFO(mode))
		rfs_dentry_set_ops_fifo(rdentry);

	else if (S_ISSOCK(mode))
		rfs_dentry_set_ops_sock(rdentry);

	spin_unlock(&rdentry->lock);
	rfs_inode_set_ops(rdentry->rinode);
}

void rfs_dentry_rem_data(struct dentry *dentry, struct rfs_flt *rflt)
{
	struct redirfs_data *data;
	struct rfs_dentry *rdentry;
	struct rfs_file *rfile;
	
	data = redirfs_detach_data_dentry(rflt, dentry);
	if (data && data->detach)
		data->detach(data);
	redirfs_put_data(data);

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return;

	spin_lock(&rdentry->lock);

	list_for_each_entry(rfile, &rdentry->rfiles, rdentry_list) {
		data = redirfs_detach_data_file(rflt, rfile->file);
		if (data && data->detach)
			data->detach(data);
		redirfs_put_data(data);
	}

	spin_unlock(&rdentry->lock);

	if (!dentry->d_inode) {
		rfs_dentry_put(rdentry);
		return;
	}

	data = redirfs_detach_data_inode(rflt, dentry->d_inode);
	if (data && data->detach)
		data->detach(data);
	redirfs_put_data(data);

	rfs_dentry_put(rdentry);
}

int rfs_dentry_move(struct dentry *dentry, struct rfs_flt *rflt,
		struct rfs_root *src, struct rfs_root *dst)
{
	int rv = 0;

	if (!rflt->ops)
		return 0;

	if (rflt->ops->dentry_moved)
		rv = rflt->ops->dentry_moved(src, dst, dentry);

	if (rv)
		return rv;

	if (!dentry->d_inode)
		return 0;

	if (rflt->ops->inode_moved)
		rv = rflt->ops->inode_moved(src, dst, dentry->d_inode);

	return rv;
}

