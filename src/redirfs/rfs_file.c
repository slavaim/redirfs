/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * History:
 * 2017 - modified by by Slava Imameev
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
#include "rfs_file_ops.h"
#include "rfs_hooked_ops.h"

#ifdef RFS_DBG
    #pragma GCC push_options
    #pragma GCC optimize ("O0")
#endif // RFS_DBG

static void rfs_file_free(struct rfs_object *rfs_object);
static int rfs_release(struct inode *inode, struct file *file);

static rfs_kmem_cache_t *rfs_file_cache = NULL;

struct file_operations rfs_file_ops = {
    .open = rfs_open,
    .release = rfs_release,
};

static struct rfs_object_type rfs_file_type = {
    .type = RFS_TYPE_RFILE,
    .free = rfs_file_free,
    };

/*---------------------------------------------------------------------------*/

#ifdef RFS_USE_HASHTABLE

#define OBJ_TABLE_SIZE 257

static struct rfs_object_table_entry  file_entries[OBJ_TABLE_SIZE];

unsigned long rfs_file_index(unsigned long file)
{
    return ((((unsigned long)file) >> 5) % ARRAY_SIZE(file_entries));
}

/* common table not divided by object types, i.e. hosts any object */
static struct rfs_object_table rfs_file_table = {
    .index = rfs_file_index,
    .rfs_type = RFS_TYPE_RFILE,
    .array_size = ARRAY_SIZE(file_entries),
    .array = file_entries,
    };

#else

struct rfs_radix_tree   rfs_file_radix_tree = {
    .root = RADIX_TREE_INIT(GFP_KERNEL),
    .lock = __SPIN_LOCK_INITIALIZER(rfs_file_radix_tree.lock),
    .rfs_type = RFS_TYPE_RFILE,
    };
#endif

/*---------------------------------------------------------------------------*/

struct rfs_file* rfs_file_find(struct file *file)
{
    struct rfs_object   *rfs_object;
    struct rfs_file     *rfs_file;

#ifdef RFS_PER_OBJECT_OPS
    rfs_file = rfs_file_get(rfs_cast_to_rfile(file));
    if (rfs_file)
        return rfs_file;
#endif /* RFS_PER_OBJECT_OPS */

    /*
     * fallback to a slow path in presence of third party hookers
     */
#ifdef RFS_USE_HASHTABLE
    rfs_object = rfs_get_object_by_system_object(&rfs_file_table, file);
#else
    rfs_object = rfs_get_object_by_system_object(&rfs_file_radix_tree, file);
#endif
    if (!rfs_object)
        return NULL;

    rfs_file = container_of(rfs_object, struct rfs_file, rfs_object);
    return rfs_file;
}

static struct rfs_file *rfs_file_alloc(struct file *file)
{
	struct rfs_file *rfile;

	rfile = kmem_cache_zalloc(rfs_file_cache, GFP_KERNEL);
	if (!rfile)
        return ERR_PTR(-ENOMEM);
        
#ifdef RFS_DBG
    rfile->signature = RFS_FILE_SIGNATURE;
#endif // RFS_DBG

	INIT_LIST_HEAD(&rfile->rdentry_list);
	INIT_LIST_HEAD(&rfile->data);
	rfile->file = file;
	spin_lock_init(&rfile->lock);
    rfs_object_init(&rfile->rfs_object, &rfs_file_type, file);

    rfile->op_old = fops_get(file->f_op);
#ifdef RFS_PER_OBJECT_OPS
	if (rfile->op_old)
		memcpy(&rfile->op_new, rfile->op_old,
                sizeof(struct file_operations));
#endif /* RFS_PER_OBJECT_OPS  */

    rfile->rhops = rfs_create_file_ops(rfile);
    DBG_BUG_ON(!rfile->rhops);
    if (!rfile->rhops) {
        rfs_object_put(&rfile->rfs_object);
        return ERR_PTR(-ENOMEM);
    }

#ifdef RFS_PER_OBJECT_OPS 
    //
    // unconditionally register open operation to be notified
    // of open requests, some devices do not register open
    // operation, e.g. null_fops, but RedirFS requires
    // open operation to be called through file_operations.
    // Also, rfs_open hook is required for correct operation
    // of rfs_file_find macro.
    //
    rfile->op_new.open = rfs_open;
#endif /* RFS_PER_OBJECT_OPS */

	return rfile;
}

struct rfs_file *rfs_file_get(struct rfs_file *rfile)
{
	if (!rfile || IS_ERR(rfile))
		return NULL;

    DBG_BUG_ON(RFS_FILE_SIGNATURE != rfile->signature);
    rfs_object_get(&rfile->rfs_object);

	return rfile;
}

void rfs_file_put(struct rfs_file *rfile)
{
	if (!rfile || IS_ERR(rfile))
		return;

    DBG_BUG_ON(RFS_FILE_SIGNATURE != rfile->signature);
	rfs_object_put(&rfile->rfs_object);
}

/*---------------------------------------------------------------------------*/

static void rfs_file_free(struct rfs_object *rfs_object)
{
    struct rfs_file *rfile = container_of(rfs_object, struct rfs_file, rfs_object);

    DBG_BUG_ON(RFS_FILE_SIGNATURE != rfile->signature);

    rfs_dentry_put(rfile->rdentry);
    
    fops_put(rfile->op_old);

    rfs_data_remove(&rfile->data);

    if (rfile->rhops)
        rfs_object_put(&rfile->rhops->rfs_object);
        
	kmem_cache_free(rfs_file_cache, rfile);
}

static struct rfs_file *rfs_file_add(struct file *file)
{
	struct rfs_file *rfile;

	rfile = rfs_file_alloc(file);
	if (IS_ERR(rfile))
        return rfile;
        
    rfs_file_get(rfile);

	rfile->rdentry = rfs_dentry_find(file->f_dentry);
	rfs_dentry_add_rfile(rfile->rdentry, rfile);

    fops_put(file->f_op);
#ifdef RFS_PER_OBJECT_OPS 
    file->f_op = &rfile->op_new;
#else
    file->f_op = rfile->rhops->new.f_op;
#endif /* RFS_PER_OBJECT_OPS */
    
#ifdef RFS_USE_HASHTABLE
    rfs_insert_object(&rfs_file_table, &rfile->rfs_object, false);
#else
    rfs_insert_object(&rfs_file_radix_tree, &rfile->rfs_object, false);
#endif

	spin_lock(&rfile->rdentry->lock);
    {
	    rfs_file_set_ops(rfile);
    }
    spin_unlock(&rfile->rdentry->lock);
    
    rfs_keep_operations(rfile->rhops);

	return rfile;
}

static void rfs_file_del(struct rfs_file *rfile)
{
    rfs_dentry_rem_rfile(rfile);

#ifdef RFS_PER_OBJECT_OPS 
    rfile->file->f_op = fops_get(rfile->op_old);
#else
    if (rfile->rhops) {
        rfile->file->f_op = fops_get(rfile->rhops->old.f_op);
        rfs_unkeep_operations(rfile->rhops);
    }
#endif /* !RFS_PER_OBJECT_OPS */

    rfs_remove_object(&rfile->rfs_object);
	rfs_file_put(rfile);
}

int rfs_file_cache_create(void)
{
	rfs_file_cache = rfs_kmem_cache_create("rfs_file_cache",
			sizeof(struct rfs_file));

	if (!rfs_file_cache)
		return -ENOMEM;

#ifdef RFS_USE_HASHTABLE
    rfs_object_table_init(&rfs_file_table);
#endif

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
    else
        BUG();

	rargs.args.f_open.inode = inode;
	rargs.args.f_open.file = file;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        DBG_BUG_ON(rinode->fop_old && rinode->fop_old->open == rfs_open);
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

void rfs_add_dir_subs(struct rfs_file *rfile)
{
    LIST_HEAD(sibs);
    struct rfs_dentry *rdentry;
    struct rfs_dcache_entry *sib;
    struct rfs_info *rinfo;

    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);

	if (rfs_dcache_get_subs(rfile->file->f_dentry, &sibs)) {
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
    rfs_info_put(rinfo);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
static int rfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(file->f_dentry->d_inode->i_mode)) {
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

    } else {
        rargs.rv.rv_int = -ENOTDIR;
    }

	if (rargs.rv.rv_int)
		goto exit;

    rfs_add_dir_subs(rfile);

exit:
	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}
#endif

static void rfs_file_set_ops_reg(struct rfs_file *rfile)
{
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_LLSEEK, llseek, rfs_llseek);
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_READ, read, rfs_read);
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_WRITE, write, rfs_write);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,14,0))
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_READ_ITER, read_iter, rfs_read_iter);
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_WRITE_ITER, write_iter, rfs_write_iter);
#endif
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_POLL, poll, rfs_poll);
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_UNLOCKED_IOCTL, unlocked_ioctl, rfs_unlocked_ioctl);
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_COMPAT_IOCTL, compat_ioctl, rfs_compat_ioctl);
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_MMAP, mmap, rfs_mmap);
    /*
     * the open opeartion is called through rfile->op_new.open registered on inode lookup
     * then unconditionally set for file_operations and should not be removed as used as
     * a watermark for rfs_cast_to_rfile
     *
     * RFS_SET_FOP(rfile, REDIRFS_REG_FOP_OPEN, open, rfs_open);
     */
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_FLUSH, flush, rfs_flush);
    RFS_SET_FOP(rfile, REDIRFS_REG_FOP_FSYNC, fsync, rfs_fsync);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_fasync), fasync, rfs_fasync);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_lock), lock, rfs_lock);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_sendpage), sendpage, rfs_sendpage);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_get_unmapped_area), get_unmapped_area, rfs_get_unmapped_area);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_flock), flock, rfs_flock);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_splice_write), splice_write, rfs_splice_write);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_splice_read), splice_read, rfs_splice_read);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_setlease), setlease, rfs_setlease);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_fallocate), fallocate, rfs_fallocate);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_show_fdinfo), show_fdinfo, rfs_show_fdinfo);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_copy_file_range), copy_file_range, rfs_copy_file_range);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_clone_file_range), clone_file_range, rfs_clone_file_range);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_dedupe_file_range), dedupe_file_range, rfs_dedupe_file_range);
}

static void rfs_file_set_ops_dir(struct rfs_file *rfile)
{
#ifdef RFS_PER_OBJECT_OPS

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
	rfile->op_new.readdir = rfs_readdir;
#else
    rfile->op_new.iterate = rfs_iterate;
    rfile->op_new.iterate_shared = rfs_iterate_shared;
#endif

#else /* RFS_PER_OBJECT_OPS  */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
    if (rfile->rhops->new.f_op->readdir != rfs_readdir)
        rfile->rhops->new.f_op->readdir = rfs_readdir;
#else
    if (rfile->rhops->new.f_op->iterate != rfs_iterate)
        rfile->rhops->new.f_op->iterate = rfs_iterate;
    if (rfile->rhops->new.f_op->iterate_shared != rfs_iterate_shared)
        rfile->rhops->new.f_op->iterate_shared = rfs_iterate_shared;
#endif

#endif /* !RFS_PER_OBJECT_OPS  */
}

static void rfs_file_set_ops_lnk(struct rfs_file *rfile)
{
}

static void rfs_file_set_ops_chr(struct rfs_file *rfile)
{
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_llseek), llseek, rfs_llseek);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_read), read, rfs_read);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_write), write, rfs_write);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,14,0))
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_read_iter), read_iter, rfs_read_iter);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_write_iter), write_iter, rfs_write_iter);
#endif
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_poll), poll, rfs_poll);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_unlocked_ioctl), unlocked_ioctl, rfs_unlocked_ioctl);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_compat_ioctl), compat_ioctl, rfs_compat_ioctl);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_mmap), mmap, rfs_mmap);
    /*
     * the open opeartion is called through rfile->op_new.open registered on inode lookup
     * then unconditionally set for file_operations and should not be removed as used as
     * a watermark for rfs_cast_to_rfile
     *
     * RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_open), open, rfs_open);
     */
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_flush), flush, rfs_flush);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_fsync), fsync, rfs_fsync);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_fasync), fasync, rfs_fasync);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_lock), lock, rfs_lock);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_sendpage), sendpage, rfs_sendpage);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_get_unmapped_area), get_unmapped_area, rfs_get_unmapped_area);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_flock), flock, rfs_flock);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_splice_write), splice_write, rfs_splice_write);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_splice_read), splice_read, rfs_splice_read);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_setlease), setlease, rfs_setlease);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_fallocate), fallocate, rfs_fallocate);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_show_fdinfo), show_fdinfo, rfs_show_fdinfo);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_copy_file_range), copy_file_range, rfs_copy_file_range);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_clone_file_range), clone_file_range, rfs_clone_file_range);
    RFS_SET_FOP(rfile, RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_dedupe_file_range), dedupe_file_range, rfs_dedupe_file_range);
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

    DBG_BUG_ON(!rfile->rdentry->rinode);
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

    /* unconditionally set release hook to match open hooks */
#ifdef RFS_PER_OBJECT_OPS
    rfile->op_new.release = rfs_release;
#else
    if (rfile->rhops->new.f_op->release != rfs_release)
        rfile->rhops->new.f_op->release = rfs_release;
#endif /* !RFS_PER_OBJECT_OPS */
}

#ifdef RFS_DBG
    #pragma GCC pop_options
#endif // RFS_DBG
