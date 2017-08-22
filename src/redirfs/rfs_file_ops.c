/*
 * RedirFS: Redirecting File System
 * Copyright 2017 Slava Imameev
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

#ifdef DBG
    #pragma GCC push_options
    #pragma GCC optimize ("O0")
#endif // DBG

loff_t rfs_llseek(struct file *file, loff_t offset, int origin)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_llseek);
	rargs.args.f_llseek.file = file;
	rargs.args.f_llseek.offset = offset;
	rargs.args.f_llseek.origin = origin;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->llseek) 
			rargs.rv.rv_loff = rfile->op_old->llseek(
					rargs.args.f_llseek.file,
					rargs.args.f_llseek.offset,
					rargs.args.f_llseek.origin);
		else
			rargs.rv.rv_loff = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_loff;
}

ssize_t rfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_read);
	rargs.args.f_read.file = file;
	rargs.args.f_read.buf = buf;
	rargs.args.f_read.count = count;
    rargs.args.f_read.pos = pos;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->read) 
			rargs.rv.rv_ssize = rfile->op_old->read(
					rargs.args.f_read.file,
					rargs.args.f_read.buf,
					rargs.args.f_read.count,
                    rargs.args.f_read.pos);
		else
			rargs.rv.rv_ssize = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_ssize;
}

ssize_t rfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_write);
	rargs.args.f_write.file = file;
	rargs.args.f_write.buf = buf;
	rargs.args.f_write.count = count;
    rargs.args.f_write.pos = pos;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->write) 
			rargs.rv.rv_ssize = rfile->op_old->write(
					rargs.args.f_write.file,
					rargs.args.f_write.buf,
					rargs.args.f_write.count,
                    rargs.args.f_write.pos);
		else
			rargs.rv.rv_ssize = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_ssize;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,14,0))
ssize_t rfs_read_iter(struct kiocb *kiocb, struct iov_iter *iov_iter)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(kiocb->ki_filp);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(kiocb->ki_filp->f_inode, RFS_OP_f_read_iter);
	rargs.args.f_read_iter.kiocb = kiocb;
	rargs.args.f_read_iter.iov_iter = iov_iter;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->read_iter) 
			rargs.rv.rv_ssize = rfile->op_old->read_iter(
					rargs.args.f_read_iter.kiocb,
					rargs.args.f_read_iter.iov_iter);
		else
			rargs.rv.rv_ssize = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_ssize;
}

ssize_t rfs_write_iter(struct kiocb *kiocb, struct iov_iter *iov_iter)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(kiocb->ki_filp);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(kiocb->ki_filp->f_inode, RFS_OP_f_write_iter);
	rargs.args.f_write_iter.kiocb = kiocb;
	rargs.args.f_write_iter.iov_iter = iov_iter;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->write_iter) 
			rargs.rv.rv_ssize = rfile->op_old->write_iter(
					rargs.args.f_write_iter.kiocb,
					rargs.args.f_write_iter.iov_iter);
		else
			rargs.rv.rv_ssize = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_ssize;
}
#endif

int rfs_iterate(struct file *file, struct dir_context *dir_context)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

	rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_iterate);
	BUG_ON(rargs.type.id != REDIRFS_REG_FOP_DIR_ITERATE);

    rargs.type.id = REDIRFS_REG_FOP_DIR_ITERATE;
	rargs.args.f_iterate.file = file;
	rargs.args.f_iterate.dir_context = dir_context;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->iterate) 
			rargs.rv.rv_int = rfile->op_old->iterate(
					rargs.args.f_iterate.file,
					rargs.args.f_iterate.dir_context);
		else
			rargs.rv.rv_int = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

int rfs_iterate_shared(struct file *file, struct dir_context *dir_context)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

	rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_iterate_shared);
	BUG_ON(rargs.type.id != REDIRFS_REG_FOP_DIR_ITERATE_SHARED);

	rargs.args.f_iterate_shared.file = file;
	rargs.args.f_iterate_shared.dir_context = dir_context;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->iterate_shared) 
			rargs.rv.rv_int = rfile->op_old->iterate_shared(
					rargs.args.f_iterate_shared.file,
					rargs.args.f_iterate_shared.dir_context);
		else
			rargs.rv.rv_int = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

unsigned int rfs_poll(struct file *file, struct poll_table_struct *poll_table_struct)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_poll);
	rargs.args.f_poll.file = file;
	rargs.args.f_poll.poll_table_struct = poll_table_struct;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->poll) 
			rargs.rv.rv_int = rfile->op_old->poll(
					rargs.args.f_poll.file,
					rargs.args.f_poll.poll_table_struct);
		else
			rargs.rv.rv_int = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

long rfs_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_unlocked_ioctl);
	rargs.args.f_unlocked_ioctl.file = file;
	rargs.args.f_unlocked_ioctl.cmd = cmd;
    rargs.args.f_unlocked_ioctl.arg = arg;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->unlocked_ioctl) 
			rargs.rv.rv_long = rfile->op_old->unlocked_ioctl(
					rargs.args.f_unlocked_ioctl.file,
					rargs.args.f_unlocked_ioctl.cmd,
                    rargs.args.f_unlocked_ioctl.arg);
		else
			rargs.rv.rv_long = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_long;
}

long rfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_compat_ioctl);
	rargs.args.f_compat_ioctl.file = file;
	rargs.args.f_compat_ioctl.cmd = cmd;
    rargs.args.f_compat_ioctl.arg = arg;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->compat_ioctl) 
			rargs.rv.rv_long = rfile->op_old->compat_ioctl(
					rargs.args.f_compat_ioctl.file,
					rargs.args.f_compat_ioctl.cmd,
                    rargs.args.f_compat_ioctl.arg);
		else
			rargs.rv.rv_long = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_long;
}

int rfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_mmap);
	rargs.args.f_mmap.file = file;
	rargs.args.f_mmap.vma = vma;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->mmap) 
			rargs.rv.rv_int = rfile->op_old->mmap(
					rargs.args.f_mmap.file,
					rargs.args.f_mmap.vma);
		else
			rargs.rv.rv_int = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

int rfs_flush(struct file *file, fl_owner_t owner)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_flush);
	rargs.args.f_flush.file = file;
	rargs.args.f_flush.owner = owner;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->flush) 
			rargs.rv.rv_int = rfile->op_old->flush(
					rargs.args.f_flush.file,
					rargs.args.f_flush.owner);
		else
			rargs.rv.rv_int = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

int rfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_fsync);
	rargs.args.f_fsync.file = file;
	rargs.args.f_fsync.start = start;
    rargs.args.f_fsync.end = end;
    rargs.args.f_fsync.datasync = datasync;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->fsync) 
			rargs.rv.rv_int = rfile->op_old->fsync(
					rargs.args.f_fsync.file,
					rargs.args.f_fsync.start,
                    rargs.args.f_fsync.end,
                    rargs.args.f_fsync.datasync);
		else
			rargs.rv.rv_int = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

/*
    int (*fasync)(int, struct file *, int);
    int (*lock)(struct file *, int, struct file_lock *);
    ssize_t (*sendpage)(struct file *, struct page *, int, size_t, loff_t *, int);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    int (*check_flags)(int);
    int (*flock)(struct file *, int, struct file_lock *);
    ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
    int (*setlease)(struct file *, long, struct file_lock **, void **);
    long (*fallocate)(struct file *, int, loff_t, loff_t);
    void (*show_fdinfo)(struct seq_file *, struct file *);
    ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
    int (*clone_file_range)(struct file *, loff_t, struct file *, loff_t, u64);
    ssize_t (*dedupe_file_range)(struct file *, u64, u64, struct file *, u64);
*/

#ifdef DBG
    #pragma GCC pop_options
#endif // DBG