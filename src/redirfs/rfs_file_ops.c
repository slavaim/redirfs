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

#ifdef RFS_DBG
    #pragma GCC push_options
    #pragma GCC optimize ("O0")
#endif // RFS_DBG

/*---------------------------------------------------------------------------*/

loff_t rfs_llseek(struct file *file, loff_t offset, int origin)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_llseek);
    rargs.args.f_llseek.file = file;
    rargs.args.f_llseek.offset = offset;
    rargs.args.f_llseek.origin = origin;
    rargs.rv.rv_loff = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->llseek) 
            rargs.rv.rv_loff = rfile->op_old->llseek(
                    rargs.args.f_llseek.file,
                    rargs.args.f_llseek.offset,
                    rargs.args.f_llseek.origin);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_loff;
}

/*---------------------------------------------------------------------------*/

ssize_t rfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_read);
    rargs.args.f_read.file = file;
    rargs.args.f_read.buf = buf;
    rargs.args.f_read.count = count;
    rargs.args.f_read.pos = pos;
    rargs.rv.rv_ssize = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->read) 
            rargs.rv.rv_ssize = rfile->op_old->read(
                    rargs.args.f_read.file,
                    rargs.args.f_read.buf,
                    rargs.args.f_read.count,
                    rargs.args.f_read.pos);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_ssize;
}

/*---------------------------------------------------------------------------*/

ssize_t rfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_write);
    rargs.args.f_write.file = file;
    rargs.args.f_write.buf = buf;
    rargs.args.f_write.count = count;
    rargs.args.f_write.pos = pos;
    rargs.rv.rv_ssize = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->write) 
            rargs.rv.rv_ssize = rfile->op_old->write(
                    rargs.args.f_write.file,
                    rargs.args.f_write.buf,
                    rargs.args.f_write.count,
                    rargs.args.f_write.pos);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_ssize;
}

/*---------------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,14,0))
ssize_t rfs_read_iter(struct kiocb *kiocb, struct iov_iter *iov_iter)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(kiocb->ki_filp);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(kiocb->ki_filp->f_inode, RFS_OP_f_read_iter);
    rargs.args.f_read_iter.kiocb = kiocb;
    rargs.args.f_read_iter.iov_iter = iov_iter;
    rargs.rv.rv_ssize = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->read_iter) 
            rargs.rv.rv_ssize = rfile->op_old->read_iter(
                    rargs.args.f_read_iter.kiocb,
                    rargs.args.f_read_iter.iov_iter);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_ssize;
}

/*---------------------------------------------------------------------------*/

ssize_t rfs_write_iter(struct kiocb *kiocb, struct iov_iter *iov_iter)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(kiocb->ki_filp);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(kiocb->ki_filp->f_inode, RFS_OP_f_write_iter);
    rargs.args.f_write_iter.kiocb = kiocb;
    rargs.args.f_write_iter.iov_iter = iov_iter;
    rargs.rv.rv_ssize = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->write_iter) 
            rargs.rv.rv_ssize = rfile->op_old->write_iter(
                    rargs.args.f_write_iter.kiocb,
                    rargs.args.f_write_iter.iov_iter);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_ssize;
}
#endif

/*---------------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0))
int rfs_iterate(struct file *file, struct dir_context *dir_context)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);
    struct dentry *d_first = NULL;

    /* this optimization was borrowed from
       the Kaspersky's version of rfs filter */
    d_first = rfs_get_first_cached_dir_entry(file->f_dentry);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_iterate);
    BUG_ON(rargs.type.id != REDIRFS_REG_FOP_DIR_ITERATE);

    rargs.type.id = REDIRFS_REG_FOP_DIR_ITERATE;
    rargs.args.f_iterate.file = file;
    rargs.args.f_iterate.dir_context = dir_context;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->iterate) 
            rargs.rv.rv_int = rfile->op_old->iterate(
                    rargs.args.f_iterate.file,
                    rargs.args.f_iterate.dir_context);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    if (!rargs.rv.rv_int)
        rfs_add_dir_subs(rfile, d_first);

    dput(d_first);
    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}
#endif

/*---------------------------------------------------------------------------*/
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0))
int rfs_iterate_shared(struct file *file, struct dir_context *dir_context)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);
    struct dentry *d_first = NULL;

    /* this optimization was borrowed from
       the Kaspersky's version of rfs filter */
    d_first = rfs_get_first_cached_dir_entry(file->f_dentry);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_iterate_shared);
    BUG_ON(rargs.type.id != REDIRFS_REG_FOP_DIR_ITERATE_SHARED);

    rargs.args.f_iterate_shared.file = file;
    rargs.args.f_iterate_shared.dir_context = dir_context;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->iterate_shared) 
            rargs.rv.rv_int = rfile->op_old->iterate_shared(
                    rargs.args.f_iterate_shared.file,
                    rargs.args.f_iterate_shared.dir_context);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    if (!rargs.rv.rv_int)
        rfs_add_dir_subs(rfile, d_first);

    dput(d_first);
    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}
#endif
/*---------------------------------------------------------------------------*/

unsigned int rfs_poll(struct file *file, struct poll_table_struct *poll_table_struct)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_poll);
    rargs.args.f_poll.file = file;
    rargs.args.f_poll.poll_table_struct = poll_table_struct;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->poll) 
            rargs.rv.rv_int = rfile->op_old->poll(
                    rargs.args.f_poll.file,
                    rargs.args.f_poll.poll_table_struct);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

/*---------------------------------------------------------------------------*/

long rfs_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_unlocked_ioctl);
    rargs.args.f_unlocked_ioctl.file = file;
    rargs.args.f_unlocked_ioctl.cmd = cmd;
    rargs.args.f_unlocked_ioctl.arg = arg;
    rargs.rv.rv_long = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->unlocked_ioctl) 
            rargs.rv.rv_long = rfile->op_old->unlocked_ioctl(
                    rargs.args.f_unlocked_ioctl.file,
                    rargs.args.f_unlocked_ioctl.cmd,
                    rargs.args.f_unlocked_ioctl.arg);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_long;
}

/*---------------------------------------------------------------------------*/

long rfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_compat_ioctl);
    rargs.args.f_compat_ioctl.file = file;
    rargs.args.f_compat_ioctl.cmd = cmd;
    rargs.args.f_compat_ioctl.arg = arg;
    rargs.rv.rv_long = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->compat_ioctl) 
            rargs.rv.rv_long = rfile->op_old->compat_ioctl(
                    rargs.args.f_compat_ioctl.file,
                    rargs.args.f_compat_ioctl.cmd,
                    rargs.args.f_compat_ioctl.arg);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_long;
}

/*---------------------------------------------------------------------------*/

int rfs_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_mmap);
    rargs.args.f_mmap.file = file;
    rargs.args.f_mmap.vma = vma;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->mmap) 
            rargs.rv.rv_int = rfile->op_old->mmap(
                    rargs.args.f_mmap.file,
                    rargs.args.f_mmap.vma);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

/*---------------------------------------------------------------------------*/

int rfs_flush(struct file *file, fl_owner_t owner)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_flush);
    rargs.args.f_flush.file = file;
    rargs.args.f_flush.owner = owner;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->flush) 
            rargs.rv.rv_int = rfile->op_old->flush(
                    rargs.args.f_flush.file,
                    rargs.args.f_flush.owner);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

/*---------------------------------------------------------------------------*/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
int rfs_fsync(struct file *file, struct dentry *dentry, int datasync)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_fsync);
	rargs.args.f_fsync.file = file;
	rargs.args.f_fsync.dentry = dentry;
    rargs.args.f_fsync.datasync = datasync;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->fsync)
            rargs.rv.rv_int = rfile->op_old->fsync(
					rargs.args.f_fsync.file,
					rargs.args.f_fsync.dentry,
                    rargs.args.f_fsync.datasync);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0))
int rfs_fsync(struct file *file, int datasync)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_fsync);
    rargs.args.f_fsync.file = file;
    rargs.args.f_fsync.datasync = datasync;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->fsync)
            rargs.rv.rv_int = rfile->op_old->fsync(
                    rargs.args.f_fsync.file,
                    rargs.args.f_fsync.datasync);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}
#else
int rfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_fsync);
    rargs.args.f_fsync.file = file;
    rargs.args.f_fsync.start = start;
    rargs.args.f_fsync.end = end;
    rargs.args.f_fsync.datasync = datasync;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->fsync) 
            rargs.rv.rv_int = rfile->op_old->fsync(
                    rargs.args.f_fsync.file,
                    rargs.args.f_fsync.start,
                    rargs.args.f_fsync.end,
                    rargs.args.f_fsync.datasync);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}
#endif

/*---------------------------------------------------------------------------*/

 int rfs_fasync(int fd, struct file *file, int on)
 {
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_fasync);
    rargs.args.f_fasync.file = file;
    rargs.args.f_fasync.fd = fd;
    rargs.args.f_fasync.on = on;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->fasync) 
            rargs.rv.rv_int = rfile->op_old->fasync(
                    rargs.args.f_fasync.fd,
                    rargs.args.f_fasync.file,
                    rargs.args.f_fasync.on);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
 }

 /*---------------------------------------------------------------------------*/

 int rfs_lock(struct file *file, int cmd, struct file_lock *flock)
 {
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_lock);
    rargs.args.f_lock.file = file;
    rargs.args.f_lock.cmd = cmd;
    rargs.args.f_lock.flock = flock;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->lock) 
            rargs.rv.rv_int = rfile->op_old->lock(
                    rargs.args.f_lock.file,
                    rargs.args.f_lock.cmd,
                    rargs.args.f_lock.flock);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
 }

 /*---------------------------------------------------------------------------*/

ssize_t rfs_sendpage(struct file *file, struct page *page, int offset,
                     size_t len, loff_t *pos, int more)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_sendpage);
    rargs.args.f_sendpage.file = file;
    rargs.args.f_sendpage.page = page;
    rargs.args.f_sendpage.offset = offset;
    rargs.args.f_sendpage.len = len;
    rargs.args.f_sendpage.pos = pos;
    rargs.args.f_sendpage.more = more;
    rargs.rv.rv_ssize = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->sendpage) 
            rargs.rv.rv_ssize = rfile->op_old->sendpage(
                    rargs.args.f_sendpage.file,
                    rargs.args.f_sendpage.page,
                    rargs.args.f_sendpage.offset,
                    rargs.args.f_sendpage.len,
                    rargs.args.f_sendpage.pos,
                    rargs.args.f_sendpage.more);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_ssize;
}

/*---------------------------------------------------------------------------*/

unsigned long rfs_get_unmapped_area(struct file *file, unsigned long addr,
        unsigned long len, unsigned long pgoff, unsigned long flags)
 {
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_get_unmapped_area);
    rargs.args.f_get_unmapped_area.file = file;
    rargs.args.f_get_unmapped_area.addr = addr;
    rargs.args.f_get_unmapped_area.len = len;
    rargs.args.f_get_unmapped_area.pgoff = pgoff;
    rargs.args.f_get_unmapped_area.flags = flags;
    rargs.rv.rv_ulong = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->get_unmapped_area) 
            rargs.rv.rv_ulong = rfile->op_old->get_unmapped_area(
                    rargs.args.f_get_unmapped_area.file,
                    rargs.args.f_get_unmapped_area.addr,
                    rargs.args.f_get_unmapped_area.len,
                    rargs.args.f_get_unmapped_area.pgoff,
                    rargs.args.f_get_unmapped_area.flags);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_ulong;
 }

 /*---------------------------------------------------------------------------*/

int rfs_flock(struct file *file, int cmd, struct file_lock *flock)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_flock);
    rargs.args.f_flock.file = file;
    rargs.args.f_flock.cmd = cmd;
    rargs.args.f_flock.flock = flock;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->flock) 
            rargs.rv.rv_int = rfile->op_old->flock(
                    rargs.args.f_flock.file,
                    rargs.args.f_flock.cmd,
                    rargs.args.f_flock.flock);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
    
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

/*---------------------------------------------------------------------------*/

ssize_t rfs_splice_write(struct pipe_inode_info *pipe, struct file *out,
              loff_t *ppos, size_t len, unsigned int flags)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(out);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(out->f_inode, RFS_OP_f_splice_write);
    rargs.args.f_splice_write.pipe = pipe;
    rargs.args.f_splice_write.out = out;
    rargs.args.f_splice_write.ppos = ppos;
    rargs.args.f_splice_write.len = len;
    rargs.args.f_splice_write.flags = flags;
    rargs.rv.rv_ssize = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->splice_write) 
            rargs.rv.rv_ssize = rfile->op_old->splice_write(
                    rargs.args.f_splice_write.pipe,
                    rargs.args.f_splice_write.out,
                    rargs.args.f_splice_write.ppos,
                    rargs.args.f_splice_write.len,
                    rargs.args.f_splice_write.flags);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_ssize;
}

/*---------------------------------------------------------------------------*/

ssize_t rfs_splice_read(struct file *in, loff_t *ppos,
                 struct pipe_inode_info *pipe, size_t len,
                 unsigned int flags)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(in);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(in->f_inode, RFS_OP_f_splice_read);
    rargs.args.f_splice_read.in = in;
    rargs.args.f_splice_read.ppos = ppos;
    rargs.args.f_splice_read.pipe = pipe;
    rargs.args.f_splice_read.len = len;
    rargs.args.f_splice_read.flags = flags;
    rargs.rv.rv_ssize = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->splice_read) 
            rargs.rv.rv_ssize = rfile->op_old->splice_read(
                    rargs.args.f_splice_read.in,
                    rargs.args.f_splice_read.ppos,
                    rargs.args.f_splice_read.pipe,
                    rargs.args.f_splice_read.len,
                    rargs.args.f_splice_read.flags);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_ssize;
}

/*---------------------------------------------------------------------------*/
#if !(defined RH_KABI_DEPRECATE && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0))
int rfs_setlease(struct file *file, long arg, struct file_lock **flock)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_setlease);
    rargs.args.f_setlease.file = file;
    rargs.args.f_setlease.arg = arg;
    rargs.args.f_setlease.flock = flock;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->setlease)
            rargs.rv.rv_int = rfile->op_old->setlease(
                    rargs.args.f_setlease.file,
                    rargs.args.f_setlease.arg,
                    rargs.args.f_setlease.flock);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}
#else
int rfs_setlease(struct file *file, long arg, struct file_lock **flock,
          void **priv)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_setlease);
    rargs.args.f_setlease.file = file;
    rargs.args.f_setlease.arg = arg;
    rargs.args.f_setlease.flock = flock;
    rargs.args.f_setlease.priv = priv;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->setlease) 
            rargs.rv.rv_int = rfile->op_old->setlease(
                    rargs.args.f_setlease.file,
                    rargs.args.f_setlease.arg,
                    rargs.args.f_setlease.flock,
                    rargs.args.f_setlease.priv);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
    
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}
#endif

/*---------------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38))
long rfs_fallocate(struct file *file, int mode,
              loff_t offset, loff_t len)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_fallocate);
    rargs.args.f_fallocate.file = file;
    rargs.args.f_fallocate.mode = mode;
    rargs.args.f_fallocate.offset = offset;
    rargs.args.f_fallocate.len = len;
    rargs.rv.rv_long = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->fallocate) 
            rargs.rv.rv_long = rfile->op_old->fallocate(
                    rargs.args.f_fallocate.file,
                    rargs.args.f_fallocate.mode,
                    rargs.args.f_fallocate.offset,
                    rargs.args.f_fallocate.len);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
    
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_long;
}
#endif

/*---------------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0))
int rfs_show_fdinfo(struct seq_file *seq_file, struct file *file)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_show_fdinfo);
    rargs.args.f_show_fdinfo.seq_file = seq_file;
    rargs.args.f_show_fdinfo.file = file;
    rargs.rv.rv_int = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->show_fdinfo)
            rargs.rv.rv_int = rfile->op_old->show_fdinfo(
                    rargs.args.f_show_fdinfo.seq_file,
                    rargs.args.f_show_fdinfo.file);
    }

    rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}
#else
void rfs_show_fdinfo(struct seq_file *seq_file, struct file *file)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file);
    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_f_show_fdinfo);
    rargs.args.f_show_fdinfo.seq_file = seq_file;
    rargs.args.f_show_fdinfo.file = file;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->show_fdinfo) 
            rfile->op_old->show_fdinfo(
                    rargs.args.f_show_fdinfo.seq_file,
                    rargs.args.f_show_fdinfo.file);
    }

    rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
}
#endif //(LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0))
#endif //(LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0))

/*---------------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0))
ssize_t rfs_copy_file_range(struct file *file_in, loff_t pos_in,
                    struct file *file_out, loff_t pos_out,
                    size_t count, unsigned int flags)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(file_in);
    if (!rfile)
        rfile = rfs_file_find(file_out);

    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(file_in->f_inode, RFS_OP_f_copy_file_range);
    rargs.args.f_copy_file_range.file_in = file_in;
    rargs.args.f_copy_file_range.pos_in = pos_in;
    rargs.args.f_copy_file_range.file_out = file_out;
    rargs.args.f_copy_file_range.pos_out = pos_out;
    rargs.args.f_copy_file_range.count = count;
    rargs.args.f_copy_file_range.flags = flags;
    rargs.rv.rv_ssize = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->copy_file_range) 
            rargs.rv.rv_ssize = rfile->op_old->copy_file_range(
                    rargs.args.f_copy_file_range.file_in,
                    rargs.args.f_copy_file_range.pos_in,
                    rargs.args.f_copy_file_range.file_out,
                    rargs.args.f_copy_file_range.pos_out,
                    rargs.args.f_copy_file_range.count,
                    rargs.args.f_copy_file_range.flags);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_ssize;
}
#endif

/*---------------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0))
int rfs_clone_file_range(struct file *src_file, loff_t src_off,
        struct file *dst_file, loff_t dst_off, u64 count)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(src_file);
    if (!rfile)
        rfile = rfs_file_find(dst_file);

    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(src_file->f_inode, RFS_OP_f_clone_file_range);
    rargs.args.f_clone_file_range.src_file = src_file;
    rargs.args.f_clone_file_range.src_off = src_off;
    rargs.args.f_clone_file_range.dst_file = dst_file;
    rargs.args.f_clone_file_range.dst_off = dst_off;
    rargs.args.f_clone_file_range.count = count;
    rargs.rv.rv_int = -EIO;
    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->clone_file_range) 
            rargs.rv.rv_int = rfile->op_old->clone_file_range(
                    rargs.args.f_clone_file_range.src_file,
                    rargs.args.f_clone_file_range.src_off,
                    rargs.args.f_clone_file_range.dst_file,
                    rargs.args.f_clone_file_range.dst_off,
                    rargs.args.f_clone_file_range.count);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
    
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}
#endif

/*---------------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0))
ssize_t rfs_dedupe_file_range(struct file *src_file, u64 loff,
                    u64 len, struct file *dst_file, u64 dst_loff)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfile = rfs_file_find(src_file);
    if (!rfile)
        rfile = rfs_file_find(dst_file);

    rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
    rfs_context_init(&rcont, 0);

    rargs.type.id = rfs_inode_to_idc(src_file->f_inode, RFS_OP_f_dedupe_file_range);
    rargs.args.f_dedupe_file_range.src_file = src_file;
    rargs.args.f_dedupe_file_range.loff = loff;
    rargs.args.f_dedupe_file_range.len = len;
    rargs.args.f_dedupe_file_range.dst_file = dst_file;
    rargs.args.f_dedupe_file_range.dst_loff = dst_loff;
    rargs.rv.rv_ssize = -EIO;

    if (!RFS_IS_FOP_SET(rfile, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rfile->op_old && rfile->op_old->dedupe_file_range) 
            rargs.rv.rv_ssize = rfile->op_old->dedupe_file_range(
                    rargs.args.f_dedupe_file_range.src_file,
                    rargs.args.f_dedupe_file_range.loff,
                    rargs.args.f_dedupe_file_range.len,
                    rargs.args.f_dedupe_file_range.dst_file,
                    rargs.args.f_dedupe_file_range.dst_loff);
    }

    if (RFS_IS_FOP_SET(rfile, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
        
    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_info_put(rinfo);
    return rargs.rv.rv_ssize;
}
#endif

/*---------------------------------------------------------------------------*/

#ifdef RFS_DBG
    #pragma GCC pop_options
#endif // RFS_DBG
