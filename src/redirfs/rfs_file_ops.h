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

#ifndef _RFS_FILE_OPS_H
#define _RFS_FILE_OPS_H

#include "rfs.h"

#define FUNCTION_FOP_open PROTOTYPE_FOP(open, rfs_open)
#define FUNCTION_FOP_release PROTOTYPE_FOP(release, rfs_release)
#define FUNCTION_FOP_read PROTOTYPE_FOP(read, rfs_read)
#define FUNCTION_FOP_write PROTOTYPE_FOP(write, rfs_write)
#define FUNCTION_FOP_llseek PROTOTYPE_FOP(llseek, rfs_llseek)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,14,0))
    #define FUNCTION_FOP_read_iter PROTOTYPE_FOP(read_iter, rfs_read_iter)
    #define FUNCTION_FOP_write_iter PROTOTYPE_FOP(write_iter, rfs_write_iter)
#else
    #define FUNCTION_FOP_read_iter
    #define FUNCTION_FOP_write_iter
#endif
#define FUNCTION_FOP_poll PROTOTYPE_FOP(poll, rfs_poll)
#define FUNCTION_FOP_unlocked_ioctl PROTOTYPE_FOP(unlocked_ioctl, rfs_unlocked_ioctl)
#define FUNCTION_FOP_compat_ioctl PROTOTYPE_FOP(compat_ioctl, rfs_compat_ioctl)
#define FUNCTION_FOP_mmap PROTOTYPE_FOP(mmap, rfs_mmap)
#define FUNCTION_FOP_flush PROTOTYPE_FOP(flush, rfs_flush)
#define FUNCTION_FOP_fsync PROTOTYPE_FOP(fsync, rfs_fsync)
#define FUNCTION_FOP_fasync PROTOTYPE_FOP(fasync, rfs_fasync)
#define FUNCTION_FOP_lock PROTOTYPE_FOP(lock, rfs_lock)
#define FUNCTION_FOP_sendpage PROTOTYPE_FOP(sendpage, rfs_sendpage)
#define FUNCTION_FOP_get_unmapped_area PROTOTYPE_FOP(get_unmapped_area, rfs_get_unmapped_area)
#define FUNCTION_FOP_flock PROTOTYPE_FOP(flock, rfs_flock)
#define FUNCTION_FOP_splice_write PROTOTYPE_FOP(splice_write, rfs_splice_write)
#define FUNCTION_FOP_splice_read PROTOTYPE_FOP(splice_read, rfs_splice_read)
#define FUNCTION_FOP_setlease PROTOTYPE_FOP(setlease, rfs_setlease)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38))
    #define FUNCTION_FOP_fallocate PROTOTYPE_FOP(fallocate, rfs_fallocate)
#else
    #define FUNCTION_FOP_fallocate
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0))
    #define FUNCTION_FOP_show_fdinfo PROTOTYPE_FOP(show_fdinfo, rfs_show_fdinfo)
#else
    #define FUNCTION_FOP_show_fdinfo
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0))
    #define FUNCTION_FOP_copy_file_range PROTOTYPE_FOP(copy_file_range, rfs_copy_file_range)
    #define FUNCTION_FOP_clone_file_range PROTOTYPE_FOP(clone_file_range, rfs_clone_file_range)
    #define FUNCTION_FOP_dedupe_file_range PROTOTYPE_FOP(dedupe_file_range, rfs_dedupe_file_range)
#else
    #define FUNCTION_FOP_copy_file_range
    #define FUNCTION_FOP_clone_file_range
    #define FUNCTION_FOP_dedupe_file_range
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
#define FUNCTION_FOP_readdir PROTOTYPE_FOP(readdir, rfs_readdir)
#define FUNCTION_FOP_iterate
#else
#define FUNCTION_FOP_readdir
#define FUNCTION_FOP_iterate PROTOTYPE_FOP(iterate, rfs_iterate)
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0))
#define FUNCTION_FOP_iterate_shared PROTOTYPE_FOP(iterate_shared, rfs_iterate_shared)
#else
#define FUNCTION_FOP_iterate_shared
#endif

#ifdef RFS_PER_OBJECT_OPS 
/*
 * the open opeartion is called through rfile->op_new.open registered on inode lookup
 * then unconditionally set for file_operations and should not be removed as used as
 * a watermark for rfs_cast_to_rfile
 *
 * FUNCTION_FOP_open
 */
#endif

#define SET_FOP_REG \
    FUNCTION_FOP_read \
    FUNCTION_FOP_write \
    FUNCTION_FOP_llseek \
    FUNCTION_FOP_read_iter \
    FUNCTION_FOP_write_iter \
    FUNCTION_FOP_poll \
    FUNCTION_FOP_unlocked_ioctl \
    FUNCTION_FOP_compat_ioctl \
    FUNCTION_FOP_mmap \
    FUNCTION_FOP_flush \
    FUNCTION_FOP_fsync \
    FUNCTION_FOP_fasync \
    FUNCTION_FOP_lock \
    FUNCTION_FOP_sendpage \
    FUNCTION_FOP_get_unmapped_area \
    FUNCTION_FOP_flock \
    FUNCTION_FOP_splice_write \
    FUNCTION_FOP_splice_read \
    FUNCTION_FOP_setlease \
    FUNCTION_FOP_fallocate \
    FUNCTION_FOP_show_fdinfo \
    FUNCTION_FOP_copy_file_range \
    FUNCTION_FOP_clone_file_range \
    FUNCTION_FOP_dedupe_file_range \

#define SET_FOP_DIR \
    FUNCTION_FOP_readdir \
    FUNCTION_FOP_iterate \
    FUNCTION_FOP_iterate_shared \

#define SET_FOP_CHR \
    FUNCTION_FOP_read \
    FUNCTION_FOP_write \
    FUNCTION_FOP_llseek \
    FUNCTION_FOP_read_iter \
    FUNCTION_FOP_write_iter \
    FUNCTION_FOP_poll \
    FUNCTION_FOP_unlocked_ioctl \
    FUNCTION_FOP_compat_ioctl \
    FUNCTION_FOP_mmap \
    FUNCTION_FOP_flush \
    FUNCTION_FOP_fsync \
    FUNCTION_FOP_fasync \
    FUNCTION_FOP_lock \
    FUNCTION_FOP_sendpage \
    FUNCTION_FOP_get_unmapped_area \
    FUNCTION_FOP_flock \
    FUNCTION_FOP_splice_write \
    FUNCTION_FOP_splice_read \
    FUNCTION_FOP_setlease \
    FUNCTION_FOP_fallocate \
    FUNCTION_FOP_show_fdinfo \
    FUNCTION_FOP_copy_file_range \
    FUNCTION_FOP_clone_file_range \
    FUNCTION_FOP_dedupe_file_range \

loff_t rfs_llseek(struct file *file,
                  loff_t offset,
                  int origin);

ssize_t rfs_read(struct file *file,
                 char __user *buf,
                 size_t count,
                 loff_t *pos);

ssize_t rfs_write(struct file *file,
                  const char __user *buf,
                  size_t count,
                  loff_t *pos);

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 14, 0))
ssize_t rfs_read_iter(struct kiocb *kiocb,
                      struct iov_iter *iov_iter);

ssize_t rfs_write_iter(struct kiocb *kiocb,
                       struct iov_iter *iov_iter);
#endif

int rfs_iterate(struct file *file,
                struct dir_context *dir_context);

int rfs_iterate_shared(struct file *file,
                       struct dir_context *dir_context);

unsigned int rfs_poll(struct file *file,
                      struct poll_table_struct *poll_table_struct);

long rfs_unlocked_ioctl(struct file *file,
                        unsigned int cmd,
                        unsigned long arg);

long rfs_compat_ioctl(struct file *file,
                      unsigned int cmd,
                      unsigned long arg);

int rfs_mmap(struct file *file,
             struct vm_area_struct *vma);

int rfs_flush(struct file *,
              fl_owner_t owner);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
int rfs_fsync(struct file *file, struct dentry *dentry, int datasync);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0))
int rfs_fsync(struct file *file, int datasync);
#else
int rfs_fsync(struct file *file,
              loff_t start,
              loff_t end,
              int datasync);
#endif

int rfs_fasync(int fd,
               struct file *file,
               int on);

int rfs_lock(struct file *file,
             int cmd,
             struct file_lock *flock);

ssize_t rfs_sendpage(struct file *file,
                     struct page *page,
                     int offset,
                     size_t len,
                     loff_t *pos,
                     int more);

unsigned long rfs_get_unmapped_area(struct file *file,
                                    unsigned long addr,
                                    unsigned long len,
                                    unsigned long pgoff,
                                    unsigned long flags);

int rfs_flock(struct file *file,
              int cmd,
              struct file_lock *flock);

ssize_t rfs_splice_write(struct pipe_inode_info *pipe,
                         struct file *out,
                         loff_t *ppos,
                         size_t len,
                         unsigned int flags);

ssize_t rfs_splice_read(struct file *in,
                        loff_t *ppos,
                        struct pipe_inode_info *pipe,
                        size_t len,
                        unsigned int flags);
#if !(defined RH_KABI_DEPRECATE && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0))
int rfs_setlease(struct file *file, long arg, struct file_lock **flock);
#else
int rfs_setlease(struct file *file,
                 long arg,
                 struct file_lock **flock,
                 void **priv);
#endif
long rfs_fallocate(struct file *file,
                   int mode,
                   loff_t offset,
                   loff_t len);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0))
int rfs_show_fdinfo(struct seq_file *seq_file,
                    struct file *file);
#else
void rfs_show_fdinfo(struct seq_file *seq_file,
                     struct file *file);
#endif

ssize_t rfs_copy_file_range(struct file *file_in,
                            loff_t pos_in,
                            struct file *file_out,
                            loff_t pos_out,
                            size_t count,
                            unsigned int flags);

int rfs_clone_file_range(struct file *src_file,
                         loff_t src_off,
                         struct file *dst_file,
                         loff_t dst_off,
                         u64 count);

ssize_t rfs_dedupe_file_range(struct file *src_file,
                              u64 loff,
                              u64 len,
                              struct file *dst_file,
                              u64 dst_loff);

int rfs_release(struct inode *inode, struct file *file);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
int rfs_readdir(struct file *file, void *dirent, filldir_t filldir);
#endif

#endif // _RFS_FILE_OPS_H
