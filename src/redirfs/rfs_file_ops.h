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

int rfs_fsync(struct file *file,
              loff_t start,
              loff_t end,
              int datasync);

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

int rfs_setlease(struct file *file,
                 long arg,
                 struct file_lock **flock,
                 void **priv);

long rfs_fallocate(struct file *file,
                   int mode,
                   loff_t offset,
                   loff_t len);

void rfs_show_fdinfo(struct seq_file *seq_file,
                     struct file *file);

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