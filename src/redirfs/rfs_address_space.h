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

#ifndef _RFS_ADDRESS_SPACE_H
#define _RFS_ADDRESS_SPACE_H

#include "rfs.h"

int rfs_readpage(struct file *file,
                 struct page *page);

int rfs_readpages(struct file *file,
                  struct address_space *mapping,
                  struct list_head *pages,
                  unsigned int nr_pages);

int rfs_writepages(struct address_space *mapping,
                   struct writeback_control *wbc);

int rfs_set_page_dirty(struct page *page);

int rfs_write_begin(struct file *file,
                    struct address_space *mapping,
                    loff_t pos,
                    unsigned len,
                    unsigned flags,
                    struct page **pagep,
                    void **fsdata);

int rfs_write_end(struct file *file,
                  struct address_space *mapping,
                  loff_t pos,
                  unsigned len,
                  unsigned copied,
                  struct page *page,
                  void *fsdata);

sector_t rfs_bmap(struct address_space *mapping,
                  sector_t block);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
void rfs_invalidatepage(struct page *page, unsigned long offset);
#else
void rfs_invalidatepage(struct page *page,
                        unsigned int offset,
                        unsigned int length);
#endif

int rfs_releasepage(struct page *page,
                    gfp_t flags);

#endif // _RFS_ADDRESS_SPACE_H
