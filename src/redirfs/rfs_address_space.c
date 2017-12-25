/*
 * RedirFS: Redirecting File System
 *
 * Copyright 2017 Slava Imameev
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
#include <linux/mm.h>

#ifdef RFS_DBG
    #pragma GCC push_options
    #pragma GCC optimize ("O0")
#endif // RFS_DBG

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0))
#define page_mapping rfs_page_mapping
static struct address_space *rfs_page_mapping(struct page *page)
{
	struct address_space *mapping;

	page = compound_head(page);

	/* This happens if someone calls flush_dcache_page on slab page */
	if (unlikely(PageSlab(page)))
		return NULL;

	if (unlikely(PageSwapCache(page))) {
		//TODO
		return NULL;
		/*
		swp_entry_t entry;

		entry.val = page_private(page);
		return swap_address_space(entry);
		*/
	}

	mapping = page->mapping;
	if ((unsigned long)mapping & PAGE_MAPPING_FLAGS)
		return NULL;
	return mapping;
}
#endif //(LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0))

int rfs_readpage(struct file *file,
                 struct page *page)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_inode *rinode;
    struct rfs_context rcont;
    struct redirfs_args rargs;

    rfs_context_init(&rcont, 0);
    
    rfile = rfs_file_find(file);
    if (rfile) {
        rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
        rinode = rfs_inode_get(rfile->rdentry->rinode);
    } else {
        rinode = rfs_inode_find(file->f_inode);
        rinfo = rfs_inode_get_rinfo(rinode);
    }
    BUG_ON(!rinfo || !rinode);

    rargs.type.id = REDIRFS_REG_AOP_READPAGE;
    rargs.args.a_readpage.file = file;
    rargs.args.a_readpage.page = page;

    if (!RFS_IS_AOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->a_op_old && rinode->a_op_old->readpage) 
            rargs.rv.rv_int = rinode->a_op_old->readpage(
                    rargs.args.a_readpage.file,
                    rargs.args.a_readpage.page);
        else
            rargs.rv.rv_int = -EIO;
    }

    if (RFS_IS_AOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

int rfs_readpages(struct file *file,
                  struct address_space *mapping,
                  struct list_head *pages,
                  unsigned int nr_pages)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_inode *rinode;
    struct rfs_context rcont;
    struct redirfs_args rargs;

    rfs_context_init(&rcont, 0);

    rfile = rfs_file_find(file);
    if (rfile) {
        rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
        rinode = rfs_inode_get(rfile->rdentry->rinode);
    } else {
        rinode = rfs_inode_find(file->f_inode);
        rinfo = rfs_inode_get_rinfo(rinode);
    }
    BUG_ON(!rinfo || !rinode);

    rargs.type.id = REDIRFS_REG_AOP_READPAGES;
    rargs.args.a_readpages.file = file;
    rargs.args.a_readpages.mapping = mapping;
    rargs.args.a_readpages.pages = pages;
    rargs.args.a_readpages.nr_pages = nr_pages;

    if (!RFS_IS_AOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->a_op_old && rinode->a_op_old->readpages) 
            rargs.rv.rv_int = rinode->a_op_old->readpages(
                    rargs.args.a_readpages.file,
                    rargs.args.a_readpages.mapping,
                    rargs.args.a_readpages.pages,
                    rargs.args.a_readpages.nr_pages);
        else
            rargs.rv.rv_int = -EIO;
    }

    if (RFS_IS_AOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

int rfs_writepages(struct address_space *mapping,
                   struct writeback_control *wbc)
{
    struct rfs_info *rinfo;
    struct rfs_inode *rinode;
    struct rfs_context rcont;
    struct redirfs_args rargs;

    rinode = rfs_inode_find(mapping->host);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    BUG_ON(!rinfo);

    rargs.type.id = rfs_inode_to_idc(rinode->inode, RFS_OP_a_writepages);
    rargs.args.a_writepages.mapping = mapping;
    rargs.args.a_writepages.wbc = wbc;

    if (!RFS_IS_AOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->a_op_old && rinode->a_op_old->writepages) 
            rargs.rv.rv_int = rinode->a_op_old->writepages(
                    rargs.args.a_writepages.mapping,
                    rargs.args.a_writepages.wbc);
        else
            rargs.rv.rv_int = -EIO;
    }

    if (RFS_IS_AOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_info_put(rinfo);
    rfs_inode_put(rinode);
    return rargs.rv.rv_int;
}

int rfs_set_page_dirty(struct page *page)
{
    struct rfs_info *rinfo;
    struct rfs_inode *rinode;
    struct rfs_context rcont;
    struct redirfs_args rargs;
    struct address_space *mapping;
    
    mapping = page_mapping(page);

    WARN_ON(!mapping);
    if (unlikely(!mapping))
        return set_page_dirty(page);

    rinode = rfs_inode_find(mapping->host);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    BUG_ON(!rinfo);

    rargs.type.id = rfs_inode_to_idc(rinode->inode, RFS_OP_a_set_page_dirty);
    rargs.args.a_set_page_dirty.page = page;

    if (!RFS_IS_AOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->a_op_old && rinode->a_op_old->set_page_dirty) 
            rargs.rv.rv_int = rinode->a_op_old->set_page_dirty(
                    rargs.args.a_set_page_dirty.page);
        else
            rargs.rv.rv_int = -EIO;
    }

    if (RFS_IS_AOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_info_put(rinfo);
    rfs_inode_put(rinode);
    return rargs.rv.rv_int;
}

int rfs_write_begin(struct file *file,
                    struct address_space *mapping,
                    loff_t pos,
                    unsigned len,
                    unsigned flags,
                    struct page **pagep,
                    void **fsdata)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_inode *rinode;
    struct rfs_context rcont;
    struct redirfs_args rargs;

    rfs_context_init(&rcont, 0);

    rfile = rfs_file_find(file);
    if (rfile) {
        rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
        rinode = rfs_inode_get(rfile->rdentry->rinode);
    } else {
        rinode = rfs_inode_find(file->f_inode);
        rinfo = rfs_inode_get_rinfo(rinode);
    }
    BUG_ON(!rinfo || !rinode);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_a_write_begin);
    rargs.args.a_write_begin.file = file;
    rargs.args.a_write_begin.mapping = mapping;
    rargs.args.a_write_begin.pos = pos;
    rargs.args.a_write_begin.len = len;
    rargs.args.a_write_begin.flags = flags;
    rargs.args.a_write_begin.pagep = pagep;
    rargs.args.a_write_begin.fsdata = fsdata;

    if (!RFS_IS_AOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->a_op_old && rinode->a_op_old->write_begin) 
            rargs.rv.rv_int = rinode->a_op_old->write_begin(
                    rargs.args.a_write_begin.file,
                    rargs.args.a_write_begin.mapping,
                    rargs.args.a_write_begin.pos,
                    rargs.args.a_write_begin.len,
                    rargs.args.a_write_begin.flags,
                    rargs.args.a_write_begin.pagep,
                    rargs.args.a_write_begin.fsdata);
        else
            rargs.rv.rv_int = -EIO;
    }

    if (RFS_IS_AOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

int rfs_write_end(struct file *file,
                  struct address_space *mapping,
                  loff_t pos,
                  unsigned len,
                  unsigned copied,
                  struct page *page,
                  void *fsdata)
{
    struct rfs_file *rfile;
    struct rfs_info *rinfo;
    struct rfs_inode *rinode;
    struct rfs_context rcont;
    struct redirfs_args rargs;

    rfs_context_init(&rcont, 0);

    rfile = rfs_file_find(file);
    if (rfile) {
        rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
        rinode = rfs_inode_get(rfile->rdentry->rinode);
    } else {
        rinode = rfs_inode_find(file->f_inode);
        rinfo = rfs_inode_get_rinfo(rinode);
    }
    BUG_ON(!rinfo || !rinode);

    rargs.type.id = rfs_inode_to_idc(file->f_inode, RFS_OP_a_write_end);
    rargs.args.a_write_end.file = file;
    rargs.args.a_write_end.mapping = mapping;
    rargs.args.a_write_end.pos = pos;
    rargs.args.a_write_end.len = len;
    rargs.args.a_write_end.copied = copied;
    rargs.args.a_write_end.page = page;
    rargs.args.a_write_end.fsdata = fsdata;

    if (!RFS_IS_AOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->a_op_old && rinode->a_op_old->write_end) 
            rargs.rv.rv_int = rinode->a_op_old->write_end(
                    rargs.args.a_write_end.file,
                    rargs.args.a_write_end.mapping,
                    rargs.args.a_write_end.pos,
                    rargs.args.a_write_end.len,
                    rargs.args.a_write_end.copied,
                    rargs.args.a_write_end.page,
                    rargs.args.a_write_end.fsdata);
        else
            rargs.rv.rv_int = -EIO;
    }

    if (RFS_IS_AOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_file_put(rfile);
    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

sector_t rfs_bmap(struct address_space *mapping,
                  sector_t block)
{
    struct rfs_info *rinfo;
    struct rfs_inode *rinode;
    struct rfs_context rcont;
    struct redirfs_args rargs;

    rinode = rfs_inode_find(mapping->host);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    BUG_ON(!rinfo);

    rargs.type.id = rfs_inode_to_idc(rinode->inode, RFS_OP_a_bmap);
    rargs.args.a_bmap.mapping = mapping;
    rargs.args.a_bmap.block = block;

    if (!RFS_IS_AOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->a_op_old && rinode->a_op_old->bmap) 
            rargs.rv.rv_int = rinode->a_op_old->bmap(
                    rargs.args.a_bmap.mapping,
                    rargs.args.a_bmap.block);
        else
            rargs.rv.rv_int = -EIO;
    }

    if (RFS_IS_AOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_info_put(rinfo);
    rfs_inode_put(rinode);
    return rargs.rv.rv_int;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
void rfs_invalidatepage(struct page *page,
                        unsigned int offset)
{
    struct rfs_info *rinfo;
    struct rfs_inode *rinode;
    struct rfs_context rcont;
    struct redirfs_args rargs;
    struct address_space *mapping;

    mapping = page_mapping(page);

    WARN_ON(!mapping);
    if (unlikely(!mapping))
        return;

    rinode = rfs_inode_find(mapping->host);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    BUG_ON(!rinfo);

    rargs.type.id = rfs_inode_to_idc(rinode->inode, RFS_OP_a_invalidatepage);
    rargs.args.a_invalidatepage.page = page;
    rargs.args.a_invalidatepage.offset = offset;

    if (!RFS_IS_AOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->a_op_old && rinode->a_op_old->invalidatepage)
            rinode->a_op_old->invalidatepage(
                    rargs.args.a_invalidatepage.page,
                    rargs.args.a_invalidatepage.offset);
    }

    if (RFS_IS_AOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_info_put(rinfo);
    rfs_inode_put(rinode);
}

#else
void rfs_invalidatepage(struct page *page,
                        unsigned int offset,
                        unsigned int length)
{
    struct rfs_info *rinfo;
    struct rfs_inode *rinode;
    struct rfs_context rcont;
    struct redirfs_args rargs;
    struct address_space *mapping;

    mapping = page_mapping(page);

    WARN_ON(!mapping);
    if (unlikely(!mapping))
        return;

    rinode = rfs_inode_find(mapping->host);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    BUG_ON(!rinfo);

    rargs.type.id = rfs_inode_to_idc(rinode->inode, RFS_OP_a_invalidatepage);
    rargs.args.a_invalidatepage.page = page;
    rargs.args.a_invalidatepage.offset = offset;
    rargs.args.a_invalidatepage.length = length;

    if (!RFS_IS_AOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->a_op_old && rinode->a_op_old->invalidatepage)
            rinode->a_op_old->invalidatepage(
                    rargs.args.a_invalidatepage.page,
                    rargs.args.a_invalidatepage.offset,
                    rargs.args.a_invalidatepage.length);
    }

    if (RFS_IS_AOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_info_put(rinfo);
    rfs_inode_put(rinode);
}
#endif

int rfs_releasepage(struct page *page,
                    gfp_t flags)
{
    struct rfs_info *rinfo;
    struct rfs_inode *rinode;
    struct rfs_context rcont;
    struct redirfs_args rargs;
    struct address_space *mapping;
    
    mapping = page_mapping(page);

    WARN_ON(!mapping);
    if (unlikely(!mapping))
        return -EINVAL;

    rinode = rfs_inode_find(mapping->host);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    BUG_ON(!rinfo);

    rargs.type.id = rfs_inode_to_idc(rinode->inode, RFS_OP_a_releasepage);
    rargs.args.a_releasepage.page = page;
    rargs.args.a_releasepage.flags = flags;

    if (!RFS_IS_AOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->a_op_old && rinode->a_op_old->releasepage) 
            rargs.rv.rv_int = rinode->a_op_old->releasepage(
                    rargs.args.a_releasepage.page,
                    rargs.args.a_releasepage.flags);
            else
                rargs.rv.rv_int = -EIO;
    }

    if (RFS_IS_AOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_info_put(rinfo);
    rfs_inode_put(rinode);
    return rargs.rv.rv_int;
}

/*
    ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *);
    int (*migratepage)(struct address_space *, struct page *, struct page *, enum migrate_mode);
    bool (*isolate_page)(struct page *, isolate_mode_t);
    void (*putback_page)(struct page *);
    int (*launder_page)(struct page *);
    int (*is_partially_uptodate)(struct page *, unsigned long, unsigned long);
    void (*is_dirty_writeback)(struct page *, bool *, bool *);
    int (*error_remove_page)(struct address_space *, struct page *);
    int (*swap_activate)(struct swap_info_struct *, struct file *, sector_t *);
    void (*swap_deactivate)(struct file *);
*/
#ifdef RFS_DBG
    #pragma GCC pop_options
#endif // RFS_DBG
