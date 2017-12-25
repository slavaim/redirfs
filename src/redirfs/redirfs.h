/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
*
 * History:
 * 2017 - Slava Imameev made the following changes
 *        - modification for 4.x kernels
 *        - extended functionality
 *        - new operation IDs model
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

#ifndef _REDIRFS_H
#define _REDIRFS_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/types.h>
#include <linux/aio.h>
#include <linux/version.h>

#define REDIRFS_VERSION "0.13 EXPERIMENTAL"

#define REDIRFS_PATH_INCLUDE        1
#define REDIRFS_PATH_EXCLUDE        2

#define REDIRFS_FILTER_ATTRIBUTE(__name, __mode, __show, __store) \
    __ATTR(__name, __mode, __show, __store)

enum rfs_inode_type{

    /* dentry */
    RFS_INODE_DNONE, /* negative dentry */
    RFS_INODE_DSOCK, /* dentry for sock */
    RFS_INODE_DLINK, /* dentry for link */
    RFS_INODE_DREG,  /* dentry for dreg */
    RFS_INODE_DBULK,
    RFS_INODE_DDIR,
    RFS_INODE_DCHAR,
    RFS_INODE_DFIFO,

    /* inode */
    RFS_INODE_SOCK,
    RFS_INODE_LINK,
    RFS_INODE_REG,
    RFS_INODE_BULK,
    RFS_INODE_DIR,
    RFS_INODE_CHAR,
    RFS_INODE_FIFO,

    /* the last enum value, also stands for *any* */
    RFS_INODE_MAX
};

enum rfs_op_id {

    // dentry
    RFS_OP_d_start, /* start of the range */
    RFS_OP_d_revalidate,
    RFS_OP_d_weak_revalidate,
    RFS_OP_d_hash,
    RFS_OP_d_compare,
    RFS_OP_d_delete,
    RFS_OP_d_init,
    RFS_OP_d_release,
    RFS_OP_d_prune,
    RFS_OP_d_iput,
    RFS_OP_d_dname,
    RFS_OP_d_automount,
    RFS_OP_d_manage,
    RFS_OP_d_real,
    RFS_OP_d_end, /* end of the range */

    // inode
    RFS_OP_i_start, /* start of the range */
    RFS_OP_i_lookup,
    RFS_OP_i_get_link,
    RFS_OP_i_permission,
    RFS_OP_i_get_acl,
    RFS_OP_i_readlink,
    RFS_OP_i_create,
    RFS_OP_i_link,
    RFS_OP_i_unlink,
    RFS_OP_i_symlink,
    RFS_OP_i_mkdir,
    RFS_OP_i_rmdir,
    RFS_OP_i_mknod,
    RFS_OP_i_rename,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
    RFS_OP_i_rename2,
#endif
    RFS_OP_i_setattr,
    RFS_OP_i_getattr,
    RFS_OP_i_listxattr,
    RFS_OP_i_fiemap,
    RFS_OP_i_update_time,
    RFS_OP_i_atomic_open,
    RFS_OP_i_tmpfile,
    RFS_OP_i_set_acl,
    RFS_OP_i_end, /* end of the range */

    // file
    RFS_OP_f_start, /* start of the range */
    RFS_OP_f_llseek,
    RFS_OP_f_read,
    RFS_OP_f_write,
    RFS_OP_f_read_iter,
    RFS_OP_f_write_iter,
    RFS_OP_f_readdir, // old interface
    RFS_OP_f_iterate,
    RFS_OP_f_iterate_shared,
    RFS_OP_f_poll,
    RFS_OP_f_unlocked_ioctl,
    RFS_OP_f_compat_ioctl,
    RFS_OP_f_mmap,
    RFS_OP_f_open,
    RFS_OP_f_flush,
    RFS_OP_f_release,
    RFS_OP_f_fsync,
    RFS_OP_f_fasync,
    RFS_OP_f_lock,
    RFS_OP_f_sendpage,
    RFS_OP_f_get_unmapped_area,
    RFS_OP_f_check_flags,
    RFS_OP_f_flock,
    RFS_OP_f_splice_write,
    RFS_OP_f_splice_read,
    RFS_OP_f_setlease,
    RFS_OP_f_fallocate,
    RFS_OP_f_show_fdinfo,
    RFS_OP_f_copy_file_range,
    RFS_OP_f_clone_file_range,
    RFS_OP_f_dedupe_file_range,
    RFS_OP_f_end, /* end of the range */

    // address_space
    RFS_OP_a_start, /* start of the range */
    RFS_OP_a_writepage,
    RFS_OP_a_readpage,
    RFS_OP_a_writepages,
    RFS_OP_a_set_page_dirty,
    RFS_OP_a_readpages,
    RFS_OP_a_write_begin,
    RFS_OP_a_write_end,
    RFS_OP_a_bmap,
    RFS_OP_a_invalidatepage,
    RFS_OP_a_releasepage,
    //
    // RFS_OP_a_freepage hook can be installed only by a client
    // on its own risk as it is not possible to find original
    // operation from a page when the mapping field is NULL as
    // is the case for freepage
    //
    // RFS_OP_a_freepage,
    RFS_OP_a_direct_IO,
    RFS_OP_a_migratepage,
    RFS_OP_a_isolate_page,
    RFS_OP_a_putback_page,
    RFS_OP_a_launder_page,
    RFS_OP_a_is_partially_uptodate,
    RFS_OP_a_is_dirty_writeback,
    RFS_OP_a_error_remove_page,
    RFS_OP_a_swap_activate,
    RFS_OP_a_swap_deactivate,
    RFS_OP_a_end, /* end of the range */

    // the last entry
    RFS_OP_MAX
};

//
// IDC stands for "ID Combined"
//
#define  RFS_OP_IDC(itype, op_id) (itype<<16 | op_id)
#define  RFS_IDC_TO_ITYPE(idc) ((enum rfs_inode_type) (((idc) >> 16) & 0xFFFF))
#define  RFS_IDC_TO_OP_ID(idc) ((enum rfs_op_id) ((idc) & 0xFFFF))

//
// the new code should use RFS_OP_IDC macro instead of xtending
// the enum redirfs_op_idc type
//
enum redirfs_op_idc {
    REDIRFS_NONE_DOP_D_REVALIDATE = RFS_OP_IDC(RFS_INODE_DNONE, RFS_OP_d_revalidate),
    /* REDIRFS_NONE_DOP_D_HASH, */
    REDIRFS_NONE_DOP_D_COMPARE    = RFS_OP_IDC(RFS_INODE_DNONE, RFS_OP_d_compare),
    /* REDIRFS_NONE_DOP_D_DELETE, */
    REDIRFS_NONE_DOP_D_RELEASE    = RFS_OP_IDC(RFS_INODE_DNONE, RFS_OP_d_release),
    REDIRFS_NONE_DOP_D_IPUT       = RFS_OP_IDC(RFS_INODE_DNONE, RFS_OP_d_iput),
    /* REDIRFS_NODE_DOP_D_NAME, */

    REDIRFS_REG_DOP_D_REVALIDATE  = RFS_OP_IDC(RFS_INODE_DREG, RFS_OP_d_revalidate),
    /* REDIRFS_REG_DOP_D_HASH, */
    REDIRFS_REG_DOP_D_COMPARE     = RFS_OP_IDC(RFS_INODE_DREG, RFS_OP_d_compare),
    /* REDIRFS_REG_DOP_D_DELETE, */
    REDIRFS_REG_DOP_D_RELEASE     = RFS_OP_IDC(RFS_INODE_DREG, RFS_OP_d_release),
    REDIRFS_REG_DOP_D_IPUT        = RFS_OP_IDC(RFS_INODE_DREG, RFS_OP_d_iput),
    /* REDIRFS_REG_DOP_D_NAME, */

    REDIRFS_DIR_DOP_D_REVALIDATE  = RFS_OP_IDC(RFS_INODE_DDIR, RFS_OP_d_revalidate),
    /* REDIRFS_DIR_DOP_D_HASH, */
    REDIRFS_DIR_DOP_D_COMPARE     = RFS_OP_IDC(RFS_INODE_DDIR, RFS_OP_d_compare),
    /* REDIRFS_DIR_DOP_D_DELETE, */
    REDIRFS_DIR_DOP_D_RELEASE     = RFS_OP_IDC(RFS_INODE_DDIR, RFS_OP_d_release),
    REDIRFS_DIR_DOP_D_IPUT        = RFS_OP_IDC(RFS_INODE_DDIR, RFS_OP_d_iput),
    /* REDIRFS_DIR_DOP_D_NAME, */

    REDIRFS_CHR_DOP_D_REVALIDATE  = RFS_OP_IDC(RFS_INODE_DCHAR, RFS_OP_d_revalidate),
    /* REDIRFS_CHR_DOP_D_HASH, */
    REDIRFS_CHR_DOP_D_COMPARE     = RFS_OP_IDC(RFS_INODE_DCHAR, RFS_OP_d_compare),
    /* REDIRFS_CHR_DOP_D_DELETE, */
    REDIRFS_CHR_DOP_D_RELEASE     = RFS_OP_IDC(RFS_INODE_DCHAR, RFS_OP_d_release),
    REDIRFS_CHR_DOP_D_IPUT        = RFS_OP_IDC(RFS_INODE_DCHAR, RFS_OP_d_iput),
    /* REDIRFS_CHR_DOP_D_NAME, */

    REDIRFS_BLK_DOP_D_REVALIDATE  = RFS_OP_IDC(RFS_INODE_DBULK, RFS_OP_d_revalidate),
    /* REDIRFS_BLK_DOP_D_HASH, */
    REDIRFS_BLK_DOP_D_COMPARE     = RFS_OP_IDC(RFS_INODE_DBULK, RFS_OP_d_compare),
    /* REDIRFS_BLK_DOP_D_DELETE, */
    REDIRFS_BLK_DOP_D_RELEASE     = RFS_OP_IDC(RFS_INODE_DBULK, RFS_OP_d_release),
    REDIRFS_BLK_DOP_D_IPUT        = RFS_OP_IDC(RFS_INODE_DBULK, RFS_OP_d_iput),
    /* REDIRFS_BLK_DOP_D_NAME, */

    REDIRFS_FIFO_DOP_D_REVALIDATE = RFS_OP_IDC(RFS_INODE_DFIFO, RFS_OP_d_revalidate),
    /* REDIRFS_FIFO_DOP_D_HASH, */
    REDIRFS_FIFO_DOP_D_COMPARE    = RFS_OP_IDC(RFS_INODE_DFIFO, RFS_OP_d_compare),
    /* REDIRFS_FIFO_DOP_D_DELETE, */
    REDIRFS_FIFO_DOP_D_RELEASE    = RFS_OP_IDC(RFS_INODE_DFIFO, RFS_OP_d_release),
    REDIRFS_FIFO_DOP_D_IPUT       = RFS_OP_IDC(RFS_INODE_DFIFO, RFS_OP_d_iput),
    /* REDIRFS_FIFO_DOP_D_NAME, */

    REDIRFS_LNK_DOP_D_REVALIDATE  = RFS_OP_IDC(RFS_INODE_DLINK, RFS_OP_d_revalidate),
    /* REDIRFS_LNK_DOP_D_HASH, */
    REDIRFS_LNK_DOP_D_COMPARE     = RFS_OP_IDC(RFS_INODE_DLINK, RFS_OP_d_compare),
    /* REDIRFS_LNK_DOP_D_DELETE, */
    REDIRFS_LNK_DOP_D_RELEASE     = RFS_OP_IDC(RFS_INODE_DLINK, RFS_OP_d_release),
    REDIRFS_LNK_DOP_D_IPUT        = RFS_OP_IDC(RFS_INODE_DLINK, RFS_OP_d_iput),
    /* REDIRFS_LNK_DOP_D_NAME, */

    REDIRFS_SOCK_DOP_D_REVALIDATE = RFS_OP_IDC(RFS_INODE_DSOCK, RFS_OP_d_revalidate),
    /* REDIRFS_SOCK_DOP_D_HASH, */
    REDIRFS_SOCK_DOP_D_COMPARE    = RFS_OP_IDC(RFS_INODE_DSOCK, RFS_OP_d_compare),
    /* REDIRFS_SOCK_DOP_D_DELETE, */
    REDIRFS_SOCK_DOP_D_RELEASE    = RFS_OP_IDC(RFS_INODE_DSOCK, RFS_OP_d_release),
    REDIRFS_SOCK_DOP_D_IPUT       = RFS_OP_IDC(RFS_INODE_DSOCK, RFS_OP_d_iput),
    /* REDIRFS_SOCK_DOP_D_NAME, */

    REDIRFS_REG_IOP_PERMISSION   = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_i_permission),
    REDIRFS_REG_IOP_SETATTR      = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_i_setattr),

    REDIRFS_DIR_IOP_CREATE       = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_create),
    REDIRFS_DIR_IOP_LOOKUP       = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_lookup),
    REDIRFS_DIR_IOP_LINK         = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_link),
    REDIRFS_DIR_IOP_UNLINK       = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_unlink),
    REDIRFS_DIR_IOP_SYMLINK      = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_symlink), 
    REDIRFS_DIR_IOP_MKDIR        = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_mkdir),
    REDIRFS_DIR_IOP_RMDIR        = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_rmdir),
    REDIRFS_DIR_IOP_MKNOD        = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_mknod),
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
    REDIRFS_DIR_IOP_RENAME       = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_rename2),
#else
    REDIRFS_DIR_IOP_RENAME       = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_rename),
#endif
    REDIRFS_DIR_IOP_PERMISSION   = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_permission),
    REDIRFS_DIR_IOP_SETATTR      = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_i_setattr),

    REDIRFS_CHR_IOP_PERMISSION   = RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_i_permission),
    REDIRFS_CHR_IOP_SETATTR      = RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_i_setattr),

    REDIRFS_BLK_IOP_PERMISSION   = RFS_OP_IDC(RFS_INODE_BULK, RFS_OP_i_permission),
    REDIRFS_BLK_IOP_SETATTR      = RFS_OP_IDC(RFS_INODE_BULK, RFS_OP_i_setattr),

    REDIRFS_FIFO_IOP_PERMISSION  = RFS_OP_IDC(RFS_INODE_FIFO, RFS_OP_i_permission),
    REDIRFS_FIFO_IOP_SETATTR     = RFS_OP_IDC(RFS_INODE_FIFO, RFS_OP_i_setattr),

    REDIRFS_LNK_IOP_PERMISSION   = RFS_OP_IDC(RFS_INODE_LINK, RFS_OP_i_permission),
    REDIRFS_LNK_IOP_SETATTR      = RFS_OP_IDC(RFS_INODE_LINK, RFS_OP_i_setattr),

    REDIRFS_SOCK_IOP_PERMISSION  = RFS_OP_IDC(RFS_INODE_SOCK, RFS_OP_i_permission),
    REDIRFS_SOCK_IOP_SETATTR     = RFS_OP_IDC(RFS_INODE_SOCK, RFS_OP_i_setattr),

    REDIRFS_REG_FOP_OPEN         = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_open),
    REDIRFS_REG_FOP_RELEASE      = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_release),
    REDIRFS_REG_FOP_LLSEEK       = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_llseek),
    REDIRFS_REG_FOP_READ         = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_read),
    REDIRFS_REG_FOP_WRITE        = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_write),
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,14,0))
    REDIRFS_REG_FOP_READ_ITER    = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_read_iter),
    REDIRFS_REG_FOP_WRITE_ITER   = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_write_iter),
#endif
    REDIRFS_REG_FOP_POLL         = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_poll),
    REDIRFS_REG_FOP_UNLOCKED_IOCTL = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_unlocked_ioctl),
    REDIRFS_REG_FOP_COMPAT_IOCTL   = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_compat_ioctl),
    /* REDIRFS_REG_FOP_AIO_READ, */
    /* REDIRFS_REG_FOP_AIO_WRITE, */
    REDIRFS_REG_FOP_MMAP        = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_mmap),
    REDIRFS_REG_FOP_FLUSH       = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_flush),
    REDIRFS_REG_FOP_FSYNC       = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_f_fsync),

    REDIRFS_DIR_FOP_OPEN        = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_f_open),
    REDIRFS_DIR_FOP_RELEASE     = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_f_release),
    REDIRFS_DIR_FOP_READDIR     = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_f_readdir),
    REDIRFS_REG_FOP_DIR_ITERATE = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_f_iterate),
    REDIRFS_REG_FOP_DIR_ITERATE_SHARED = RFS_OP_IDC(RFS_INODE_DIR, RFS_OP_f_iterate_shared),
    /* REDIRFS_DIR_FOP_FLUSH, */

    REDIRFS_CHR_FOP_OPEN         = RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_open),
    REDIRFS_CHR_FOP_RELEASE      = RFS_OP_IDC(RFS_INODE_CHAR, RFS_OP_f_release),
    /* REDIRFS_CHR_FOP_LLSEEK, */
    /* REDIRFS_CHR_FOP_READ, */
    /* REDIRFS_CHR_FOP_WRITE, */
    /* REDIRFS_CHR_FOP_AIO_READ, */
    /* REDIRFS_CHR_FOP_AIO_WRITE, */
    /* REDIRFS_CHR_FOP_FLUSH, */

    REDIRFS_BLK_FOP_OPEN       = RFS_OP_IDC(RFS_INODE_BULK, RFS_OP_f_open),
    REDIRFS_BLK_FOP_RELEASE    = RFS_OP_IDC(RFS_INODE_BULK, RFS_OP_f_release),
    /* REDIRFS_BLK_FOP_LLSEEK, */
    /* REDIRFS_BLK_FOP_READ, */
    /* REDIRFS_BLK_FOP_WRITE, */
    /* REDIRFS_BLK_FOP_AIO_READ, */
    /* REDIRFS_BLK_FOP_AIO_WRITE, */
    /* REDIRFS_BLK_FOP_FLUSH, */

    REDIRFS_FIFO_FOP_OPEN      = RFS_OP_IDC(RFS_INODE_FIFO, RFS_OP_f_open),
    REDIRFS_FIFO_FOP_RELEASE   = RFS_OP_IDC(RFS_INODE_FIFO, RFS_OP_f_release),
    /* REDIRFS_FIFO_FOP_LLSEEK, */
    /* REDIRFS_FIFO_FOP_READ, */
    /* REDIRFS_FIFO_FOP_WRITE, */
    /* REDIRFS_FIFO_FOP_AIO_READ, */
    /* REDIRFS_FIFO_FOP_AIO_WRITE, */
    /* REDIRFS_FIFO_FOP_FLUSH, */

    REDIRFS_LNK_FOP_OPEN       = RFS_OP_IDC(RFS_INODE_LINK, RFS_OP_f_open),
    REDIRFS_LNK_FOP_RELEASE    = RFS_OP_IDC(RFS_INODE_LINK, RFS_OP_f_release),
    /* REDIRFS_LNK_FOP_LLSEEK, */
    /* REDIRFS_LNK_FOP_READ, */
    /* REDIRFS_LNK_FOP_WRITE, */
    /* REDIRFS_LNK_FOP_AIO_READ, */
    /* REDIRFS_LNK_FOP_AIO_WRITE, */
    /* REDIRFS_LNK_FOP_FLUSH, */

    REDIRFS_REG_AOP_READPAGE  = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_a_readpage),
    /* REDIRFS_REG_AOP_WRITEPAGE, */
    REDIRFS_REG_AOP_READPAGES = RFS_OP_IDC(RFS_INODE_REG, RFS_OP_a_readpages),
    /* REDIRFS_REG_AOP_WRITEPAGES, */
    /* REDIRFS_REG_AOP_SYNC_PAGE, */
    /* REDIRFS_REG_AOP_SET_PAGE_DIRTY, */
    /* REDIRFS_REG_AOP_PREPARE_WRITE, */
    /* REDIRFS_REG_AOP_COMMIT_WRITE, */
    /* REDIRFS_REG_AOP_BMAP, */
    /* REDIRFS_REG_AOP_INVALIDATEPAGE, */
    /* REDIRFS_REG_AOP_RELEASEPAGE, */
    /* REDIRFS_REG_AOP_DIRECT_IO, */
    /* REDIRFS_REG_AOP_GET_XIP_PAGE, */
    /* REDIRFS_REG_AOP_MIGRATEPAGE, */
    /* REDIRFS_REG_AOP_LAUNDER_PAGE, */

    REDIRFS_OP_MAX = RFS_OP_IDC(RFS_INODE_MAX, RFS_OP_MAX),
    REDIRFS_OP_END = (-1)
};

enum redirfs_op_call {
    REDIRFS_PRECALL,
    REDIRFS_POSTCALL
};

enum redirfs_rv {
    REDIRFS_STOP,
    REDIRFS_CONTINUE
};

typedef void *redirfs_filter;
typedef void *redirfs_context;
typedef void *redirfs_path;
typedef void *redirfs_root;

//
// a union for returned values
//
union redirfs_op_rv {
    int                 rv_int;
    unsigned int     rv_uint;
    unsigned long     rv_ulong;
    long             rv_long;
    loff_t             rv_loff;
    struct dentry    *rv_dentry;
    sector_t         rv_sector;
    struct page        *rv_page;
    ssize_t          rv_ssize;
};

union redirfs_op_args {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
    struct {
        struct dentry *dentry;
        struct nameidata *nd;
    } d_revalidate;
#else
    struct {
        struct dentry *dentry;
        unsigned int flags;
    } d_revalidate;
#endif

    /*
    struct {
        struct dentry *dentry;
        struct qstr *name;
    } d_hash;
    */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38))
    struct {
        struct dentry *dentry;
        struct qstr *name1;
        struct qstr *name2;
    } d_compare;
#elif !(defined RH_KABI_DEPRECATE && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
    struct {
        const struct dentry *parent;
        const struct inode *inode;
        const struct dentry *dentry;
        const struct inode *d_inode;
        unsigned int tlen;
        const char *tname;
        const struct qstr *name;
	} d_compare;
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0))
    struct {
        const struct dentry *parent;
        const struct dentry *dentry;
        unsigned int len;
        const char   *str;
        const struct qstr *name;
    } d_compare;
#else
    struct {
        const struct dentry *dentry;
        unsigned int len;
        const char   *str;
        const struct qstr *name;
    } d_compare;
#endif

    /*
    struct {
        struct dentry *dentry;
    } d_delete;
    */

    struct {
        struct dentry *dentry;
    } d_release;

    struct {
        struct dentry *dentry;
        struct inode *inode;
    } d_iput;    

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
    struct {
        struct inode *dir;
        struct dentry *dentry;
        int mode;
        struct nameidata *nd;
    } i_create;

    struct {
        struct inode *dir;
        struct dentry *dentry;
        struct nameidata *nd;
    } i_lookup;
#else
    struct {
        struct inode *dir;
        struct dentry *dentry;
        umode_t mode;
        bool excl;
    } i_create;

    struct {
        struct inode *dir;
        struct dentry *dentry;
        unsigned int flags;
    } i_lookup;
#endif

    struct {
        struct dentry *old_dentry;
        struct inode *dir;
        struct dentry *dentry;
    } i_link;

    struct {
        struct inode *dir;
        struct dentry *dentry;
    } i_unlink;

    struct {
        struct inode *dir;
        struct dentry *dentry;
        const char *oldname;
    } i_symlink;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
    struct {
        struct inode *dir;
        struct dentry *dentry;
        int mode;
    } i_mkdir;
#else
    struct {
        struct inode *dir;
        struct dentry *dentry;
        umode_t mode;
    } i_mkdir;
#endif

    struct {
        struct inode *dir;
        struct dentry *dentry;
    } i_rmdir;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
    struct {
        struct inode *dir;
        struct dentry *dentry;
        int mode;
        dev_t rdev;
    } i_mknod;
#else
    struct {
        struct inode *dir;
        struct dentry *dentry;
        umode_t mode;
        dev_t rdev;
    } i_mknod;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0))
    struct {
        struct inode *old_dir;
        struct dentry *old_dentry;
        struct inode *new_dir;
        struct dentry *new_dentry;
    } i_rename;
#else
    struct {
        struct inode *old_dir;
        struct dentry *old_dentry;
        struct inode *new_dir;
        struct dentry *new_dentry;
        unsigned int flags;
    } i_rename;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
    struct {
        struct inode *inode;
        int mask;
        struct nameidata *nd;
    } i_permission;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
    struct {
        struct inode *inode;
        int mask;
    } i_permission;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
    struct {
        struct inode *inode;
        int mask;
        unsigned int flags;
    } i_permission;
#else
    struct {
        struct inode *inode;
        int mask;
    } i_permission;
#endif

    struct {
        struct dentry *dentry;
        struct iattr *iattr;
    } i_setattr;

    struct {
        struct inode *inode;
        struct file *file;
    } f_open;

    struct {
        struct inode *inode;
        struct file *file;
    } f_release;

    struct {
        struct file *file;
        fl_owner_t  owner;
    } f_flush;

    struct {
        struct file *file;
        struct vm_area_struct *vma;
    } f_mmap;

    struct {
        struct file *file;
        void *dirent;
        filldir_t filldir;
    } f_readdir;

    struct {
        struct file *file;
        loff_t offset;
        int origin;
    } f_llseek;

    struct {
        struct file *file;
        char __user *buf;
        size_t count;
        loff_t *pos;
    } f_read;

    struct {
        struct file *file;
        const char __user *buf;
        size_t count;
        loff_t *pos;
    } f_write;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,14,0))
    struct {
        struct kiocb *kiocb;
        struct iov_iter *iov_iter;
    } f_read_iter;

    struct {
        struct kiocb *kiocb;
        struct iov_iter *iov_iter;
    } f_write_iter;
#endif

    struct {
        struct file *file;
        struct dir_context *dir_context;
    } f_iterate;

    struct {
        struct file *file;
        struct dir_context *dir_context;
    } f_iterate_shared;

    struct {
        struct file *file;
        struct poll_table_struct *poll_table_struct;
    } f_poll;

    struct {
        struct file *file;
        unsigned int cmd;
        unsigned long arg;
    } f_unlocked_ioctl;

    struct {
        struct file *file;
        unsigned int cmd;
        unsigned long arg;
    } f_compat_ioctl;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
    struct {
		struct file *file;
		struct dentry *dentry;
        int datasync;
    } f_fsync;
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0))
    struct {
		struct file *file;
        int datasync;
    } f_fsync;
#else
    struct {
        struct file *file;
        loff_t start;
        loff_t end;
        int datasync;
    } f_fsync;
#endif

    struct {
        int fd;
        struct file *file;
        int on;
    } f_fasync;

    struct {
        struct file *file;
        int cmd;
        struct file_lock *flock;
    } f_lock;

    struct {
        struct file *file;
        struct page *page;
        int offset;
        size_t len;
        loff_t *pos;
        int more;
    } f_sendpage;

    struct {
        struct file *file;
        unsigned long addr;
        unsigned long len;
        unsigned long pgoff;
        unsigned long flags;
    } f_get_unmapped_area;

    struct {
        struct file *file;
        int cmd;
        struct file_lock *flock;
    } f_flock;

    struct {
        struct pipe_inode_info *pipe;
        struct file *out;
        loff_t *ppos;
        size_t len;
        unsigned int flags;
    } f_splice_write;

    struct {
        struct file *in;
        loff_t *ppos;
        struct pipe_inode_info *pipe;
        size_t len;
        unsigned int flags;
    } f_splice_read;

#if !(defined RH_KABI_DEPRECATE && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0))
    struct {
        struct file *file;
        long arg;
        struct file_lock **flock;
    } f_setlease;
#else
    struct {
        struct file *file;
        long arg;
        struct file_lock **flock;
        void **priv;
    } f_setlease;
#endif

    struct {
        struct file *file;
        int mode;
        loff_t offset;
        loff_t len;
    } f_fallocate;

    struct {
        struct seq_file *seq_file;
        struct file *file;
    } f_show_fdinfo;

    struct {
        struct file *file_in;
        loff_t pos_in;
        struct file *file_out;
        loff_t pos_out;
        size_t count;
        unsigned int flags;
    } f_copy_file_range;

    struct {
        struct file *src_file;
        loff_t src_off;
        struct file *dst_file;
        loff_t dst_off;
        u64 count;
    } f_clone_file_range;

    struct {
        struct file *src_file;
        u64 loff;
        u64 len;
        struct file *dst_file;
        u64 dst_loff;
    } f_dedupe_file_range;

    /*
    struct {
        struct kiocb *iocb;
        const struct iovec *iov;
        unsigned long nr_segs;
        loff_t pos;
    } f_aio_read;
    */

    /*
    struct {
        struct kiocb *iocb;
        const struct iovec *iov;
        unsigned long nr_segs;
        loff_t pos;
    } f_aio_write;
    */

    struct {
        struct file *file;
        struct page *page;
    } a_readpage;

    /*
    struct {
        struct page *page;
        struct writeback_control *wbc;
    } a_writepage;
    */

    struct {
        struct file *file;
        struct address_space *mapping;
        struct list_head *pages;
        unsigned nr_pages;
    } a_readpages;

    struct {
        struct address_space *mapping;
        struct writeback_control *wbc;
    } a_writepages;

    struct {
        struct page *page;
    } a_set_page_dirty;

    struct {
        struct file *file;
        struct address_space *mapping;
        loff_t pos;
        unsigned len;
        unsigned flags;
        struct page **pagep;
        void **fsdata;
    } a_write_begin;

    struct {
        struct file *file;
        struct address_space *mapping;
        loff_t pos;
        unsigned len;
        unsigned copied;
        struct page *page;
        void *fsdata;
    } a_write_end;

    struct {
        struct address_space *mapping;
        sector_t block;
    } a_bmap;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
    struct {
        struct page *page;
        unsigned int offset;
    } a_invalidatepage;
#else
    struct {
        struct page *page;
        unsigned int offset;
        unsigned int length;
    } a_invalidatepage;
#endif

    struct {
        struct page *page;
        gfp_t flags;
    } a_releasepage;

    struct {
        struct page *page;
    } a_freepage;

    /*
    struct {
        struct page *page;
    } a_sync_page;
    */

    /*
    struct {
        struct page *page;
    } a_set_page_dirty;
    */

    /*
    struct {
        struct file *file;
        struct page *page;
        unsigned from;
        unsigned to;
    } a_prepare_write;
    */

    /*
    struct {
        struct file *file;
        struct page *page;
        unsigned from;
        unsigned to;
    } a_commit_write;
    */

    /*
    struct {
        int rw;
        struct kiocb *iocb;
        const struct iovec *iov;
        loff_t offset;
        unsigned long nr_segs;
    } a_direct_IO;
    */

    /*
    struct {
        struct address_space *mapping;
        sector_t offset;
        int create;
    } a_get_xip_page;
    */

    /*
    struct {
        struct address_space *mapping;
        struct page *newpage;
        struct page *page;
    } a_migratepage;
    */

    /*
    struct {
        struct page *page;
    } a_launder_page;
    */
};

struct redirfs_op_type {
    enum redirfs_op_idc id;
    enum redirfs_op_call call;
};

struct redirfs_args {
    union redirfs_op_args args;
    union redirfs_op_rv rv;
    struct redirfs_op_type type;
};

struct redirfs_path_info {
    struct dentry *dentry;
    struct vfsmount *mnt;
    int flags;
};

struct redirfs_op_info {
    enum redirfs_op_idc op_id;
    enum redirfs_rv (*pre_cb)(redirfs_context, struct redirfs_args *);
    enum redirfs_rv (*post_cb)(redirfs_context, struct redirfs_args *);
};

struct redirfs_filter_operations {
    int (*activate)(void);
    int (*deactivate)(void);
    int (*add_path)(struct redirfs_path_info *);
    int (*rem_path)(redirfs_path);
    int (*unregister)(void);
    int (*rem_paths)(void);
    void (*move_begin)(void);
    void (*move_end)(void);
    int (*dentry_moved)(redirfs_root, redirfs_root, struct dentry *);
    int (*inode_moved)(redirfs_root, redirfs_root, struct inode *);
    enum redirfs_rv (*pre_rename)(redirfs_context, struct redirfs_args *);
    enum redirfs_rv (*post_rename)(redirfs_context, struct redirfs_args *);
};

struct redirfs_filter_info {
    struct module *owner;
    const char *name;
    int priority;
    int active;
    struct redirfs_filter_operations *ops;
};

struct redirfs_filter_attribute {
    struct attribute attr;
    ssize_t (*show)(redirfs_filter filter,
            struct redirfs_filter_attribute *attr, char *buf);
    ssize_t (*store)(redirfs_filter filter,
            struct redirfs_filter_attribute *attr, const char *buf,
            size_t count);
};

struct redirfs_data {
    struct list_head list;
    atomic_t cnt;
    redirfs_filter filter;
    void (*free)(struct redirfs_data *);
    void (*detach)(struct redirfs_data *);
};

int redirfs_create_attribute(redirfs_filter filter,
        struct redirfs_filter_attribute *attr);
int redirfs_remove_attribute(redirfs_filter filter,
        struct redirfs_filter_attribute *attr);
struct kobject *redirfs_filter_kobject(redirfs_filter filter);
redirfs_path redirfs_add_path(redirfs_filter filter,
        struct redirfs_path_info *info);
int redirfs_rem_path(redirfs_filter filter, redirfs_path path);
int redirfs_get_id_path(redirfs_path path);
redirfs_path redirfs_get_path_id(int id);
redirfs_path redirfs_get_path(redirfs_path path);
void redirfs_put_path(redirfs_path path);
redirfs_path* redirfs_get_paths_root(redirfs_filter filter, redirfs_root root);
redirfs_path* redirfs_get_paths(redirfs_filter filter);
void redirfs_put_paths(redirfs_path *paths);
struct redirfs_path_info *redirfs_get_path_info(redirfs_filter filter,
        redirfs_path path);
void redirfs_put_path_info(struct redirfs_path_info *info);
int redirfs_rem_paths(redirfs_filter filter);
redirfs_root redirfs_get_root_file(redirfs_filter filter, struct file *file);
redirfs_root redirfs_get_root_dentry(redirfs_filter filter,
        struct dentry *dentry);
redirfs_root redirfs_get_root_inode(redirfs_filter filter, struct inode *inode);
redirfs_root redirfs_get_root_path(redirfs_path path);
redirfs_root redirfs_get_root(redirfs_root root);
void redirfs_put_root(redirfs_root root);
redirfs_filter redirfs_register_filter(struct redirfs_filter_info *info);
int redirfs_unregister_filter(redirfs_filter filter);
void redirfs_delete_filter(redirfs_filter filter);
int redirfs_set_operations(redirfs_filter filter, struct redirfs_op_info ops[]);
int redirfs_activate_filter(redirfs_filter filter);
int redirfs_deactivate_filter(redirfs_filter filter);
int redirfs_get_filename(struct vfsmount *mnt, struct dentry *dentry, char *buf,
        int size);
int redirfs_init_data(struct redirfs_data *data, redirfs_filter filter,
        void (*free)(struct redirfs_data *),
        void (*detach)(struct redirfs_data *));
struct redirfs_data *redirfs_get_data(struct redirfs_data *data);
void redirfs_put_data(struct redirfs_data *data);
struct redirfs_data *redirfs_attach_data_file(redirfs_filter filter,
        struct file *file, struct redirfs_data *data);
struct redirfs_data *redirfs_detach_data_file(redirfs_filter filter,
        struct file *file);
struct redirfs_data *redirfs_get_data_file(redirfs_filter filter,
        struct file *file);
struct redirfs_data *redirfs_attach_data_dentry(redirfs_filter filter,
        struct dentry *dentry, struct redirfs_data *data);
struct redirfs_data *redirfs_detach_data_dentry(redirfs_filter filter,
        struct dentry *dentry);
struct redirfs_data *redirfs_get_data_dentry(redirfs_filter filter,
        struct dentry *dentry);
struct redirfs_data *redirfs_attach_data_inode(redirfs_filter filter,
        struct inode *inode, struct redirfs_data *data);
struct redirfs_data *redirfs_detach_data_inode(redirfs_filter filter,
        struct inode *inode);
struct redirfs_data *redirfs_get_data_inode(redirfs_filter filter,
        struct inode *inode);
struct redirfs_data *redirfs_attach_data_context(redirfs_filter filter,
        redirfs_context context, struct redirfs_data *data);
struct redirfs_data *redirfs_detach_data_context(redirfs_filter filter,
        redirfs_context context);
struct redirfs_data *redirfs_get_data_context(redirfs_filter filter,
        redirfs_context context);
struct redirfs_data *redirfs_attach_data_root(redirfs_filter filter,
        redirfs_root root, struct redirfs_data *data);
struct redirfs_data *redirfs_detach_data_root(redirfs_filter filter,
        redirfs_root root);
struct redirfs_data *redirfs_get_data_root(redirfs_filter filter,
        redirfs_root root);
#endif

