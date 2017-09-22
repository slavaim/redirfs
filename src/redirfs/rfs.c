/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * History:
 * 2017 - redesigned by Slava Imameev for new kernels and new hook ID model
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

#ifdef RFS_DBG
    #pragma GCC push_options
    #pragma GCC optimize ("O0")
#endif // RFS_DBG

struct rfs_info *rfs_info_none;

int rfs_precall_flts(struct rfs_chain *rchain, struct rfs_context *rcont,
        struct redirfs_args *rargs)
{
    enum redirfs_rv      (*rop)(redirfs_context, struct redirfs_args *);
    enum redirfs_rv      rv;
    enum rfs_inode_type  it;
    enum rfs_op_id       op_id;

    if (!rchain)
        return 0;

    it = RFS_IDC_TO_ITYPE(rargs->type.id);
    op_id = RFS_IDC_TO_OP_ID(rargs->type.id);

    BUG_ON(it >= RFS_INODE_MAX);
    BUG_ON(op_id >= RFS_OP_MAX);

    rargs->type.call = REDIRFS_PRECALL;

    rcont->idx = rcont->idx_start;

    for (; rcont->idx < rchain->rflts_nr; rcont->idx++) {
        if (!atomic_read(&rchain->rflts[rcont->idx]->active))
            continue;

        rop = rchain->rflts[rcont->idx]->cbs[it][op_id].pre_cb;
        if (!rop)
            continue;

        rv = rop(rcont, rargs);
        if (rv == REDIRFS_STOP)
            return -1;
    }

    rcont->idx--;

    return 0;
}

void rfs_postcall_flts(struct rfs_chain *rchain, struct rfs_context *rcont,
        struct redirfs_args *rargs)
{
    enum redirfs_rv      (*rop)(redirfs_context, struct redirfs_args *);
    enum rfs_inode_type  it;
    enum rfs_op_id       op_id;

    if (!rchain)
        return;

    it = RFS_IDC_TO_ITYPE(rargs->type.id);
    op_id = RFS_IDC_TO_OP_ID(rargs->type.id);

    BUG_ON(it >= RFS_INODE_MAX);
    BUG_ON(op_id >= RFS_OP_MAX);

    rargs->type.call = REDIRFS_POSTCALL;

    for (; rcont->idx >= rcont->idx_start; rcont->idx--) {
        if (!atomic_read(&rchain->rflts[rcont->idx]->active))
            continue;

        rop = rchain->rflts[rcont->idx]->cbs[it][op_id].post_cb;
        if (rop) 
            rop(rcont, rargs);
    }

    rcont->idx++;
}

enum rfs_inode_type  rfs_imode_to_type(umode_t i_mode, bool is_dentry)
{
    if (likely(!is_dentry)) {
        if (S_ISREG(i_mode))
            return RFS_INODE_REG;
        else if (S_ISDIR(i_mode))
            return RFS_INODE_DIR;
        else if (S_ISLNK(i_mode))
            return RFS_INODE_LINK;
        else if (S_ISCHR(i_mode))
            return RFS_INODE_CHAR;
        else if (S_ISBLK(i_mode))
            return RFS_INODE_BULK;
        else if (S_ISFIFO(i_mode))
            return RFS_INODE_FIFO;
        else if (S_ISSOCK(i_mode))
            return RFS_INODE_SOCK;
        else
            BUG();
    } else {
        if (S_ISREG(i_mode))
            return RFS_INODE_DREG;
        else if (S_ISDIR(i_mode))
            return RFS_INODE_DDIR;
        else if (S_ISLNK(i_mode))
            return RFS_INODE_DLINK;
        else if (S_ISCHR(i_mode))
            return RFS_INODE_DCHAR;
        else if (S_ISBLK(i_mode))
            return RFS_INODE_DBULK;
        else if (S_ISFIFO(i_mode))
            return RFS_INODE_DFIFO;
        else if (S_ISSOCK(i_mode))
            return RFS_INODE_DSOCK;
        else
            BUG();
    }
}

enum redirfs_op_idc rfs_inode_to_idc(struct inode* inode, enum rfs_op_id id)
{
    return RFS_OP_IDC(rfs_imode_to_type(inode->i_mode, false), id);
}

static int __init rfs_init(void)
{
    int rv;

    rfs_object_susbsystem_init();

    rfs_info_none = rfs_info_alloc(NULL, NULL);
    if (IS_ERR(rfs_info_none))
        return PTR_ERR(rfs_info_none);

    rv = rfs_dentry_cache_create();
    if (rv)
        goto err_dentry_cache;

    rv = rfs_inode_cache_create();
    if (rv)
        goto err_inode_cache;

    rv = rfs_file_cache_create();
    if (rv)
        goto err_file_cache;

    rv = rfs_sysfs_create();
    if (rv)
        goto err_sysfs;

    printk(KERN_INFO "Redirecting File System Framework Version "
            REDIRFS_VERSION " <www.redirfs.org>\n");

    return 0;

err_sysfs:
    rfs_file_cache_destory();
err_file_cache:
    rfs_inode_cache_destroy();
err_inode_cache:
    rfs_dentry_cache_destory();
err_dentry_cache:
    rfs_info_put(rfs_info_none);
    return rv;
}

module_init(rfs_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <frantisek.hrbata@redirfs.org>");
MODULE_DESCRIPTION("Redirecting File System Framework Version "
        REDIRFS_VERSION " <www.redirfs.org>");

#ifdef RFS_DBG
    #pragma GCC pop_options
#endif // RFS_DBG
