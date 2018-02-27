/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * History:
 * 2008 - 2010 Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 * 2017 - Slava Imameev, a new hooks model and a new objects model
 *
 * Copyright 2008 - 2010 Frantisek Hrbata
 * Copyright 2017 - Slava Imameev
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
#include "rfs_hooked_ops.h"

#ifdef RFS_DBG
    #pragma GCC push_options
    #pragma GCC optimize ("O0")
#endif // RFS_DBG

/*---------------------------------------------------------------------------*/

static rfs_kmem_cache_t *rfs_dentry_cache = NULL;

/*---------------------------------------------------------------------------*/

static void rfs_dentry_free(struct rfs_object *robject);

static struct rfs_object_type rfs_dentry_type = {
    .type = RFS_TYPE_RDENTRY,
    .free = rfs_dentry_free,
};

/*---------------------------------------------------------------------------*/

struct rfs_radix_tree   rfs_dentry_radix_tree = {
    .root = RADIX_TREE_INIT(GFP_ATOMIC),
    .lock = __SPIN_LOCK_INITIALIZER(rfs_dentry_radix_tree.lock),
    .rfs_type = RFS_TYPE_RDENTRY,
    };

/*---------------------------------------------------------------------------*/

#ifdef RFS_PER_OBJECT_OPS
    #define rfs_cast_to_rdentry(dentry) \
        (dentry && dentry->d_op && dentry->d_op->d_iput == rfs_d_iput ? \
        rfs_dentry_get(container_of(dentry->d_op, struct rfs_dentry, op_new)) : \
        NULL)
#endif /* RFS_PER_OBJECT_OPS */

struct rfs_dentry* rfs_dentry_find(const struct dentry *dentry)
{
    struct rfs_dentry  *rdentry;
    struct rfs_object  *robject;

#ifdef RFS_PER_OBJECT_OPS
    rdentry = rfs_dentry_get(rfs_cast_to_rdentry(dentry));
    if (rdentry)
        return rdentry;
#endif /* RFS_PER_OBJECT_OPS */

    robject = rfs_get_object_by_system_object(&rfs_dentry_radix_tree, dentry);
    if (!robject)
        return NULL;

    rdentry = container_of(robject, struct rfs_dentry, robject);
    DBG_BUG_ON(RFS_DENTRY_SIGNATURE != rdentry->signature);
    return rdentry;
}

/*---------------------------------------------------------------------------*/

static struct rfs_dentry *rfs_dentry_alloc(struct dentry *dentry)
{
    struct rfs_dentry *rdentry;

    DBG_BUG_ON(!rfs_preemptible());

    rdentry = kmem_cache_zalloc(rfs_dentry_cache, GFP_KERNEL);
    if (!rdentry)
        return ERR_PTR(-ENOMEM);

    rfs_object_init(&rdentry->robject, &rfs_dentry_type, dentry);

#ifdef RFS_DBG
    rdentry->signature = RFS_DENTRY_SIGNATURE;
#endif // RFS_DBG

    INIT_LIST_HEAD(&rdentry->rinode_list);
    INIT_LIST_HEAD(&rdentry->rfiles);
    INIT_LIST_HEAD(&rdentry->data);
    rdentry->dentry = dentry;
    rdentry->op_old = dentry->d_op;
    spin_lock_init(&rdentry->lock);
    
#ifdef RFS_PER_OBJECT_OPS

    if (dentry->d_op)
        memcpy(&rdentry->op_new, dentry->d_op,
                sizeof(struct dentry_operations));
    
    rdentry->op_new.d_iput = rfs_d_iput;

#else /* RFS_PER_OBJECT_OPS */

    rdentry->d_rhops = rfs_create_dentry_ops(dentry->d_op);
    DBG_BUG_ON(IS_ERR(rdentry->d_rhops));
    if (IS_ERR(rdentry->d_rhops)) {
        void* err_ptr = rdentry->d_rhops;
        rdentry->d_rhops = NULL;
        rfs_object_put(&rdentry->robject);
        return err_ptr;
    }

#endif /* !RFS_PER_OBJECT_OPS */

    return rdentry;
}

/*---------------------------------------------------------------------------*/

struct rfs_dentry *rfs_dentry_get(struct rfs_dentry *rdentry)
{
    if (!rdentry || IS_ERR(rdentry))
        return NULL;
        
    DBG_BUG_ON(RFS_DENTRY_SIGNATURE != rdentry->signature);

    rfs_object_get(&rdentry->robject);
    return rdentry;
}

void rfs_dentry_put(struct rfs_dentry *rdentry)
{
    if (!rdentry || IS_ERR(rdentry))
        return;
        
    DBG_BUG_ON(RFS_DENTRY_SIGNATURE != rdentry->signature);

    rfs_object_put(&rdentry->robject);
}

/*---------------------------------------------------------------------------*/

static void rfs_dentry_free(struct rfs_object *robject)
{
    struct rfs_dentry *rdentry = container_of(robject,
                                              struct rfs_dentry,
                                              robject);

    DBG_BUG_ON(RFS_DENTRY_SIGNATURE != rdentry->signature);

    rfs_inode_put(rdentry->rinode);
    rfs_info_put(rdentry->rinfo);

    rfs_data_remove(&rdentry->data);
    
#ifndef RFS_PER_OBJECT_OPS
        if (rdentry->d_rhops)
            rfs_object_put(&rdentry->d_rhops->robject);
#endif /* !RFS_PER_OBJECT_OPS */

    kmem_cache_free(rfs_dentry_cache, rdentry);
}

/*---------------------------------------------------------------------------*/

struct rfs_dentry *rfs_dentry_add(struct dentry *dentry, struct rfs_info *rinfo)
{
    struct rfs_dentry *rd_new;
    struct rfs_dentry *rd = NULL;
    int err;

    DBG_BUG_ON(!dentry);
    if (!dentry)
        return NULL;

    spin_lock(&dentry->d_lock);
    rd = rfs_dentry_find(dentry);
    /*
     * Workaround for the isofs_lookup function. It assigns
     * dentry operations for the new dentry from the root dentry.
     * This leads to the situation when one rdentry object can be
     * found for more dentry objects.
     *
     * isofs_lookup: dentry->d_op = dir->i_sb->s_root->d_op;
     * vfat_lookup: dentry->d_op = dir->i_sb->s_root->d_op;
     */
    {
        if (rd) {
#ifdef RFS_PER_OBJECT_OPS
            if (rd->dentry != dentry) {
                dentry->d_op = rd->op_old;
                rfs_dentry_put(rd);
            } else {
                spin_unlock(&dentry->d_lock);
                rfs_pr_debug("rd=%p", rd);
                return rd;
            }
#else
            spin_unlock(&dentry->d_lock);
            rfs_pr_debug("rd=%p", rd);
            return rd;
#endif /* RFS_PER_OBJECT_OPS */
        }
#ifndef RFS_PER_OBJECT_OPS
        if (dentry->d_op && dentry->d_op->d_iput == rfs_d_iput) {
            if (dentry->d_sb && dentry->d_sb->s_root) {
                rd = rfs_dentry_find(dentry->d_sb->s_root);
                if (rd && rd->dentry != dentry) {
                    dentry->d_op = rd->d_rhops->old.d_op;
                    rfs_pr_debug("dentry->d_op = dentry->d_sb->s_root->d_op");
                }
                rfs_dentry_put(rd);
            }
        }
#endif
    }

    rd_new = rfs_dentry_alloc(dentry);
    if (IS_ERR(rd_new)) {
        spin_unlock(&dentry->d_lock);
        return rd_new;
    }
#ifndef RFS_PER_OBJECT_OPS
    DBG_BUG_ON(!rd_new->d_rhops);
#endif
    rd_new->rinfo = rfs_info_get(rinfo);
#ifdef RFS_PER_OBJECT_OPS
    dentry->d_op = &rd_new->op_new;
#endif /* RFS_PER_OBJECT_OPS */
    rfs_dentry_get(rd_new);
    spin_unlock(&dentry->d_lock);

#ifndef RFS_PER_OBJECT_OPS
    rfs_keep_operations(rd_new->d_rhops);
#endif /* !RFS_PER_OBJECT_OPS */

    err = rfs_insert_object(&rfs_dentry_radix_tree,
                            &rd_new->robject,
                            false);
    DBG_BUG_ON(err);
    if (unlikely(err)) {
        rfs_dentry_del(rd_new);
        rfs_dentry_put(rd_new);
        return ERR_PTR(err);
    }

    rfs_pr_debug("rd_new=%p", rd_new);
    return rd_new;
}

void rfs_dentry_del(struct rfs_dentry *rdentry)
{
#ifdef RFS_PER_OBJECT_OPS 
    rdentry->dentry->d_op = rdentry->op_old;
#else
    rdentry->dentry->d_op = rdentry->d_rhops->old.d_op;
    rfs_unkeep_operations(rdentry->d_rhops);
#endif /* !RFS_PER_OBJECT_OPS */

    rfs_remove_object(&rdentry->robject);
    rfs_dentry_put(rdentry);
}

int rfs_dentry_add_rinode(struct rfs_dentry *rdentry, struct rfs_info *rinfo)
{
    struct rfs_inode *rinode;

    if (!rdentry->dentry->d_inode)
        return 0;

    if (rdentry->rinode) {
        return 0;
    }

    rinode = rfs_inode_add(rdentry->dentry->d_inode, rinfo);
    if (IS_ERR(rinode))
        return PTR_ERR(rinode);

    spin_lock(&rdentry->lock);
    {
        if (rdentry->rinode) {
            spin_unlock(&rdentry->lock);
            rfs_inode_del(rinode);
            rfs_inode_put(rinode);
            return 0;
        }
        rdentry->rinode = rfs_inode_get(rinode);
    }
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
    {
        rinfo = rfs_info_get(rdentry->rinfo);
    }
    spin_unlock(&rdentry->lock);

    return rinfo;
}

void rfs_dentry_set_rinfo(struct rfs_dentry *rdentry, struct rfs_info *rinfo)
{
    struct rfs_info *rinfo_old;

    spin_lock(&rdentry->lock);
    {
        rinfo_old = rdentry->rinfo;
        rdentry->rinfo = rfs_info_get(rinfo);
    }
    spin_unlock(&rdentry->lock);

    rfs_info_put(rinfo_old);
}

void rfs_dentry_add_rfile(struct rfs_dentry *rdentry, struct rfs_file *rfile)
{
    rfs_file_get(rfile);

    spin_lock(&rdentry->lock);
    {
        list_add_tail(&rfile->rdentry_list, &rdentry->rfiles);
    }
    spin_unlock(&rdentry->lock);
}

void rfs_dentry_rem_rfile(struct rfs_file *rfile)
{
    if (list_empty(&rfile->rdentry_list))
        return;

    spin_lock(&rfile->rdentry->lock);
    {
        list_del_init(&rfile->rdentry_list);
    }
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
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfs_pr_debug("dentry=%p, inode=%p", dentry, inode);

    rdentry = rfs_dentry_find(dentry);
    if (!rdentry) {
        rfs_pr_debug("dentry=%p, rdentry=%p", dentry, rdentry);
        iput(inode);
        return;
    }
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

    if (!RFS_IS_DOP_SET(rdentry, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        BUG_ON(rfs_dcache_rinode_del(rdentry, inode));

        if (rdentry->op_old && rdentry->op_old->d_iput)
            rdentry->op_old->d_iput(rargs.args.d_iput.dentry,
                    rargs.args.d_iput.inode);
        else
            iput(inode);
    }

    if (RFS_IS_DOP_SET(rdentry, rargs.type.id))
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
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rdentry = rfs_dentry_find(dentry);
    if (!rdentry) {
        rfs_pr_debug("dentry=%p", dentry);
        return;
    }
    rinfo = rfs_dentry_get_rinfo(rdentry);
    rfs_context_init(&rcont, 0);
    rargs.type.id = REDIRFS_NONE_DOP_D_RELEASE;
    rargs.args.d_release.dentry = dentry;

    if (!RFS_IS_DOP_SET(rdentry, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rdentry->op_old && rdentry->op_old->d_release)
            rdentry->op_old->d_release(rargs.args.d_release.dentry);
    }

    if (RFS_IS_DOP_SET(rdentry, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_dentry_del(rdentry);
    rfs_dentry_put(rdentry);
    rfs_info_put(rinfo);
    rfs_pr_debug("dentry=%p", dentry);
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
    RFS_DEFINE_REDIRFS_ARGS(rargs);

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
    rargs.rv.rv_int = 1;

    if (!RFS_IS_DOP_SET(rdentry, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
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

    if (RFS_IS_DOP_SET(rdentry, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_dentry_put(rdentry);
    rfs_info_put(rinfo);

    return rargs.rv.rv_int;
}

#elif !(defined RH_KABI_DEPRECATE && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))

static int rfs_d_compare(const struct dentry *parent, const struct inode *inode,
        const struct dentry *dentry, const struct inode *d_inode,
        unsigned int tlen, const char *tname,
        const struct qstr *name)
{
    struct rfs_dentry *rdentry;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

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
    rargs.rv.rv_int = 1;

    if (!RFS_IS_DOP_SET(rdentry, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
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

    if (RFS_IS_DOP_SET(rdentry, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_dentry_put(rdentry);
    rfs_info_put(rinfo);

    return rargs.rv.rv_int;
}

#elif (LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0))

static int rfs_d_compare(const struct dentry *parent,
		const struct dentry *dentry, unsigned int len, const char *str,
		const struct qstr *name)
{
    struct rfs_dentry *rdentry;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

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
    rargs.args.d_compare.dentry = dentry;
    rargs.args.d_compare.len = len;
    rargs.args.d_compare.str = str;
    rargs.args.d_compare.name = name;
    rargs.rv.rv_int = 1;

    if (!RFS_IS_DOP_SET(rdentry, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rdentry->op_old && rdentry->op_old->d_compare)
            rargs.rv.rv_int = rdentry->op_old->d_compare(
                    rargs.args.d_compare.parent,
                    rargs.args.d_compare.dentry,
                    rargs.args.d_compare.len,
                    rargs.args.d_compare.str,
                    rargs.args.d_compare.name);
        else
            rargs.rv.rv_int = rfs_d_compare_default(
                    &rargs.args.d_compare.dentry->d_name,
                    rargs.args.d_compare.name);
    }

    if (RFS_IS_DOP_SET(rdentry, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_dentry_put(rdentry);
    rfs_info_put(rinfo);

    return rargs.rv.rv_int;

}

#else

static int rfs_d_compare(const struct dentry *dentry,
        unsigned int len, const char *str, const struct qstr *name)
{
    struct rfs_dentry *rdentry;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

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
    rargs.args.d_compare.len = len;
    rargs.args.d_compare.str = str;
    rargs.args.d_compare.name = name;
    rargs.rv.rv_int = 1;

    if (!RFS_IS_DOP_SET(rdentry, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rdentry->op_old && rdentry->op_old->d_compare)
            rargs.rv.rv_int = rdentry->op_old->d_compare(
                    rargs.args.d_compare.dentry,
                    rargs.args.d_compare.len,
                    rargs.args.d_compare.str,
                    rargs.args.d_compare.name);
        else
            rargs.rv.rv_int = rfs_d_compare_default(
                    &rargs.args.d_compare.dentry->d_name,
                    rargs.args.d_compare.name);
    }

    if (RFS_IS_DOP_SET(rdentry, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_dentry_put(rdentry);
    rfs_info_put(rinfo);

    return rargs.rv.rv_int;
}

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))

static int rfs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
    struct rfs_dentry *rdentry;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

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
    rargs.rv.rv_int = 1;

    if (!RFS_IS_DOP_SET(rdentry, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rdentry->op_old && rdentry->op_old->d_revalidate)
            rargs.rv.rv_int = rdentry->op_old->d_revalidate(
                    rargs.args.d_revalidate.dentry,
                    rargs.args.d_revalidate.nd);
    }

    if (RFS_IS_DOP_SET(rdentry, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_dentry_put(rdentry);
    rfs_info_put(rinfo);

    return rargs.rv.rv_int;
}

#else

static int rfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
    struct rfs_dentry *rdentry;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

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
    rargs.args.d_revalidate.flags = flags;
    rargs.rv.rv_int = 1;

    if (!RFS_IS_DOP_SET(rdentry, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rdentry->op_old && rdentry->op_old->d_revalidate)
            rargs.rv.rv_int = rdentry->op_old->d_revalidate(
                    rargs.args.d_revalidate.dentry,
                    rargs.args.d_revalidate.flags);
    }

    if (RFS_IS_DOP_SET(rdentry, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_dentry_put(rdentry);
    rfs_info_put(rinfo);

    return rargs.rv.rv_int;
}

#endif

static void rfs_dentry_set_ops_none(struct rfs_dentry *rdentry)
{
    RFS_SET_DOP(rdentry, REDIRFS_NONE_DOP_D_COMPARE, d_compare, rfs_d_compare);
    RFS_SET_DOP(rdentry, REDIRFS_NONE_DOP_D_REVALIDATE, d_revalidate, rfs_d_revalidate);
}

static void rfs_dentry_set_ops_reg(struct rfs_dentry *rdentry)
{
    RFS_SET_DOP(rdentry, REDIRFS_REG_DOP_D_COMPARE, d_compare, rfs_d_compare);
    RFS_SET_DOP(rdentry, REDIRFS_REG_DOP_D_REVALIDATE, d_revalidate, rfs_d_revalidate);
}

static void rfs_dentry_set_ops_dir(struct rfs_dentry *rdentry)
{
    RFS_SET_DOP(rdentry, REDIRFS_DIR_DOP_D_COMPARE, d_compare, rfs_d_compare);
    RFS_SET_DOP(rdentry, REDIRFS_DIR_DOP_D_REVALIDATE, d_revalidate, rfs_d_revalidate);
}

static void rfs_dentry_set_ops_lnk(struct rfs_dentry *rdentry)
{
    RFS_SET_DOP(rdentry, REDIRFS_LNK_DOP_D_COMPARE, d_compare, rfs_d_compare);
    RFS_SET_DOP(rdentry, REDIRFS_LNK_DOP_D_REVALIDATE, d_revalidate, rfs_d_revalidate);
}

static void rfs_dentry_set_ops_chr(struct rfs_dentry *rdentry)
{
    RFS_SET_DOP(rdentry, REDIRFS_CHR_DOP_D_COMPARE, d_compare, rfs_d_compare);
    RFS_SET_DOP(rdentry, REDIRFS_CHR_DOP_D_REVALIDATE, d_revalidate, rfs_d_revalidate);
}

static void rfs_dentry_set_ops_blk(struct rfs_dentry *rdentry)
{
    RFS_SET_DOP(rdentry, REDIRFS_BLK_DOP_D_COMPARE, d_compare, rfs_d_compare);
    RFS_SET_DOP(rdentry, REDIRFS_BLK_DOP_D_REVALIDATE, d_revalidate, rfs_d_revalidate);
}

static void rfs_dentry_set_ops_fifo(struct rfs_dentry *rdentry)
{
    RFS_SET_DOP(rdentry, REDIRFS_FIFO_DOP_D_COMPARE, d_compare, rfs_d_compare);
    RFS_SET_DOP(rdentry, REDIRFS_FIFO_DOP_D_REVALIDATE, d_revalidate, rfs_d_revalidate);
}

static void rfs_dentry_set_ops_sock(struct rfs_dentry *rdentry)
{
    RFS_SET_DOP(rdentry, REDIRFS_SOCK_DOP_D_COMPARE, d_compare, rfs_d_compare);
    RFS_SET_DOP(rdentry, REDIRFS_SOCK_DOP_D_REVALIDATE, d_revalidate, rfs_d_revalidate);
}

void rfs_dentry_set_ops(struct rfs_dentry *rdentry)
{
    struct rfs_file *rfile;
    umode_t mode;

    spin_lock(&rdentry->lock);
    {
        enum rfs_inode_type itype;

        if (rdentry->rinode)
            itype = rfs_imode_to_type(rdentry->rinode->inode->i_mode, true);
        else
            itype = RFS_INODE_DNONE;
        
#ifdef RFS_PER_OBJECT_OPS
        rdentry->op_new.d_release = rfs_d_release;
#else /* RFS_PER_OBJECT_OPS */
        RFS_SET_DOP_MGT(rdentry,
                        RFS_OP_IDC(itype, RFS_OP_d_release),
                        d_release,
                        rfs_d_release);

        RFS_SET_DOP_MGT(rdentry,
                        RFS_OP_IDC(itype, RFS_OP_d_iput),
                        d_iput,
                        rfs_d_iput);
#endif /* !RFS_PER_OBJECT_OPS */

        if (!rdentry->rinode) {
            rfs_dentry_set_ops_none(rdentry);
            spin_unlock(&rdentry->lock);
            return;
        }

        mode = rdentry->rinode->inode->i_mode;

        list_for_each_entry(rfile, &rdentry->rfiles, rdentry_list) {
            rfs_file_set_ops(rfile);
        }

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
    }
    spin_unlock(&rdentry->lock);
    
#ifndef RFS_PER_OBJECT_OPS
    spin_lock(&rdentry->dentry->d_lock);
    {
        DBG_BUG_ON(rdentry->op_old != rdentry->dentry->d_op &&
                   rdentry->dentry->d_op != rdentry->d_rhops->new.d_op);
        DBG_BUG_ON(!rdentry->d_rhops->new.d_op);
        if (rdentry->dentry->d_op != rdentry->d_rhops->new.d_op)
            rdentry->dentry->d_op = rdentry->d_rhops->new.d_op;
    }
    spin_unlock(&rdentry->dentry->d_lock);
#endif /* !RFS_PER_OBJECT_OPS */

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

#ifdef RFS_DBG
    #pragma GCC pop_options
#endif // RFS_DBG
