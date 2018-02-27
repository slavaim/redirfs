/*
 * RedirFS: Redirecting File System
 * Original version was written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * History:
 * 2008 - 2010 Frantisek Hrbata
 * 2017 - Slava Imameev
 *      - adress_space_operations hooks
 *      - new object model
 *      - shared hooking structure
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
#include "rfs_address_space.h"
#include "rfs_hooked_ops.h"
#include "rfs_file_ops.h"

#ifdef RFS_DBG
    #pragma GCC push_options
    #pragma GCC optimize ("O0")
#endif // RFS_DBG

/*---------------------------------------------------------------------------*/

struct rfs_radix_tree   rfs_inode_radix_tree = {
    .root = RADIX_TREE_INIT(GFP_ATOMIC),
    .lock = __SPIN_LOCK_INITIALIZER(rfs_inode_radix_tree.lock),
    .rfs_type = RFS_TYPE_RINODE,
    };

/*---------------------------------------------------------------------------*/

void rfs_inode_free(struct rfs_object *robject);

static struct rfs_object_type rfs_inode_type = {
    .type = RFS_TYPE_RINODE,
    .free = rfs_inode_free,
    };
    
/*---------------------------------------------------------------------------*/

static rfs_kmem_cache_t *rfs_inode_cache = NULL;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0))
int rfs_rename(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
int rfs_rename2(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry,
        unsigned int flags);
#else
int rfs_rename(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry,
		unsigned int flags);
#endif //(LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))

/*---------------------------------------------------------------------------*/
#ifdef RFS_PER_OBJECT_OPS
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
        #define rfs_cast_to_rinode(inode) \
            (inode && inode->i_op && inode->i_op->rename2 == rfs_rename2 ? \
            container_of(inode->i_op, struct rfs_inode, op_new) : \
            NULL)
    #else
        #define rfs_cast_to_rinode(inode) \
            (inode && inode->i_op && inode->i_op->rename == rfs_rename ? \
            container_of(inode->i_op, struct rfs_inode, op_new) : \
            NULL)
    #endif
#endif /* RFS_PER_OBJECT_OPS */
struct rfs_inode* rfs_inode_find(struct inode *inode) 
{
    struct rfs_inode  *rinode;
    struct rfs_object *robject;

#ifdef RFS_PER_OBJECT_OPS
    rinode = rfs_inode_get(rfs_cast_to_rinode(inode));
    if (rinode)
        return rinode;
#endif /* RFS_PER_OBJECT_OPS */

    robject = rfs_get_object_by_system_object(&rfs_inode_radix_tree, inode);
    if (!robject)
        return NULL;

    rinode = container_of(robject, struct rfs_inode, robject);
    DBG_BUG_ON(RFS_INODE_SIGNATURE != rinode->signature);
    return rinode;
}

/*---------------------------------------------------------------------------*/

static struct rfs_inode *rfs_inode_alloc(struct inode *inode)
{
    struct rfs_inode *rinode;

    DBG_BUG_ON(!rfs_preemptible());

    rinode = kmem_cache_zalloc(rfs_inode_cache, GFP_KERNEL);
    if (IS_ERR(rinode))
        return ERR_PTR(-ENOMEM);
        
#ifdef RFS_DBG
    rinode->signature = RFS_INODE_SIGNATURE;
#endif

    rfs_object_init(&rinode->robject, &rfs_inode_type, inode);

    INIT_LIST_HEAD(&rinode->rdentries);
    INIT_LIST_HEAD(&rinode->data);
    rinode->inode = inode;
    rinode->op_old = inode->i_op;
    rinode->f_op_old = inode->i_fop;
    rinode->a_op_old = inode->i_mapping ? inode->i_mapping->a_ops : NULL;
    spin_lock_init(&rinode->lock);
    rfs_mutex_init(&rinode->mutex);
    atomic_set(&rinode->nlink, 1);
    rinode->rdentries_nr = 0;

#ifdef RFS_PER_OBJECT_OPS

    if (inode->i_op)
        memcpy(&rinode->op_new, inode->i_op,
                sizeof(struct inode_operations));

    /* rename hook is required for correct functioning of rfs_inode_find */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
    rinode->op_new.rename2 = rfs_rename2;
#else
    rinode->op_new.rename = rfs_rename;
#endif

    if (inode->i_mapping && inode->i_mapping->a_ops) {
        memcpy(&rinode->a_op_new,
               inode->i_mapping->a_ops,
               sizeof(struct address_space_operations));
    }
                
#else /* RFS_PER_OBJECT_OPS */
                
    rinode->i_rhops = rfs_create_inode_ops(rinode->op_old);
    DBG_BUG_ON(IS_ERR(rinode->i_rhops));
    if (IS_ERR(rinode->i_rhops)) {
        void *err_ptr = rinode->i_rhops;
        rinode->i_rhops = NULL;
        rfs_object_put(&rinode->robject);
        return err_ptr;
    }

    if (rinode->a_op_old) {
        rinode->a_rhops = rfs_create_address_space_ops(rinode->a_op_old);
        DBG_BUG_ON(IS_ERR(rinode->a_rhops));
        if (IS_ERR(rinode->a_rhops)) {
            void *err_ptr = rinode->a_rhops;
            rinode->a_rhops = NULL;
            rfs_object_put(&rinode->robject);
            return err_ptr;
        }
    }

#endif /* !RFS_PER_OBJECT_OPS  */

    return rinode;
}

/*---------------------------------------------------------------------------*/

struct rfs_inode *rfs_inode_get(struct rfs_inode *rinode)
{
    if (!rinode || IS_ERR(rinode))
        return NULL;

    DBG_BUG_ON(RFS_INODE_SIGNATURE != rinode->signature);
    rfs_object_get(&rinode->robject);

    return rinode;
}

/*---------------------------------------------------------------------------*/

void rfs_inode_put(struct rfs_inode *rinode)
{
    if (!rinode || IS_ERR(rinode))
        return;

    DBG_BUG_ON(RFS_INODE_SIGNATURE != rinode->signature);
    rfs_object_put(&rinode->robject);
}

/*---------------------------------------------------------------------------*/

void rfs_inode_free(struct rfs_object *robject)
{
    struct rfs_inode *rinode = container_of(robject, struct rfs_inode, robject);

    DBG_BUG_ON(RFS_INODE_SIGNATURE != rinode->signature);

#ifndef RFS_PER_OBJECT_OPS
    if (rinode->i_rhops)
        rfs_object_put(&rinode->i_rhops->robject);
    if (rinode->a_rhops)
        rfs_object_put(&rinode->a_rhops->robject);
#endif /* !RFS_PER_OBJECT_OPS */

    rfs_info_put(rinode->rinfo);
    rfs_data_remove(&rinode->data);
    kmem_cache_free(rfs_inode_cache, rinode);
}

/*---------------------------------------------------------------------------*/

static void rfs_inode_set_default_fop_reg(struct rfs_inode *ri_new, struct inode *inode)
{
#define PROTOTYPE_FOP(op, new_op) \
    RFS_ADD_OP(ri_new->f_op_new, inode->i_fop, op, new_op);
    SET_FOP_REG
#undef PROTOTYPE_FOP
}

static void rfs_inode_set_default_fop_dir(struct rfs_inode *ri_new, struct inode *inode)
{
#define PROTOTYPE_FOP(op, new_op) \
    RFS_ADD_OP(ri_new->f_op_new, inode->i_fop, op, new_op);
    SET_FOP_DIR
#undef PROTOTYPE_FOP
}

static void rfs_inode_set_default_fop_lnk(struct rfs_inode *ri_new, struct inode *inode)
{
}

static void rfs_inode_set_default_fop_chr(struct rfs_inode *ri_new, struct inode *inode)
{
#define PROTOTYPE_FOP(op, new_op) \
    RFS_ADD_OP(ri_new->f_op_new, inode->i_fop, op, new_op);
    SET_FOP_CHR
#undef PROTOTYPE_FOP
}

static void rfs_inode_set_default_fop_blk(struct rfs_inode *ri_new, struct inode *inode)
{
}

static void rfs_inode_set_default_fop_fifo(struct rfs_inode *ri_new, struct inode *inode)
{
}

static void rfs_inode_set_default_fop(struct rfs_inode *ri_new, struct inode *inode)
{
    umode_t mode = inode->i_mode;

    if (S_ISREG(mode))
        rfs_inode_set_default_fop_reg(ri_new, inode);

    else if (S_ISDIR(mode))
        rfs_inode_set_default_fop_dir(ri_new, inode);

    else if (S_ISLNK(mode))
        rfs_inode_set_default_fop_lnk(ri_new, inode);

    else if (S_ISCHR(mode))
        rfs_inode_set_default_fop_chr(ri_new, inode);

    else if (S_ISBLK(mode))
        rfs_inode_set_default_fop_blk(ri_new, inode);

    else if (S_ISFIFO(mode))
        rfs_inode_set_default_fop_fifo(ri_new, inode);

    else if (S_ISSOCK(mode))
    {
        /*
         * nothing
         */
        return;
    }

#define PROTOTYPE_FOP(op, new_op) \
    RFS_ADD_OP_MGT(ri_new->f_op_new, inode->i_fop, op, new_op);
    FUNCTION_FOP_open // a watermark for rfs_cast_to_rfile
    FUNCTION_FOP_release
#undef PROTOTYPE_FOP

    inode->i_fop = &ri_new->f_op_new;
}

/*---------------------------------------------------------------------------*/

struct rfs_inode *rfs_inode_add(struct inode *inode, struct rfs_info *rinfo)
{
    struct rfs_inode *ri_new;
    struct rfs_inode *ri;
    int err = 0;

    if (!inode)
        return NULL;

    ri_new = rfs_inode_alloc(inode);
    if (IS_ERR(ri_new))
        return ri_new;
#ifndef RFS_PER_OBJECT_OPS
    DBG_BUG_ON(!ri_new->i_rhops);
#endif

    spin_lock(&inode->i_lock);
    {
        ri = rfs_inode_find(inode);
        if (!ri) {
            DBG_BUG_ON(ri_new->f_op_old->open == rfs_open);

            ri_new->rinfo = rfs_info_get(rinfo);

            rfs_inode_set_default_fop(ri_new, inode);

#ifdef RFS_PER_OBJECT_OPS
            inode->i_op = &ri_new->op_new;
            if (inode->i_mapping && inode->i_mapping->a_ops) {
                inode->i_mapping->a_ops = &ri_new->a_op_new;
            }
#endif /* RFS_PER_OBJECT_OPS */

            err = rfs_insert_object(&rfs_inode_radix_tree,
                                    &ri_new->robject,
                                    false);
            DBG_BUG_ON(err);

            rfs_inode_get(ri_new);
            ri = rfs_inode_get(ri_new);
        } else
            atomic_inc(&ri->nlink);
    }
    spin_unlock(&inode->i_lock);

    rfs_inode_put(ri_new);
    
#ifndef RFS_PER_OBJECT_OPS
    if (ri == ri_new) {
        rfs_keep_operations(ri_new->i_rhops);
        if (ri_new->a_rhops)
            rfs_keep_operations(ri_new->a_rhops);
    }
#endif /* RFS_PER_OBJECT_OPS */

    if (unlikely(err)) {
        if (ri) {
            rfs_inode_del(ri);
            rfs_inode_put(ri);
        }
        ri = ERR_PTR(err);
    }

    return ri;
}

/*---------------------------------------------------------------------------*/

void rfs_inode_del(struct rfs_inode *rinode)
{
    if (!atomic_dec_and_test(&rinode->nlink))
        return;

    if (!S_ISSOCK(rinode->inode->i_mode))
        rinode->inode->i_fop = rinode->f_op_old;

    rinode->inode->i_op = rinode->op_old;

    if (rinode->inode->i_mapping && rinode->inode->i_mapping->a_ops) {
        DBG_BUG_ON(!rinode->a_op_old);
        rinode->inode->i_mapping->a_ops = rinode->a_op_old;
    }
    
    rfs_remove_object(&rinode->robject);
#ifndef RFS_PER_OBJECT_OPS
    rfs_unkeep_operations(rinode->i_rhops);
    if (rinode->a_rhops)
        rfs_unkeep_operations(rinode->a_rhops);
#endif /* RFS_PER_OBJECT_OPS */
    rfs_inode_put(rinode);
}

/*---------------------------------------------------------------------------*/

void rfs_inode_add_rdentry(struct rfs_inode *rinode, struct rfs_dentry *rdentry)
{
    rfs_mutex_lock(&rinode->mutex);
    rinode->rdentries_nr++;
    list_add_tail(&rdentry->rinode_list, &rinode->rdentries);
    rfs_mutex_unlock(&rinode->mutex);
    rfs_dentry_get(rdentry);
}

void rfs_inode_rem_rdentry(struct rfs_inode *rinode, struct rfs_dentry *rdentry)
{
    rfs_mutex_lock(&rinode->mutex);
    if (list_empty(&rdentry->rinode_list)) {
        rfs_mutex_unlock(&rinode->mutex);
        return;
    }
    rinode->rdentries_nr--;
    list_del_init(&rdentry->rinode_list);
    rfs_mutex_unlock(&rinode->mutex);
    rfs_dentry_put(rdentry);
}

static struct rfs_chain *rfs_inode_join_rchains(struct rfs_inode *rinode)
{
    struct rfs_dentry *rdentry = NULL;
    struct rfs_info *rinfo = NULL;
    struct rfs_chain *rchain = NULL;
    struct rfs_chain *rchain_old = NULL;

    list_for_each_entry(rdentry, &rinode->rdentries, rinode_list) {
        spin_lock(&rdentry->lock);
        rinfo = rfs_info_get(rdentry->rinfo);
        spin_unlock(&rdentry->lock);

        rchain = rfs_chain_join(rinfo->rchain, rchain_old);

        rfs_info_put(rinfo);
        rfs_chain_put(rchain_old);

        if (IS_ERR(rchain))
            return rchain;

        rchain_old = rchain;
    }

    return rchain;
}

static int rfs_inode_set_rinfo_fast(struct rfs_inode *rinode)
{
    struct rfs_dentry *rdentry;
    struct rfs_info   *rinfo_old;

    if (!rinode->rdentries_nr)
        return 0;

    if (rinode->rdentries_nr > 1)
        return -1;

    rdentry = list_entry(rinode->rdentries.next, struct rfs_dentry, rinode_list);

    spin_lock(&rdentry->lock);
    spin_lock(&rinode->lock);
    {
        rinfo_old = rinode->rinfo;
        rinode->rinfo = rfs_info_get(rdentry->rinfo);
    }
    spin_unlock(&rinode->lock);
    spin_unlock(&rdentry->lock);

    rfs_info_put(rinfo_old);

    return 0;
}

struct rfs_info *rfs_inode_get_rinfo(struct rfs_inode *rinode)
{
    struct rfs_info *rinfo;

    spin_lock(&rinode->lock);
    {
        rinfo = rfs_info_get(rinode->rinfo);
    }
    spin_unlock(&rinode->lock);

    return rinfo;
}

int rfs_inode_set_rinfo(struct rfs_inode *rinode)
{
    struct rfs_chain *rchain;
    struct rfs_info *rinfo;
    struct rfs_ops *rops;
    struct rfs_info *rinfo_old = NULL;
    int rv;

    if (!rinode)
        return 0;

    rfs_mutex_lock(&rinode->mutex);
    rv = rfs_inode_set_rinfo_fast(rinode);
    rfs_mutex_unlock(&rinode->mutex);
    if (!rv)
        return 0;

    rinfo = rfs_info_alloc(NULL, NULL);
    if (IS_ERR(rinfo))
        return PTR_ERR(rinfo);

    rops = rfs_ops_alloc();
    if (IS_ERR(rops)) {
        rfs_info_put(rinfo);
        return PTR_ERR(rops);
    }

    rinfo->rops = rops;

    rfs_mutex_lock(&rinode->mutex);
    { // start of the mutex lock
        rv = rfs_inode_set_rinfo_fast(rinode);
        if (!rv) {
            rfs_mutex_unlock(&rinode->mutex);
            rfs_info_put(rinfo);
            return 0;
        }

        rchain = rfs_inode_join_rchains(rinode);
        if (IS_ERR(rchain)) {
            rfs_mutex_unlock(&rinode->mutex);
            rfs_info_put(rinfo);
            return PTR_ERR(rchain);
        }

        rinfo->rchain = rchain;

        if (!rinfo->rchain) {
            rfs_info_put(rinfo);
            rinfo = rfs_info_get(rfs_info_none);
        }

        rfs_chain_ops(rinfo->rchain, rinfo->rops);
        spin_lock(&rinode->lock);
        { // start of the lock
            rinfo_old = rinode->rinfo;
            rinode->rinfo = rinfo;
        } // end of the lock
        spin_unlock(&rinode->lock);
    } // end of the mutex lock
    rfs_mutex_unlock(&rinode->mutex);

    rfs_info_put(rinfo_old);

    return 0;
}

int rfs_inode_cache_create(void)
{
    rfs_inode_cache = rfs_kmem_cache_create("rfs_inode_cache",
            sizeof(struct rfs_inode));

    if (!rfs_inode_cache)
        return -ENOMEM;

    return 0;
}

void rfs_inode_cache_destroy(void)
{
    kmem_cache_destroy(rfs_inode_cache);
}

static int is_fs_with_name(const char* name, struct inode *dir)
{
    if (dir && dir->i_sb && dir->i_sb->s_type && dir->i_sb->s_type->name) {
        rfs_pr_debug("name=%s", dir->i_sb->s_type->name);
        return !strcmp(name, dir->i_sb->s_type->name);
    }
    return 0;
}

static int lookup_cifs_rfs_dcache_rdentry_add(unsigned int flags, struct dentry *dentry, struct rfs_info *rinfo)
{
	/*
	 * If dentry->d_inode doesn't exist and dentry wants to be exclusive created, then it
	 * will be handled by rfs_create. Create of FS can override dentry
	 * operation(d_op). eg: CIFS
	 */

	if ((flags & LOOKUP_OPEN) && !(flags & LOOKUP_EXCL)) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
        return 0;
	}
    return -1;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))

static void rfs_lookup_add_nameidata(struct dentry *dentry, struct nameidata *nd)
{
    struct file         *file;
    struct rfs_file     *rfile;

	if (nd && nd->flags & LOOKUP_OPEN) {
		file = !IS_ERR(nd->intent.open.file) ? nd->intent.open.file : NULL;
		rfs_pr_debug("file(%p)->f_dentry(%p)->d_inode(%p), dentry(%p)->d_inode(%p)",
					 file,
					 file ? file->f_dentry : NULL,
					 file && file->f_dentry ? file->f_dentry->d_inode : NULL,
					 dentry,
					 dentry->d_inode);
		if (file && (file->f_dentry == dentry) && (file->f_dentry->d_inode && dentry->d_inode)) {
			/*
			 * File was open and can be used by f_op -> register it to rfs.
			 * e.g: NFS first open of file
			 */

			if (S_ISREG(nd->intent.open.file->f_mode)) {
				/*
				 * Emulate open operation for redirfs filters.
				 */
				rfile = rfs_file_find_with_open_flts(file);
				if (IS_ERR(rfile)) {
					d_drop(dentry);
					dentry = (struct dentry *)rfile;
				}
			} else {
				rfile = rfs_file_add(file);
				if (IS_ERR(rfile))
					BUG();
			}
			rfs_file_put(rfile);
		}
	}
}

struct dentry *rfs_lookup(struct inode *dir, struct dentry *dentry,
        struct nameidata *nd)
{
    struct rfs_inode    *rinode;
    struct rfs_info     *rinfo;
    struct rfs_context   rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfs_pr_debug("dir=%p, dentry=%p, nameidata=%p", dir, dentry, nd);
    if (nd)
        rfs_pr_debug("nd: { flags: 0x%x, intent.open: { flags: 0x%x, create_mode: 0x%x }}", nd->flags, nd->intent.open.flags, nd->intent.open.create_mode);

    if (S_ISDIR(dir->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_LOOKUP;
    else
        return ERR_PTR(-ENOTDIR);

    rinode = rfs_inode_find(dir);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    rargs.args.i_lookup.dir = dir;
    rargs.args.i_lookup.dentry = dentry;
    rargs.args.i_lookup.nd = nd;

    rargs.rv.rv_dentry = ERR_PTR(-ENOSYS);

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->lookup) {
            rargs.rv.rv_dentry = rinode->op_old->lookup(
                    rargs.args.i_lookup.dir,
                    rargs.args.i_lookup.dentry,
                    rargs.args.i_lookup.nd);
        }
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    if (IS_ERR(rargs.rv.rv_dentry))
        goto exit;

	if (is_fs_with_name("cifs", dir)) {
        if (nd) {
            if (!lookup_cifs_rfs_dcache_rdentry_add(nd->flags, dentry, rinfo) && (nd->flags & LOOKUP_CREATE)) {
                rfs_lookup_add_nameidata(dentry, nd);
			}
		}
	} else {
		if (rargs.rv.rv_dentry)
			dentry = rargs.rv.rv_dentry;
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}
exit:
    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    rfs_pr_debug("dentry=%p, ret=%ld", dentry, IS_ERR(dentry) ? PTR_ERR(dentry) : 0);
    return rargs.rv.rv_dentry;
}

#else

static struct dentry *rfs_lookup(struct inode *dir, struct dentry *dentry,
        unsigned int flags)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;

    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfs_pr_debug("dir=%p, dentry=%p, flags=0x%x", dir, dentry, flags);

    if (S_ISDIR(dir->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_LOOKUP;
    else
        return ERR_PTR(-ENOTDIR);

    rinode = rfs_inode_find(dir);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    rargs.args.i_lookup.dir = dir;
    rargs.args.i_lookup.dentry = dentry;
    rargs.args.i_lookup.flags = flags;

    rargs.rv.rv_dentry = ERR_PTR(-ENOSYS);

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->lookup) {
            rargs.rv.rv_dentry = rinode->op_old->lookup(
                    rargs.args.i_lookup.dir,
                    rargs.args.i_lookup.dentry,
                    rargs.args.i_lookup.flags);
        }
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    if (IS_ERR(rargs.rv.rv_dentry))
        goto exit;

    if (is_fs_with_name("cifs", dir)) {
		lookup_cifs_rfs_dcache_rdentry_add(flags, dentry, rinfo);
    } else {
        if (rargs.rv.rv_dentry)
            dentry = rargs.rv.rv_dentry;
        if (rfs_dcache_rdentry_add(dentry, rinfo))
            BUG();
    }

exit:
    rfs_inode_put(rinode);
    rfs_info_put(rinfo);

    rfs_pr_debug("dentry=%p, ret=%ld", dentry, IS_ERR(rargs.rv.rv_dentry) ? PTR_ERR(rargs.rv.rv_dentry) : 0);
    return rargs.rv.rv_dentry;
}

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
static int rfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
#else
static int rfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
#endif
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rinode = rfs_inode_find(dir);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISDIR(dir->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_MKDIR;
    else
        BUG();

    rargs.args.i_mkdir.dir = dir;
    rargs.args.i_mkdir.dentry = dentry;
    rargs.args.i_mkdir.mode = mode;
    rargs.rv.rv_int = -ENOSYS;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->mkdir)
            rargs.rv.rv_int = rinode->op_old->mkdir(
                    rargs.args.i_mkdir.dir,
                    rargs.args.i_mkdir.dentry,
                    rargs.args.i_mkdir.mode);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    if (!rargs.rv.rv_int) {
        if (rfs_dcache_rdentry_add(dentry, rinfo))
            BUG();
    }

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))

static int rfs_create(struct inode *dir, struct dentry *dentry, int mode,
        struct nameidata *nd)
{
    struct rfs_file     *rfile;
    struct file         *file;
    struct rfs_inode    *rinode;
    struct rfs_info     *rinfo;
    struct rfs_context   rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfs_pr_debug("dir=%p, dentry=%p, mode=%d, nameidata=%p",
        dir, dentry, mode, nd);
    if (nd)
        rfs_pr_debug("nd: { flags: 0x%x, intent.open: { flags: 0x%x, create_mode: 0x%x }}", nd->flags, nd->intent.open.flags, nd->intent.open.create_mode);

    rinode = rfs_inode_find(dir);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISDIR(dir->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_CREATE;
    else
        BUG();

    rargs.args.i_create.dir = dir;
    rargs.args.i_create.dentry = dentry;
    rargs.args.i_create.mode = mode;
    rargs.args.i_create.nd = nd;

    rargs.rv.rv_int = -ENOSYS;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->create) {
            rargs.rv.rv_int = rinode->op_old->create(
                    rargs.args.i_create.dir,
                    rargs.args.i_create.dentry,
                    rargs.args.i_create.mode,
                    rargs.args.i_create.nd);
        }
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int && dentry) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
		if (nd && !IS_ERR(nd->intent.open.file) && nd->intent.open.file && dentry == nd->intent.open.file->f_dentry) {
			/*
			 * Empty file was created and can be used by f_op -> register it to rfs.
			 */
			file = nd->intent.open.file;
			rfs_pr_debug("flags=0x%x, open_flags=0x%x, "
						 "file(%p)->f_dentry(%p)->d_inode(%p), dentry(%p)->d_inode(%p)",
						 nd->flags,
						 nd->intent.open.flags,
						 file,
						 file->f_dentry,
						 file->f_dentry->d_inode,
						 dentry,
						 dentry->d_inode);
			rfile = rfs_file_add(file);
			if (IS_ERR(rfile))
				BUG();
			rfs_file_put(rfile);
		}
	}

	rfs_inode_put(rinode);
    rfs_info_put(rinfo);

    rfs_pr_debug("dentry=%p, ret=%d", dentry, rargs.rv.rv_int);
    return rargs.rv.rv_int;
}

#else

static int rfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
        bool excl)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rinode = rfs_inode_find(dir);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISDIR(dir->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_CREATE;
    else
        BUG();

    rargs.args.i_create.dir = dir;
    rargs.args.i_create.dentry = dentry;
    rargs.args.i_create.mode = mode;
    rargs.args.i_create.excl = excl;

    rargs.rv.rv_int = -ENOSYS;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->create) {
            rargs.rv.rv_int = rinode->op_old->create(
                    rargs.args.i_create.dir,
                    rargs.args.i_create.dentry,
                    rargs.args.i_create.mode,
                    rargs.args.i_create.excl);
        }
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    if (!rargs.rv.rv_int) {
        if (rfs_dcache_rdentry_add(dentry, rinfo))
          BUG();
    }

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);

    rfs_pr_debug("dentry=%p, ret=%d", dentry, rargs.rv.rv_int);
    return rargs.rv.rv_int;
}

#endif

static int rfs_link(struct dentry *old_dentry, struct inode *dir,
        struct dentry *dentry)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rinode = rfs_inode_find(dir);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISDIR(dir->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_LINK;
    else
        BUG();

    rargs.args.i_link.old_dentry = old_dentry;
    rargs.args.i_link.dir = dir;
    rargs.args.i_link.dentry = dentry;
    rargs.rv.rv_int = -ENOSYS;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->link)
            rargs.rv.rv_int = rinode->op_old->link(
                    rargs.args.i_link.old_dentry,
                    rargs.args.i_link.dir,
                    rargs.args.i_link.dentry);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    if (!rargs.rv.rv_int) {
        if (rfs_dcache_rdentry_add(dentry, rinfo))
            BUG();
    }

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

static int rfs_symlink(struct inode *dir, struct dentry *dentry,
        const char *oldname)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rinode = rfs_inode_find(dir);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISDIR(dir->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_SYMLINK;
    else
        BUG();

    rargs.args.i_symlink.dir = dir;
    rargs.args.i_symlink.dentry = dentry;
    rargs.args.i_symlink.oldname = oldname;
    rargs.rv.rv_int = -ENOSYS;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->symlink)
            rargs.rv.rv_int = rinode->op_old->symlink(
                    rargs.args.i_symlink.dir,
                    rargs.args.i_symlink.dentry,
                    rargs.args.i_symlink.oldname);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    if (!rargs.rv.rv_int) {
        if (rfs_dcache_rdentry_add(dentry, rinfo))
            BUG();
    }

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
static int rfs_mknod(struct inode * dir, struct dentry *dentry, int mode,
        dev_t rdev)
#else
static int rfs_mknod(struct inode * dir, struct dentry *dentry, umode_t mode,
        dev_t rdev)
#endif
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rinode = rfs_inode_find(dir);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISDIR(dir->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_MKNOD;
    else
        BUG();

    rargs.args.i_mknod.dir = dir;
    rargs.args.i_mknod.dentry = dentry;
    rargs.args.i_mknod.mode = mode;
    rargs.args.i_mknod.rdev = rdev;
    rargs.rv.rv_int = -ENOSYS;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->mknod)
            rargs.rv.rv_int = rinode->op_old->mknod(
                    rargs.args.i_mknod.dir,
                    rargs.args.i_mknod.dentry,
                    rargs.args.i_mknod.mode,
                    rargs.args.i_mknod.rdev);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    if (!rargs.rv.rv_int) {
        if (rfs_dcache_rdentry_add(dentry, rinfo))
            BUG();
    }

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

static int rfs_unlink(struct inode *inode, struct dentry *dentry)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rinode = rfs_inode_find(inode);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISDIR(inode->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_UNLINK;
    else
        BUG();

    rargs.args.i_unlink.dir = inode;
    rargs.args.i_unlink.dentry = dentry;
    rargs.rv.rv_int = -ENOSYS;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->unlink)
            rargs.rv.rv_int = rinode->op_old->unlink(
                    rargs.args.i_unlink.dir,
                    rargs.args.i_unlink.dentry);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    rfs_pr_debug("dentry=%p, ret=%d", dentry, rargs.rv.rv_int);
    return rargs.rv.rv_int;
}

static int rfs_rmdir(struct inode *inode, struct dentry *dentry)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rinode = rfs_inode_find(inode);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISDIR(inode->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_RMDIR;
    else
        BUG();

    rargs.args.i_unlink.dir = inode;
    rargs.args.i_unlink.dentry = dentry;
    rargs.rv.rv_int = -ENOSYS;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->rmdir)
            rargs.rv.rv_int = rinode->op_old->rmdir(
                    rargs.args.i_unlink.dir,
                    rargs.args.i_unlink.dentry);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

static int rfs_permission(struct inode *inode, int mask, struct nameidata *nd)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);
    int submask;

    submask = mask & ~MAY_APPEND;
    rinode = rfs_inode_find(inode);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISREG(inode->i_mode))
        rargs.type.id = REDIRFS_REG_IOP_PERMISSION;
    else if (S_ISDIR(inode->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_PERMISSION;
    else if (S_ISLNK(inode->i_mode))
        rargs.type.id = REDIRFS_LNK_IOP_PERMISSION;
    else if (S_ISCHR(inode->i_mode))
        rargs.type.id = REDIRFS_CHR_IOP_PERMISSION;
    else if (S_ISBLK(inode->i_mode))
        rargs.type.id = REDIRFS_BLK_IOP_PERMISSION;
    else if (S_ISFIFO(inode->i_mode))
        rargs.type.id = REDIRFS_FIFO_IOP_PERMISSION;
    else 
        rargs.type.id = REDIRFS_SOCK_IOP_PERMISSION;

    rargs.args.i_permission.inode = inode;
    rargs.args.i_permission.mask = mask;
    rargs.args.i_permission.nd = nd;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->permission)
            rargs.rv.rv_int = rinode->op_old->permission(
                    rargs.args.i_permission.inode,
                    rargs.args.i_permission.mask,
                    rargs.args.i_permission.nd);
        else
            rargs.rv.rv_int = generic_permission(inode, submask,
                    NULL);
    } else {
        rargs.rv.rv_int = generic_permission(inode, submask, NULL);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)

static int rfs_permission(struct inode *inode, int mask)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);
    int submask;

    submask = mask & ~MAY_APPEND;
    rinode = rfs_inode_find(inode);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISREG(inode->i_mode))
        rargs.type.id = REDIRFS_REG_IOP_PERMISSION;
    else if (S_ISDIR(inode->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_PERMISSION;
    else if (S_ISLNK(inode->i_mode))
        rargs.type.id = REDIRFS_LNK_IOP_PERMISSION;
    else if (S_ISCHR(inode->i_mode))
        rargs.type.id = REDIRFS_CHR_IOP_PERMISSION;
    else if (S_ISBLK(inode->i_mode))
        rargs.type.id = REDIRFS_BLK_IOP_PERMISSION;
    else if (S_ISFIFO(inode->i_mode))
        rargs.type.id = REDIRFS_FIFO_IOP_PERMISSION;
    else 
        rargs.type.id = REDIRFS_SOCK_IOP_PERMISSION;

    rargs.args.i_permission.inode = inode;
    rargs.args.i_permission.mask = mask;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->permission)
            rargs.rv.rv_int = rinode->op_old->permission(
                    rargs.args.i_permission.inode,
                    rargs.args.i_permission.mask);
        else
            rargs.rv.rv_int = generic_permission(inode, submask,
                    NULL);
    } else {
        rargs.rv.rv_int = generic_permission(inode, submask, NULL);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)

static int rfs_permission(struct inode *inode, int mask, unsigned int flags)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);
    int submask;

    submask = mask & ~MAY_APPEND;
    rinode = rfs_inode_find(inode);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISREG(inode->i_mode))
        rargs.type.id = REDIRFS_REG_IOP_PERMISSION;
    else if (S_ISDIR(inode->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_PERMISSION;
    else if (S_ISLNK(inode->i_mode))
        rargs.type.id = REDIRFS_LNK_IOP_PERMISSION;
    else if (S_ISCHR(inode->i_mode))
        rargs.type.id = REDIRFS_CHR_IOP_PERMISSION;
    else if (S_ISBLK(inode->i_mode))
        rargs.type.id = REDIRFS_BLK_IOP_PERMISSION;
    else if (S_ISFIFO(inode->i_mode))
        rargs.type.id = REDIRFS_FIFO_IOP_PERMISSION;
    else 
        rargs.type.id = REDIRFS_SOCK_IOP_PERMISSION;

    rargs.args.i_permission.inode = inode;
    rargs.args.i_permission.mask = mask;
    rargs.args.i_permission.flags = flags;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->permission)
            rargs.rv.rv_int = rinode->op_old->permission(
                    rargs.args.i_permission.inode,
                    rargs.args.i_permission.mask,
                    rargs.args.i_permission.flags);
        else
            rargs.rv.rv_int = generic_permission(inode, submask,
                    flags, NULL);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

#else

static int rfs_permission(struct inode *inode, int mask)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);
    int submask;

    submask = mask & ~MAY_APPEND;
    rinode = rfs_inode_find(inode);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISREG(inode->i_mode))
        rargs.type.id = REDIRFS_REG_IOP_PERMISSION;
    else if (S_ISDIR(inode->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_PERMISSION;
    else if (S_ISLNK(inode->i_mode))
        rargs.type.id = REDIRFS_LNK_IOP_PERMISSION;
    else if (S_ISCHR(inode->i_mode))
        rargs.type.id = REDIRFS_CHR_IOP_PERMISSION;
    else if (S_ISBLK(inode->i_mode))
        rargs.type.id = REDIRFS_BLK_IOP_PERMISSION;
    else if (S_ISFIFO(inode->i_mode))
        rargs.type.id = REDIRFS_FIFO_IOP_PERMISSION;
    else 
        rargs.type.id = REDIRFS_SOCK_IOP_PERMISSION;

    rargs.args.i_permission.inode = inode;
    rargs.args.i_permission.mask = mask;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->permission)
            rargs.rv.rv_int = rinode->op_old->permission(
                    rargs.args.i_permission.inode,
                    rargs.args.i_permission.mask);
        else
            rargs.rv.rv_int = generic_permission(inode, submask);
    } else {
        rargs.rv.rv_int = generic_permission(inode, submask);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

#endif

static int rfs_setattr_default(struct dentry *dentry, struct iattr *iattr)
{
    struct inode *inode = dentry->d_inode;
    int rv;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0) && !(LINUX_VERSION_CODE > KERNEL_VERSION(3,16,38) && LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)))
    rv = inode_change_ok(inode, iattr);
#else
    rv = setattr_prepare(dentry, iattr);
#endif
    if (rv)
        return rv;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
    if ((iattr->ia_valid & ATTR_UID && iattr->ia_uid != inode->i_uid) ||
        (iattr->ia_valid & ATTR_GID && iattr->ia_gid != inode->i_gid))
        rv = rfs_dq_transfer(inode, iattr);
    if (rv)
        return -EDQUOT;
#endif

    return rfs_inode_setattr(inode, iattr);
}

static int rfs_setattr(struct dentry *dentry, struct iattr *iattr)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rinode = rfs_inode_find(dentry->d_inode);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);

    if (S_ISREG(dentry->d_inode->i_mode))
        rargs.type.id = REDIRFS_REG_IOP_SETATTR;
    else if (S_ISDIR(dentry->d_inode->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_SETATTR;
    else if (S_ISLNK(dentry->d_inode->i_mode))
        rargs.type.id = REDIRFS_LNK_IOP_SETATTR;
    else if (S_ISCHR(dentry->d_inode->i_mode))
        rargs.type.id = REDIRFS_CHR_IOP_SETATTR;
    else if (S_ISBLK(dentry->d_inode->i_mode))
        rargs.type.id = REDIRFS_BLK_IOP_SETATTR;
    else if (S_ISFIFO(dentry->d_inode->i_mode))
        rargs.type.id = REDIRFS_FIFO_IOP_SETATTR;
    else 
        rargs.type.id = REDIRFS_SOCK_IOP_SETATTR;

    rargs.args.i_setattr.dentry = dentry;
    rargs.args.i_setattr.iattr = iattr;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->setattr)
            rargs.rv.rv_int = rinode->op_old->setattr(
                    rargs.args.i_setattr.dentry,
                    rargs.args.i_setattr.iattr);
        else 
            rargs.rv.rv_int = rfs_setattr_default(dentry, iattr);
    } else {
        rargs.rv.rv_int = rfs_setattr_default(dentry, iattr);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);
    return rargs.rv.rv_int;
}

static int rfs_precall_flts_rename(struct rfs_info *rinfo,
        struct rfs_context *rcont, struct redirfs_args *rargs)
{
    struct redirfs_filter_operations *ops;
    enum redirfs_rv (*rop)(redirfs_context, struct redirfs_args *);
    enum redirfs_rv rv;

    if (!rinfo)
        return 0;

    if (!rinfo->rchain)
        return 0;

    rargs->type.call = REDIRFS_PRECALL;

    rcont->idx = rcont->idx_start;

    for (; rcont->idx < rinfo->rchain->rflts_nr; rcont->idx++) {
        if (!atomic_read(&rinfo->rchain->rflts[rcont->idx]->active))
            continue;

        ops = rinfo->rchain->rflts[rcont->idx]->ops;
        if (!ops)
            continue;
        rop = ops->pre_rename;
        if (!rop)
            continue;

        rv = rop(rcont, rargs);
        if (rv == REDIRFS_STOP)
            return -1;
    }

    rcont->idx--;

    return 0;
}

static void rfs_postcall_flts_rename(struct rfs_info *rinfo,
        struct rfs_context *rcont, struct redirfs_args *rargs)
{
    struct redirfs_filter_operations *ops;
    enum redirfs_rv (*rop)(redirfs_context, struct redirfs_args *);

    if (!rinfo)
        return;

    if (!rinfo->rchain)
        return;

    rargs->type.call = REDIRFS_POSTCALL;

    for (; rcont->idx >= rcont->idx_start; rcont->idx--) {
        if (!atomic_read(&rinfo->rchain->rflts[rcont->idx]->active))
            continue;

        ops = rinfo->rchain->rflts[rcont->idx]->ops;
        if (!ops)
            continue;
        rop = ops->post_rename;
        if (rop) 
            rop(rcont, rargs);
    }

    rcont->idx++;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0))
int rfs_rename(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry)
{
    struct rfs_inode *rinode_old;
    struct rfs_inode *rinode_new;
    struct rfs_info *rinfo_old;
    struct rfs_info *rinfo_new;
    struct rfs_context rcont_old;
    struct rfs_context rcont_new;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfs_context_init(&rcont_old, 0);
    rinode_old = rfs_inode_find(old_dir);
    rinfo_old = rfs_inode_get_rinfo(rinode_old);

    rfs_context_init(&rcont_new, 0);
    rinode_new = rfs_inode_find(new_dir);

    if (rinode_new)
        rinfo_new = rfs_inode_get_rinfo(rinode_new);
    else
        rinfo_new = NULL;

    if (S_ISDIR(old_dir->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_RENAME;
    else
        BUG();

    rargs.args.i_rename.old_dir = old_dir;
    rargs.args.i_rename.old_dentry = old_dentry;
    rargs.args.i_rename.new_dir = new_dir;
    rargs.args.i_rename.new_dentry = new_dentry;
    rargs.rv.rv_int = -ENOSYS;

    if (RFS_IS_IOP_SET(rinode_old, rargs.type.id) &&
        rfs_precall_flts(rinfo_old->rchain, &rcont_old, &rargs))
        goto skip;

    if (RFS_IS_IOP_SET(rinode_new, rargs.type.id) &&
        rfs_precall_flts_rename(rinfo_new, &rcont_new, &rargs))
        goto skip;

    if (rinode_old->op_old && rinode_old->op_old->rename)
        rargs.rv.rv_int = rinode_old->op_old->rename(
                rargs.args.i_rename.old_dir,
                rargs.args.i_rename.old_dentry,
                rargs.args.i_rename.new_dir,
                rargs.args.i_rename.new_dentry);
    
skip:
    if (!rargs.rv.rv_int)
        rargs.rv.rv_int = rfs_fsrename(
                rargs.args.i_rename.old_dir,
                rargs.args.i_rename.old_dentry,
                rargs.args.i_rename.new_dir,
                rargs.args.i_rename.new_dentry);

    if (RFS_IS_IOP_SET(rinode_new, rargs.type.id))
        rfs_postcall_flts_rename(rinfo_new, &rcont_new, &rargs);
    if (RFS_IS_IOP_SET(rinode_old, rargs.type.id))
        rfs_postcall_flts(rinfo_old->rchain, &rcont_old, &rargs);

    rfs_context_deinit(&rcont_old);
    rfs_context_deinit(&rcont_new);
    rfs_inode_put(rinode_old);
    rfs_inode_put(rinode_new);
    rfs_info_put(rinfo_old);
    rfs_info_put(rinfo_new);
    return rargs.rv.rv_int;
}
#else
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
int rfs_rename2(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry,
        unsigned int flags)
#else
int rfs_rename(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry,
		unsigned int flags)
#endif //(LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
{
    struct rfs_inode *rinode_old;
    struct rfs_inode *rinode_new;
    struct rfs_info *rinfo_old;
    struct rfs_info *rinfo_new;
    struct rfs_context rcont_old;
    struct rfs_context rcont_new;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rfs_context_init(&rcont_old, 0);
    rinode_old = rfs_inode_find(old_dir);
    rinfo_old = rfs_inode_get_rinfo(rinode_old);

    rfs_context_init(&rcont_new, 0);
    rinode_new = rfs_inode_find(new_dir);

    if (rinode_new)
        rinfo_new = rfs_inode_get_rinfo(rinode_new);
    else
        rinfo_new = NULL;

    if (S_ISDIR(old_dir->i_mode))
        rargs.type.id = REDIRFS_DIR_IOP_RENAME;
    else
        BUG();

    rargs.args.i_rename.old_dir = old_dir;
    rargs.args.i_rename.old_dentry = old_dentry;
    rargs.args.i_rename.new_dir = new_dir;
    rargs.args.i_rename.new_dentry = new_dentry;
    rargs.args.i_rename.flags = flags;
    rargs.rv.rv_int = -ENOSYS;

    if (RFS_IS_IOP_SET(rinode_old, rargs.type.id) &&
        rfs_precall_flts(rinfo_old->rchain, &rcont_old, &rargs))
        goto skip;

    if (RFS_IS_IOP_SET(rinode_new, rargs.type.id) &&
        rfs_precall_flts_rename(rinfo_new, &rcont_new, &rargs))
        goto skip;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
    if (rinode_old->op_old && rinode_old->op_old->rename2) {
        rargs.rv.rv_int = rinode_old->op_old->rename2(
                rargs.args.i_rename.old_dir,
                rargs.args.i_rename.old_dentry,
                rargs.args.i_rename.new_dir,
                rargs.args.i_rename.new_dentry,
                rargs.args.i_rename.flags);
    } else if (rinode_old->op_old && rinode_old->op_old->rename) {
        rargs.rv.rv_int = rinode_old->op_old->rename(
                rargs.args.i_rename.old_dir,
                rargs.args.i_rename.old_dentry,
                rargs.args.i_rename.new_dir,
                rargs.args.i_rename.new_dentry);
    }
#else
    if (rinode_old->op_old && rinode_old->op_old->rename)
        rargs.rv.rv_int = rinode_old->op_old->rename(
                rargs.args.i_rename.old_dir,
                rargs.args.i_rename.old_dentry,
                rargs.args.i_rename.new_dir,
                rargs.args.i_rename.new_dentry,
                rargs.args.i_rename.flags);
#endif //(LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))

skip:
    if (!rargs.rv.rv_int)
        rargs.rv.rv_int = rfs_fsrename(
                rargs.args.i_rename.old_dir,
                rargs.args.i_rename.old_dentry,
                rargs.args.i_rename.new_dir,
                rargs.args.i_rename.new_dentry);

    if (RFS_IS_IOP_SET(rinode_new, rargs.type.id))
        rfs_postcall_flts_rename(rinfo_new, &rcont_new, &rargs);
    if (RFS_IS_IOP_SET(rinode_old, rargs.type.id))
        rfs_postcall_flts(rinfo_old->rchain, &rcont_old, &rargs);

    rfs_context_deinit(&rcont_old);
    rfs_context_deinit(&rcont_new);
    rfs_inode_put(rinode_old);
    rfs_inode_put(rinode_new);
    rfs_info_put(rinfo_old);
    rfs_info_put(rinfo_new);
    return rargs.rv.rv_int;
}
#endif //(LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0))

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,5,0))
int rfs_atomic_open(struct inode *inode, struct dentry *dentry, struct file *file, unsigned open_flag, umode_t create_mode, int *opened)
{
    struct rfs_inode *rinode;
    struct rfs_info *rinfo;
    struct rfs_context rcont;
    struct rfs_file *rfile;
    RFS_DEFINE_REDIRFS_ARGS(rargs);

    rinode = rfs_inode_find(inode);
    rinfo = rfs_inode_get_rinfo(rinode);
    rfs_context_init(&rcont, 0);
    rargs.type.id = REDIRFS_DIR_IOP_ATOMIC_OPEN;
    rargs.args.i_atomic_open.inode = inode;
    rargs.args.i_atomic_open.dentry = dentry;
    rargs.args.i_atomic_open.file = file;
    rargs.args.i_atomic_open.open_flag = open_flag;
    rargs.args.i_atomic_open.create_mode = create_mode;
    rargs.args.i_atomic_open.opened = opened;
    rargs.rv.rv_int = -ENOSYS;

    if (!RFS_IS_IOP_SET(rinode, rargs.type.id) ||
        !rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
        if (rinode->op_old && rinode->op_old->atomic_open)
            rargs.rv.rv_int = rinode->op_old->atomic_open(
	    rargs.args.i_atomic_open.inode,
	    rargs.args.i_atomic_open.dentry,
	    rargs.args.i_atomic_open.file,
	    rargs.args.i_atomic_open.open_flag,
	    rargs.args.i_atomic_open.create_mode,
	    rargs.args.i_atomic_open.opened);
    } else {
        rargs.rv.rv_int = -EACCES;
    }

    if (!rargs.rv.rv_int) {
        if (rfs_dcache_rdentry_add(dentry, rinfo))
            BUG();
        rfile = rfs_file_add(file);
        if (IS_ERR(rfile))
            BUG();
        rfs_file_put(rfile);
    }

    if (RFS_IS_IOP_SET(rinode, rargs.type.id))
        rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);

    rfs_context_deinit(&rcont);

    rfs_inode_put(rinode);
    rfs_info_put(rinfo);

    rfs_pr_debug("dentry=%p, ret=%d", dentry, rargs.rv.rv_int);
    return rargs.rv.rv_int;
}
#endif

/*---------------------------------------------------------------------------*/

/* 
 * switch on the agressive optimization to reduce the frame size 
 * bloating by multiple inline functions and local variables in
 * RFS_SET_IOP macro
 */
#pragma GCC push_options
#pragma GCC optimize ("O3")

static void rfs_inode_set_ops_reg(struct rfs_inode *rinode)
{
    RFS_SET_IOP(rinode, REDIRFS_REG_IOP_PERMISSION, permission, rfs_permission);
    RFS_SET_IOP(rinode, REDIRFS_REG_IOP_SETATTR, setattr, rfs_setattr);

    RFS_SET_AOP(rinode, REDIRFS_REG_AOP_READPAGE, readpage, rfs_readpage);
    RFS_SET_AOP(rinode, REDIRFS_REG_AOP_READPAGES, readpages, rfs_readpages);
    RFS_SET_AOP(rinode, RFS_OP_IDC(RFS_INODE_REG, RFS_OP_a_writepages), writepages, rfs_writepages);
}

static void rfs_inode_set_ops_dir(struct rfs_inode *rinode)
{
    RFS_SET_IOP(rinode, REDIRFS_DIR_IOP_UNLINK, unlink, rfs_unlink);
    RFS_SET_IOP(rinode, REDIRFS_DIR_IOP_RMDIR, rmdir, rfs_rmdir);
    RFS_SET_IOP(rinode, REDIRFS_DIR_IOP_PERMISSION, permission, rfs_permission);
    RFS_SET_IOP(rinode, REDIRFS_DIR_IOP_SETATTR, setattr, rfs_setattr);

    RFS_SET_IOP_MGT(rinode, REDIRFS_DIR_IOP_CREATE, create, rfs_create);
    RFS_SET_IOP_MGT(rinode, REDIRFS_DIR_IOP_LINK, link, rfs_link);
    RFS_SET_IOP_MGT(rinode, REDIRFS_DIR_IOP_MKNOD, mknod, rfs_mknod);
    RFS_SET_IOP_MGT(rinode, REDIRFS_DIR_IOP_SYMLINK, symlink, rfs_symlink);

    //
    // the following operations are required to support hooking,
    // their registration do not dependent on registered filters
    //
    RFS_SET_IOP_MGT(rinode, REDIRFS_DIR_IOP_LOOKUP, lookup, rfs_lookup);
    RFS_SET_IOP_MGT(rinode, REDIRFS_DIR_IOP_MKDIR, mkdir, rfs_mkdir);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,5,0))
    // hook atomic_open when i_op has it
    if (rinode->op_old->atomic_open)
        RFS_SET_IOP_MGT(rinode, REDIRFS_DIR_IOP_ATOMIC_OPEN, atomic_open, rfs_atomic_open);
#endif
}

static void rfs_inode_set_ops_lnk(struct rfs_inode *rinode)
{
    RFS_SET_IOP(rinode, REDIRFS_LNK_IOP_PERMISSION, permission, rfs_permission);
    RFS_SET_IOP(rinode, REDIRFS_LNK_IOP_SETATTR, setattr, rfs_setattr);
}

static void rfs_inode_set_ops_chr(struct rfs_inode *rinode)
{
    RFS_SET_IOP(rinode, REDIRFS_CHR_IOP_PERMISSION, permission, rfs_permission);
    RFS_SET_IOP(rinode, REDIRFS_CHR_IOP_SETATTR, setattr, rfs_setattr);
}

static void rfs_inode_set_ops_blk(struct rfs_inode *rinode)
{
    RFS_SET_IOP(rinode, REDIRFS_BLK_IOP_PERMISSION, permission, rfs_permission);
    RFS_SET_IOP(rinode, REDIRFS_BLK_IOP_SETATTR, setattr, rfs_setattr);
}

static void rfs_inode_set_ops_fifo(struct rfs_inode *rinode)
{
    RFS_SET_IOP(rinode, REDIRFS_FIFO_IOP_PERMISSION, permission, rfs_permission);
    RFS_SET_IOP(rinode, REDIRFS_FIFO_IOP_SETATTR, setattr, rfs_setattr);
}

static void rfs_inode_set_ops_sock(struct rfs_inode *rinode)
{
    RFS_SET_IOP(rinode, REDIRFS_SOCK_IOP_PERMISSION, permission, rfs_permission);
    RFS_SET_IOP(rinode, REDIRFS_SOCK_IOP_SETATTR, setattr, rfs_setattr);
}

static void rfs_inode_set_aops_reg(struct rfs_inode *rinode)
{
}

void rfs_inode_set_ops(struct rfs_inode *rinode)
{
    umode_t mode = rinode->inode->i_mode;

    spin_lock(&rinode->lock);
    {
        if (S_ISREG(mode)) {
            rfs_inode_set_ops_reg(rinode);
            rfs_inode_set_aops_reg(rinode);
        } else if (S_ISDIR(mode))
            rfs_inode_set_ops_dir(rinode);

        else if (S_ISLNK(mode))
            rfs_inode_set_ops_lnk(rinode);

        else if (S_ISCHR(mode))
            rfs_inode_set_ops_chr(rinode);

        else if (S_ISBLK(mode))
            rfs_inode_set_ops_blk(rinode);

        else if (S_ISFIFO(mode))
            rfs_inode_set_ops_fifo(rinode);

        else if (S_ISSOCK(mode))
            rfs_inode_set_ops_sock(rinode);
            
    #ifndef RFS_PER_OBJECT_OPS
    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
        RFS_SET_IOP_MGT(rinode,
                        RFS_OP_IDC(rfs_imode_to_type(mode, false), RFS_OP_i_rename2),
                        rename2,
                        rfs_rename2);
        RFS_SET_IOP_MGT(rinode,
                        RFS_OP_IDC(rfs_imode_to_type(mode, false), RFS_OP_i_rename),
                        rename,
                        NULL);
    #else
        RFS_SET_IOP_MGT(rinode,
                        RFS_OP_IDC(rfs_imode_to_type(mode, false), RFS_OP_i_rename),
                        rename,
                        rfs_rename);
    #endif

    #endif /* !RFS_PER_OBJECT_OPS */
    }
    spin_unlock(&rinode->lock);
    
#ifndef RFS_PER_OBJECT_OPS
    spin_lock(&rinode->inode->i_lock);
    {
        DBG_BUG_ON(rinode->op_old != rinode->inode->i_op &&
                   rinode->inode->i_op != rinode->i_rhops->new.i_op);
        DBG_BUG_ON(!rinode->i_rhops->new.i_op);
        if (rinode->inode->i_op != rinode->i_rhops->new.i_op)
            rinode->inode->i_op = rinode->i_rhops->new.i_op;

        if (rinode->inode->i_mapping && rinode->inode->i_mapping->a_ops) {
            DBG_BUG_ON(!rinode->a_rhops);
            DBG_BUG_ON(rinode->a_op_old != rinode->inode->i_mapping->a_ops &&
                       rinode->inode->i_mapping->a_ops != rinode->a_rhops->new.a_op);
            DBG_BUG_ON(!rinode->a_rhops->new.a_op);
            if (rinode->inode->i_mapping->a_ops != rinode->a_rhops->new.a_op)
                rinode->inode->i_mapping->a_ops = rinode->a_rhops->new.a_op;
        }
    }
    spin_unlock(&rinode->inode->i_lock);
#endif /* !RFS_PER_OBJECT_OPS */
}

#pragma GCC pop_options

/*---------------------------------------------------------------------------*/

#ifdef RFS_DBG
    #pragma GCC pop_options
#endif // RFS_DBG
