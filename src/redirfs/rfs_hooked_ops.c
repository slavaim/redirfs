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

#include <linux/slab.h>
#include "rfs_hooked_ops.h"
#include "rfs_dbg.h"
#include "rfs.h"

/*---------------------------------------------------------------------------*/

#ifdef RFS_USE_HASHTABLE
#error "a hash table is not defined"
#else
static struct rfs_radix_tree   rfs_f_hoperations_radix_tree = {
    .root = RADIX_TREE_INIT(GFP_ATOMIC),
    .lock = __SPIN_LOCK_INITIALIZER(rfs_f_hoperations_radix_tree.lock),
    .rfs_type = RFS_TYPE_FILE_OPS,
};

static struct rfs_radix_tree   rfs_i_hoperations_radix_tree = {
    .root = RADIX_TREE_INIT(GFP_ATOMIC),
    .lock = __SPIN_LOCK_INITIALIZER(rfs_i_hoperations_radix_tree.lock),
    .rfs_type = RFS_TYPE_INODE_OPS,
};

static struct rfs_radix_tree   rfs_a_hoperations_radix_tree = {
    .root = RADIX_TREE_INIT(GFP_ATOMIC),
    .lock = __SPIN_LOCK_INITIALIZER(rfs_a_hoperations_radix_tree.lock),
    .rfs_type = RFS_TYPE_AS_OPS,
};

static struct rfs_radix_tree   rfs_d_hoperations_radix_tree = {
    .root = RADIX_TREE_INIT(GFP_ATOMIC),
    .lock = __SPIN_LOCK_INITIALIZER(rfs_d_hoperations_radix_tree.lock),
    .rfs_type = RFS_TYPE_DENTRY_OPS,
};

struct rfs_radix_tree*  rfs_hoperations_radix_tree[RFS_TYPE_MAX] = {
    [RFS_TYPE_FILE_OPS]=&rfs_f_hoperations_radix_tree,
    [RFS_TYPE_INODE_OPS]=&rfs_i_hoperations_radix_tree,
    [RFS_TYPE_AS_OPS]=&rfs_a_hoperations_radix_tree,
    [RFS_TYPE_DENTRY_OPS]=&rfs_d_hoperations_radix_tree,
};
#endif /* !RFS_USE_HASHTABLE */

/*---------------------------------------------------------------------------*/

/* returns an old flags value */
static unsigned int
rfs_hoperations_set_flags(
    struct rfs_hoperations *rfs_hoperations,
    unsigned int flags_to_set,
    unsigned int flags_to_remove)
{
    unsigned int old_flags, new_flags;

    do {
        old_flags = ACCESS_ONCE(rfs_hoperations->flags);
        new_flags = (old_flags & ~flags_to_remove) | flags_to_set;
    } while (unlikely(cmpxchg(&rfs_hoperations->flags, old_flags,
                  new_flags) != old_flags));

    return old_flags;
}

/*---------------------------------------------------------------------------*/

#ifdef RFS_USE_HASHTABLE
#error "rfs_keep_operations is not defined for a hash table"
#else
void
rfs_keep_operations(
    struct rfs_hoperations *rfs_hoperations)
{
    int err;
    unsigned int old_flags;
    enum rfs_type type;

    if (0x1 != atomic_inc_return(&rfs_hoperations->keep_alive))
        return;

    old_flags = rfs_hoperations_set_flags(rfs_hoperations,
                                          RFS_OPS_INSERTED,
                                          0);

    /*
     * the multiple insert-remove cycles are not supported
     * because of concurrency issues with rfs_insert_object
     * and rfs_remove_object
     */
    if (old_flags & RFS_OPS_INSERTED)
        return;

    type = rfs_hoperations->robject.type->type;
    DBG_BUG_ON(type == RFS_TYPE_UNKNOWN || type >= RFS_TYPE_MAX);
    DBG_BUG_ON(!rfs_hoperations_radix_tree[type]);
    DBG_BUG_ON(rfs_hoperations_radix_tree[type]->rfs_type != type);

    err = rfs_insert_object(rfs_hoperations_radix_tree[type],
                            &rfs_hoperations->robject,
                            true);
    DBG_BUG_ON(err && (-EEXIST != err));
    if (unlikely(err)) {
        rfs_hoperations_set_flags(rfs_hoperations,
                                  0,
                                  RFS_OPS_INSERTED);
    }
}
#endif /* !RFS_USE_HASHTABLE */

/*---------------------------------------------------------------------------*/

void
rfs_unkeep_operations(
    struct rfs_hoperations* rfs_hoperations)
{
    unsigned int old_flags;

    if (!atomic_dec_and_test(&rfs_hoperations->keep_alive))
        return;

    /*
     * remove from the table, do not remove RFS_OPS_INSERTED flag
     * as insert and remove functions can't be called concurrently
     * in case a concurren thread calls rfs_ops_object_keep_alive
     */
    old_flags = rfs_hoperations_set_flags(rfs_hoperations,
                                         RFS_OPS_REMOVED,
                                         0);

    if (RFS_OPS_INSERTED == ((RFS_OPS_INSERTED | RFS_OPS_REMOVED) & old_flags)) {
        rfs_remove_object(&rfs_hoperations->robject);
    }
}

/*---------------------------------------------------------------------------*/

#ifdef RFS_USE_HASHTABLE
#error "rfs_find_operations is not defined for a hash table"
#else
struct rfs_hoperations*
rfs_find_operations(
    struct rfs_radix_tree *radix_tree,
    const void  *old_op)
{
    struct rfs_object      *robject;
    struct rfs_hoperations *rfs_hoperations;

    robject = rfs_get_object_by_system_object(radix_tree,
                                              old_op);
    if (!robject)
        return NULL;

    rfs_hoperations = container_of(robject,
                                   struct rfs_hoperations,
                                   robject);
    DBG_BUG_ON(RFS_HOPERATIONS_SIGNATURE != rfs_hoperations->signature);

    return rfs_hoperations;
}
#endif

/*---------------------------------------------------------------------------*/

static void
rfs_free_file_operations(
    struct rfs_object* robject)
{
    struct rfs_hoperations *rhoperations;

    rhoperations = container_of(robject,
                                   struct rfs_hoperations,
                                   robject);

    DBG_BUG_ON(RFS_HOPERATIONS_SIGNATURE != rhoperations->signature);
    DBG_BUG_ON(!(RFS_OPS_FILE & rhoperations->flags));
    DBG_BUG_ON(RFS_OPS_INSERTED == ((RFS_OPS_INSERTED | RFS_OPS_REMOVED) & rhoperations->flags));

    if (rhoperations->old.f_op)
        fops_put(rhoperations->old.f_op);

    kfree(rhoperations);
}

static struct rfs_object_type rfs_file_operations_type = {
    .type = RFS_TYPE_FILE_OPS,
    .free = rfs_free_file_operations,
    };

/*---------------------------------------------------------------------------*/

struct rfs_hoperations*
rfs_create_file_ops(
    const struct file_operations *op_old)
{
    long                    err = 0;
    struct rfs_hoperations  *rhoperations = NULL;
    size_t                  size;

    DBG_BUG_ON(!preemptible());
    DBG_BUG_ON(!op_old);
    if (!op_old)
        return NULL;

    rhoperations = rfs_find_operations(rfs_hoperations_radix_tree[RFS_TYPE_FILE_OPS],
                                       op_old);
    if (rhoperations) {
        /* found in the table */
        goto exit;
    }
    
    /* allocate space for the object and file operations just right after it */
    size = sizeof(*rhoperations) + sizeof(*rhoperations->new.f_op);
    rhoperations = kzalloc(size, GFP_KERNEL);
    DBG_BUG_ON(!rhoperations);
    if (!rhoperations) {
        err = -ENOMEM;
        goto exit;
    }

    rfs_object_init(&rhoperations->robject,
                    &rfs_file_operations_type,
                    op_old);

#ifdef RFS_DBG
    rhoperations->signature = RFS_HOPERATIONS_SIGNATURE;
#endif /* RFS_DBG */

    rhoperations->flags = RFS_OPS_FILE;

    /* the space for new file operations is located after the object */
    rhoperations->new.f_op = (struct file_operations *)(rhoperations + 1);
    
    /* copy the old operations to the new ones */
    *rhoperations->new.f_op = *op_old;

    rhoperations->old.f_op = fops_get(op_old);
    DBG_BUG_ON(!rhoperations->old.f_op);
    if (!rhoperations->old.f_op) {
        err = -EINVAL;
        goto exit;
    }

exit:

    if (err && rhoperations)
        rfs_object_put(&rhoperations->robject);

    return err ? ERR_PTR(err) : rhoperations;
}

/*---------------------------------------------------------------------------*/

static void
rfs_free_inode_operations(
    struct rfs_object* robject)
{
    struct rfs_hoperations *rhoperations;

    rhoperations = container_of(robject,
                                struct rfs_hoperations,
                                robject);

    DBG_BUG_ON(RFS_HOPERATIONS_SIGNATURE != rhoperations->signature);
    DBG_BUG_ON(!(RFS_OPS_INODE & rhoperations->flags));
    DBG_BUG_ON(RFS_OPS_INSERTED == ((RFS_OPS_INSERTED | RFS_OPS_REMOVED) & rhoperations->flags));

    kfree(rhoperations);
}

static struct rfs_object_type rfs_inode_operations_type = {
    .type = RFS_TYPE_INODE_OPS,
    .free = rfs_free_inode_operations,
    };

/*---------------------------------------------------------------------------*/

struct rfs_hoperations*
rfs_create_inode_ops(
    const struct inode_operations *op_old)
{
    long                    err = 0;
    struct rfs_hoperations  *rhoperations = NULL;
    size_t                  size;

    DBG_BUG_ON(!preemptible());
    DBG_BUG_ON(!op_old);
    if (!op_old)
        return ERR_PTR(-EINVAL); 

    rhoperations = rfs_find_operations(rfs_hoperations_radix_tree[RFS_TYPE_INODE_OPS],
                                       op_old);
    if (rhoperations) {
        /* found in the table */
        goto exit;
    }

    /* allocate space for the object and file operations just right after it */
    size = sizeof(*rhoperations) + sizeof(*rhoperations->new.i_op);
    rhoperations = kzalloc(size, GFP_KERNEL);
    DBG_BUG_ON(!rhoperations);
    if (!rhoperations) {
        err = -ENOMEM;
        goto exit;
    }

    rfs_object_init(&rhoperations->robject,
                    &rfs_inode_operations_type,
                    op_old);

#ifdef RFS_DBG
    rhoperations->signature = RFS_HOPERATIONS_SIGNATURE;
#endif /* RFS_DBG */

    rhoperations->flags = RFS_OPS_INODE;
    rhoperations->old.i_op = op_old;
    /* the space for new file operations is located after the object */
    rhoperations->new.i_op = (struct inode_operations *)(rhoperations + 1);
    /* copy the old operations to the new ones */
    *rhoperations->new.i_op = *op_old;

exit:

    if (err && rhoperations)
        rfs_object_put(&rhoperations->robject);

    return err ? ERR_PTR(err) : rhoperations;
}

/*---------------------------------------------------------------------------*/

static void
rfs_free_address_space_operations(
    struct rfs_object* robject)
{
    struct rfs_hoperations *rhoperations;

    rhoperations = container_of(robject,
                                struct rfs_hoperations,
                                robject);

    DBG_BUG_ON(RFS_HOPERATIONS_SIGNATURE != rhoperations->signature);
    DBG_BUG_ON(!(RFS_OPS_AS & rhoperations->flags));
    DBG_BUG_ON(RFS_OPS_INSERTED == ((RFS_OPS_INSERTED | RFS_OPS_REMOVED) & rhoperations->flags));

    kfree(rhoperations);
}

static struct rfs_object_type rfs_address_space_operations_type = {
    .type = RFS_TYPE_AS_OPS,
    .free = rfs_free_address_space_operations,
    };

/*---------------------------------------------------------------------------*/

struct rfs_hoperations*
rfs_create_address_space_ops(
    const struct address_space_operations *op_old)
{
    long                    err = 0;
    struct rfs_hoperations  *rhoperations = NULL;
    size_t                  size;

    DBG_BUG_ON(!preemptible());
    DBG_BUG_ON(!op_old);
    if (!op_old)
        return ERR_PTR(-EINVAL); 

    rhoperations = rfs_find_operations(rfs_hoperations_radix_tree[RFS_TYPE_AS_OPS],
                                       op_old);
    if (rhoperations) {
        /* found in the table */
        goto exit;
    }

    /* allocate space for the object and file operations just right after it */
    size = sizeof(*rhoperations) + sizeof(*rhoperations->new.a_op);
    rhoperations = kzalloc(size, GFP_KERNEL);
    DBG_BUG_ON(!rhoperations);
    if (!rhoperations) {
        err = -ENOMEM;
        goto exit;
    }

    rfs_object_init(&rhoperations->robject,
                    &rfs_address_space_operations_type,
                    op_old);

#ifdef RFS_DBG
    rhoperations->signature = RFS_HOPERATIONS_SIGNATURE;
#endif /* RFS_DBG */

    rhoperations->flags = RFS_OPS_AS;
    rhoperations->old.a_op = op_old;
    /* the space for new file operations is located after the object */
    rhoperations->new.a_op = (struct address_space_operations *)(rhoperations + 1);
    /* copy the old operations to the new ones */
    *rhoperations->new.a_op = *op_old;

exit:

    if (err && rhoperations)
        rfs_object_put(&rhoperations->robject);

    return err ? ERR_PTR(err) : rhoperations;
}

/*---------------------------------------------------------------------------*/

static void
rfs_free_dentry_operations(
    struct rfs_object* robject)
{
    struct rfs_hoperations *rhoperations;

    rhoperations = container_of(robject,
                                struct rfs_hoperations,
                                robject);

    DBG_BUG_ON(RFS_HOPERATIONS_SIGNATURE != rhoperations->signature);
    DBG_BUG_ON(!(RFS_OPS_DENTRY & rhoperations->flags));
    DBG_BUG_ON(RFS_OPS_INSERTED == ((RFS_OPS_INSERTED | RFS_OPS_REMOVED) & rhoperations->flags));

    kfree(rhoperations);
}

static struct rfs_object_type rfs_dentry_type = {
    .type = RFS_TYPE_DENTRY_OPS,
    .free = rfs_free_dentry_operations,
    };

/*---------------------------------------------------------------------------*/

struct rfs_hoperations*
rfs_create_dentry_ops(
    const struct dentry_operations *op_old)
{
    long                    err = 0;
    struct rfs_hoperations  *rhoperations = NULL;
    size_t                  size;

    DBG_BUG_ON(!preemptible());

    /* op_old might be NULL for some dentries */
    rhoperations = rfs_find_operations(rfs_hoperations_radix_tree[RFS_TYPE_DENTRY_OPS],
                                       op_old);
    if (rhoperations) {
        /* found in the table */
        goto exit;
    }

    /* allocate space for the object and file operations just right after it */
    size = sizeof(*rhoperations) + sizeof(*rhoperations->new.d_op);
    rhoperations = kzalloc(size, GFP_KERNEL);
    DBG_BUG_ON(!rhoperations);
    if (!rhoperations) {
        err = -ENOMEM;
        goto exit;
    }

    rfs_object_init(&rhoperations->robject,
                    &rfs_dentry_type,
                    op_old);

#ifdef RFS_DBG
    rhoperations->signature = RFS_HOPERATIONS_SIGNATURE;
#endif /* RFS_DBG */

    rhoperations->flags = RFS_OPS_DENTRY;
    rhoperations->old.d_op = op_old;
    /* the space for new file operations is located after the object */
    rhoperations->new.d_op = (struct dentry_operations *)(rhoperations + 1);
    /* copy the old operations to the new ones */
    if (op_old)
        *rhoperations->new.d_op = *op_old;

exit:

    if (err && rhoperations)
        rfs_object_put(&rhoperations->robject);

    return err ? ERR_PTR(err) : rhoperations;
}

/*---------------------------------------------------------------------------*/