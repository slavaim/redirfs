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
struct rfs_radix_tree   rfs_hoperations_radix_tree = {
    .root = RADIX_TREE_INIT(GFP_KERNEL),
    .lock = __SPIN_LOCK_INITIALIZER(rfs_hoperations_radix_tree.lock),
    .rfs_type = RFS_TYPE_UNKNOWN,
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

    err = rfs_insert_object(&rfs_hoperations_radix_tree,
                            &rfs_hoperations->rfs_object,
                            true);
    DBG_BUG_ON(err && (-EEXIST != err));
    if (err) {
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
        rfs_remove_object(&rfs_hoperations->rfs_object);
    }
}

/*---------------------------------------------------------------------------*/

#ifdef RFS_USE_HASHTABLE
#error "rfs_find_operations is not defined for a hash table"
#else
struct rfs_hoperations*
rfs_find_operations(
    const void  *old_op)
{
    struct rfs_object     *rfs_object;
    struct rfs_hoperations *rfs_hoperations;

    rfs_object = rfs_get_object_by_system_object(&rfs_hoperations_radix_tree,
                                                 old_op);
    if (!rfs_object)
        return NULL;

    rfs_hoperations = container_of(rfs_object,
                                  struct rfs_hoperations,
                                  rfs_object);
    DBG_BUG_ON(RFS_HOPERATIONS_SIGNATURE != rfs_hoperations->signature);

    return rfs_hoperations;
}
#endif

/*---------------------------------------------------------------------------*/

static void
rfs_free_file_operations(
    struct rfs_object* rfs_object)
{
    struct rfs_hoperations *rfs_hoperations;

    rfs_hoperations = container_of(rfs_object,
                                   struct rfs_hoperations,
                                   rfs_object);

    DBG_BUG_ON(RFS_HOPERATIONS_SIGNATURE != rfs_hoperations->signature);
    DBG_BUG_ON(!(RFS_OPS_FILE & rfs_hoperations->flags));
    DBG_BUG_ON(RFS_OPS_INSERTED == ((RFS_OPS_INSERTED | RFS_OPS_REMOVED) & rfs_hoperations->flags));

    if (rfs_hoperations->old.f_op)
        fops_put(rfs_hoperations->old.f_op);

	kfree(rfs_hoperations);
}

static struct rfs_object_type rfs_file_operations_type = {
    .type = RFS_TYPE_FILE_OPS,
    .free = rfs_free_file_operations,
    };

/*---------------------------------------------------------------------------*/

struct rfs_hoperations*
rfs_create_file_ops(
    struct rfs_file     *rfile)
{
    long   err = 0;
    struct rfs_hoperations  *rfs_hoperations = NULL;
    struct file             *file = NULL;
    size_t                  size;

    DBG_BUG_ON(!rfile->op_old);
    
    file = rfile->file;

    rfs_hoperations = rfs_find_operations(rfile->op_old);
    if (rfs_hoperations) {
        /* found in the table */
        goto exit;
    }

    /* allocate space for the object and file operations just right after it */
    size = sizeof(*rfs_hoperations) + sizeof(*rfs_hoperations->new.f_op);
    rfs_hoperations = kzalloc(size, GFP_KERNEL);
    DBG_BUG_ON(!rfs_hoperations);
    if (!rfs_hoperations) {
        err = -ENOMEM;
        goto exit;
    }

    rfs_object_init(&rfs_hoperations->rfs_object,
                    &rfs_file_operations_type,
                    rfile->op_old);

#if RFS_DBG
    rfs_hoperations->signature = RFS_HOPERATIONS_SIGNATURE;
#endif /* RFS_DBG */

    rfs_hoperations->flags = RFS_OPS_FILE;

    rfs_hoperations->old.f_op = fops_get(rfile->op_old);
    DBG_BUG_ON(!rfs_hoperations->old.f_op);
    if (!rfs_hoperations->old.f_op) {
        err = -EINVAL;
        goto exit;
    }

    /* the space for new file operations is located after the object */
    rfs_hoperations->new.f_op = (struct file_operations *)(rfs_hoperations + 1);
    /* copy the old operations to the new ones */
    *rfs_hoperations->new.f_op = *rfile->op_old;

exit:

    if (err && rfs_hoperations)
        rfs_object_put(&rfs_hoperations->rfs_object);

    return err ? ERR_PTR(err) : rfs_hoperations;
}

/*---------------------------------------------------------------------------*/