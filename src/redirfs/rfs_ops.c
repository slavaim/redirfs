/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * History:
 * 2017 - modified by by Slava Imameev
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

/* the number of allocations for the debug purposses */
static atomic_t ops_allocations_count = ATOMIC_INIT(0);

struct rfs_ops *rfs_ops_alloc(void)
{
    struct rfs_ops *rops;

    DBG_BUG_ON(!preemptible());

    rops = kzalloc(sizeof(struct rfs_ops), GFP_KERNEL);
    WARN_ON(!rops);
    if (!rops) {
        return ERR_PTR(-ENOMEM);
    }

    atomic_inc(&ops_allocations_count);

    memset(rops->arr, 0, sizeof(rops->arr)) ;
    atomic_set(&rops->count, 1);

    return rops;
}

struct rfs_ops *rfs_ops_get(struct rfs_ops *rops)
{
    if (!rops || IS_ERR(rops))
        return NULL;

    BUG_ON(!atomic_read(&rops->count));
    atomic_inc(&rops->count);
    return rops;
}

void rfs_ops_put(struct rfs_ops *rops)
{
    if (!rops || IS_ERR(rops))
        return;

    BUG_ON(!atomic_read(&rops->count));
    if (!atomic_dec_and_test(&rops->count))
        return;

    kfree(rops);
    atomic_dec(&ops_allocations_count);
}

#ifdef RFS_DBG
    #pragma GCC pop_options
#endif // RFS_DBG
