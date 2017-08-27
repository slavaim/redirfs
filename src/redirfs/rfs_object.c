/*
 * RedirFS: Redirecting File System
 *
 * Copyright 2017 SLava Imameev
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

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include "rfs_object.h"

#ifdef RFS_DBG
    #pragma GCC push_options
    #pragma GCC optimize ("O0")
#endif // RFS_DBG

/*---------------------------------------------------------------------------*/

struct rfs_object_table_entry {
    struct list_head   hash_list_head;
    spinlock_t         lock;
};

#define OBJ_TABLE_SIZE 257

#define HASH_TABLE_INDEX(system_object) ((((unsigned long)system_object) >> 5) % OBJ_TABLE_SIZE)

/*---------------------------------------------------------------------------*/

struct rfs_objects_table {
    struct rfs_object_table_entry  entries[OBJ_TABLE_SIZE];
};

/* common table not divided by object types, i.e. hosts any object */
static struct rfs_objects_table rfs_objects_table_common;

/*---------------------------------------------------------------------------*/

#ifdef RFS_DBG
struct rfs_objects_debug_info {
    /* a list of allocated objects for debug purposses */
    struct list_head    objects_list_head;

    /* protects the list */
    spinlock_t          lock;

    /* counts allocated objects */
    atomic_t            objects_count;
};

static struct rfs_objects_debug_info   rfs_objects_debug_info[RFS_TYPE_MAX];
#endif // RFS_DBG

/*---------------------------------------------------------------------------*/

void rfs_objects_table_init(void)
{
    int i;

    for (i=0; i < ARRAY_SIZE(rfs_objects_table_common.entries); ++i) {
        INIT_LIST_HEAD_RCU(&rfs_objects_table_common.entries[i].hash_list_head);
        spin_lock_init(&rfs_objects_table_common.entries[i].lock);
    }

#ifdef RFS_DBG
    for (i = 0; i < ARRAY_SIZE(rfs_objects_debug_info); ++i) {
        INIT_LIST_HEAD(&rfs_objects_debug_info[i].objects_list_head);
        spin_lock_init(&rfs_objects_debug_info[i].lock);
    }
#endif // RFS_DBG
}

/*---------------------------------------------------------------------------*/

static struct rfs_object_table_entry* rfs_object_hash_entry(
    void* system_object,
    enum rfs_type rfs_type)
{
    return &rfs_objects_table_common.entries[HASH_TABLE_INDEX(system_object)];
}

/*---------------------------------------------------------------------------*/

struct rfs_object* rfs_get_object_by_system_object(
    void          * system_object,
    enum rfs_type rfs_type)
{
    struct rfs_object_table_entry   *table_entry;

    table_entry = rfs_object_hash_entry(system_object, rfs_type);

    rcu_read_lock();
    { /* start of the RCU lock */
        struct rfs_object *rfs_object;

        list_for_each_entry_rcu(rfs_object, &table_entry->hash_list_head, u.hash_list_entry) {

            DBG_BUG_ON(!refcount_read(&rfs_object->refcount));
            DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);

            if (rfs_object->system_object == system_object){

                /* bump the reference count */
                refcount_inc(&rfs_object->refcount);
                rcu_read_unlock();
                return rfs_object;
            }
        } /* end list_for_each_entry */

    } /* end of the RCU lock */
    rcu_read_unlock();

    return NULL;
}

/*---------------------------------------------------------------------------*/

int rfs_insert_object(
    struct rfs_object   *rfs_object,
    bool                check_for_duplicate)
/*
* -EEXIST is returned in case of a duplicate
*/
{
    int error = 0;
    struct rfs_object_table_entry   *table_entry;

    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);
    DBG_BUG_ON(!refcount_read(&rfs_object->refcount));
    DBG_BUG_ON(!rfs_object->system_object);
    DBG_BUG_ON(rfs_object->type->type >= RFS_TYPE_MAX);
    DBG_BUG_ON(!list_empty(&rfs_object->u.hash_list_entry));

    table_entry = rfs_object_hash_entry(rfs_object->system_object,
                                        rfs_object->type->type);

    /* bump the reference count */
    rfs_object_get(rfs_object);

    spin_lock(&table_entry->lock);
    { /* start of the lock */

#ifdef RFS_DBG
        {
#else
        if (check_for_duplicate) {
#endif
            struct rfs_object *found_rfs_object;
            list_for_each_entry_rcu(found_rfs_object, &table_entry->hash_list_head, u.hash_list_entry) {

                DBG_BUG_ON(RFS_OBJECT_SIGNATURE != found_rfs_object->signature);
                DBG_BUG_ON(!refcount_read(&found_rfs_object->refcount));

                if (rfs_object->system_object == found_rfs_object->system_object) {
                    DBG_BUG_ON(!check_for_duplicate);
                    error = -EEXIST;
                    break;
                }
            } /* end list_for_each_entry */
        } /* end if (check_for_duplicate) */

        if (!error) {
            list_add_rcu(&rfs_object->u.hash_list_entry, &table_entry->hash_list_head);
        }

    } /* end of the lock */
    spin_unlock(&table_entry->lock);

    /* undo in case of error */
    if (error)
        rfs_object_put(rfs_object);

    DBG_BUG_ON(!refcount_read(&rfs_object->refcount));

    return error;
}

/*---------------------------------------------------------------------------*/

/* the object is initialized with a refcount set to 1 */
void rfs_object_init(
    struct rfs_object       *rfs_object,
    struct rfs_object_type  *type,
    void                    *system_object)
{
    DBG_BUG_ON(type->type >= RFS_TYPE_MAX);
    DBG_BUG_ON(!type->free);
    DBG_BUG_ON(!system_object);

    INIT_LIST_HEAD_RCU(&rfs_object->u.hash_list_entry);
    refcount_set(&rfs_object->refcount, 1);
    rfs_object->type = type;
    rfs_object->system_object = system_object;

#ifdef RFS_DBG
    {
        struct rfs_objects_debug_info  *di = &rfs_objects_debug_info[rfs_object->type->type];

        rfs_object->signature = RFS_OBJECT_SIGNATURE;
        atomic_inc(&di->objects_count);

        spin_lock(&di->lock);
        {
            list_add(&rfs_object->objects_list, &di->objects_list_head);
        }
        spin_unlock(&di->lock);
    }
#endif //RFS_DBG
}

/*---------------------------------------------------------------------------*/

void rfs_remove_object(
    struct rfs_object   *rfs_object,
    bool                check_for_duplicate)
{
    struct rfs_object_table_entry   *table_entry;

    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);

    table_entry = rfs_object_hash_entry(rfs_object->system_object,
                                        rfs_object->type->type);

    DBG_BUG_ON(LIST_POISON2 == rfs_object->u.hash_list_entry.prev);

    spin_lock(&table_entry->lock);
    { /* start of the lock */
        list_del_rcu(&rfs_object->u.hash_list_entry);
    } /* end of the lock */
    spin_unlock(&table_entry->lock);

    rfs_object_put(rfs_object);
}

/*---------------------------------------------------------------------------*/

void rfs_object_free_rcu(
    struct rcu_head *rcu_head)
{
    struct rfs_object *rfs_object;

    rfs_object = container_of(rcu_head, struct rfs_object, u.rcu_head);
    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);

#ifdef RFS_DBG
    {
        struct rfs_objects_debug_info  *di = &rfs_objects_debug_info[rfs_object->type->type];

        DBG_BUG_ON(!atomic_read(&di->objects_count));
        atomic_dec(&di->objects_count);

        spin_lock(&di->lock);
        {
            list_del(&rfs_object->objects_list);
        }
        spin_unlock(&di->lock);
    }
#endif //RFS_DBG

    rfs_object->type->free(rfs_object);
}

/*---------------------------------------------------------------------------*/

void rfs_object_get(
    struct rfs_object   *rfs_object)
{
    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);
    DBG_BUG_ON(!refcount_read(&rfs_object->refcount));

    refcount_inc(&rfs_object->refcount);
}

void rfs_object_put(
    struct rfs_object   *rfs_object)
{
    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);
    DBG_BUG_ON(!refcount_read(&rfs_object->refcount));

    if (refcount_dec_and_test(&rfs_object->refcount))
        call_rcu(&rfs_object->u.rcu_head, rfs_object_free_rcu);
}

/*---------------------------------------------------------------------------*/

#ifdef RFS_DBG
    #pragma GCC pop_options
#endif // RFS_DBG