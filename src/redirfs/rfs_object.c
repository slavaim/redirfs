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

#include <linux/rculist.h>
#include "rfs_object.h"
#include "rfs_dbg.h"

#ifdef RFS_DBG
    #pragma GCC push_options
    #pragma GCC optimize ("O0")
    /*compiletime_assert_atomic_type failes w/o optimization*/
    #undef compiletime_assert_atomic_type
    #define compiletime_assert_atomic_type(t)
#endif // RFS_DBG

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

void rfs_object_susbsystem_init(void)
{
#ifdef RFS_DBG
    int i;
    for (i = 0; i < ARRAY_SIZE(rfs_objects_debug_info); ++i) {
        INIT_LIST_HEAD(&rfs_objects_debug_info[i].objects_list_head);
        spin_lock_init(&rfs_objects_debug_info[i].lock);
    }
#endif // RFS_DBG
}

/*---------------------------------------------------------------------------*/

/* forward definitions */
static void
rfs_object_put_rcu(
    struct rcu_head *rcu_head);

/*---------------------------------------------------------------------------*/

#ifdef RFS_USE_HASHTABLE

void
rfs_object_table_init(
    struct rfs_object_table *table)
{
    int i;

    DBG_BUG_ON(table->rfs_type >= RFS_TYPE_MAX);
    DBG_BUG_ON(!table->array_size);

    for (i=0; i < table->array_size; ++i) {
        INIT_LIST_HEAD_RCU(&table->array[i].hash_list_head);
        spin_lock_init(&table->array[i].lock);
    }
}

/*---------------------------------------------------------------------------*/

static struct rfs_object_table_entry* rfs_object_hash_entry(
    struct rfs_object_table *table,
    void* system_object)
{
    return &table->array[table->index((unsigned long)system_object)];
}

/*---------------------------------------------------------------------------*/

struct rfs_object*
rfs_get_object_by_system_object(
    struct rfs_object_table *rfs_object_table,
    const void              *system_object)
{
    struct rfs_object_table_entry   *table_entry;

    DBG_BUG_ON(!system_object);

    table_entry = rfs_object_hash_entry(rfs_object_table, system_object);

    rcu_read_lock();
    { /* start of the RCU lock */
        struct rfs_object *rfs_object;

        list_for_each_entry_rcu(rfs_object, &table_entry->hash_list_head, hash_list_entry) {

            /*
             * it is possible to hit an object with zero reference count, 
             * this is an object waiting RCU grace period expiration
             * to be removed, such objects have system_object set to NULL
             * and hash_list_head.prev set to invalid value
             */
            DBG_BUG_ON(!refcount_read(&rfs_object->refcount) &&
                       rcu_access_pointer(rfs_object->system_object));
            DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);
            DBG_BUG_ON(rfs_object->type->type != rfs_object_table->rfs_type &&
                       rfs_object_table->rfs_type != RFS_TYPE_UNKNOWN);

            if (rcu_access_pointer(rfs_object->system_object) == system_object){

                /* bump the reference count */
                rfs_object_get(rfs_object);
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
    struct rfs_object_table *rfs_object_table,
    struct rfs_object       *rfs_object,
    bool                    check_for_duplicate)
/*
* -EEXIST is returned in case of a duplicate
*/
{
    int error = 0;
    struct rfs_object_table_entry   *table_entry;
    void *system_object;

    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);
    DBG_BUG_ON(!refcount_read(&rfs_object->refcount));
    DBG_BUG_ON(!rcu_access_pointer(rfs_object->system_object));
    DBG_BUG_ON(rfs_object->type->type >= RFS_TYPE_MAX);
    DBG_BUG_ON(!list_empty(&rfs_object->hash_list_entry));

    system_object = rcu_access_pointer(rfs_object->system_object);
    table_entry = rfs_object_hash_entry(rfs_object_table, system_object);

    /* bump the reference count */
    rfs_object_get(rfs_object);

    DBG_BUG_ON(rfs_object->object_table);
    rfs_object->object_table = rfs_object_table;

    /* spin_lock can't synchronize user context with softirq */
    DBG_BUG_ON(in_softirq());

    spin_lock(&table_entry->lock);
    { /* start of the lock */

#ifdef RFS_DBG
        {
#else
        if (check_for_duplicate) {
#endif
            struct rfs_object *found_rfs_object;
            list_for_each_entry_rcu(found_rfs_object, &table_entry->hash_list_head, hash_list_entry) {

                DBG_BUG_ON(RFS_OBJECT_SIGNATURE != found_rfs_object->signature);
                DBG_BUG_ON(!refcount_read(&found_rfs_object->refcount) &&
                           rcu_access_pointer(rfs_object->system_object));

                if (system_object == rcu_access_pointer(found_rfs_object->system_object)) {
                    DBG_BUG_ON(!check_for_duplicate);
                    error = -EEXIST;
                    break;
                }
            } /* end list_for_each_entry */
        } /* end if (check_for_duplicate) */

        if (!error) {
            list_add_rcu(&rfs_object->hash_list_entry, &table_entry->hash_list_head);
        }

    } /* end of the lock */
    spin_unlock(&table_entry->lock);

    /* undo in case of error */
    if (error)
        rfs_object_put(rfs_object);

    DBG_BUG_ON(!refcount_read(&rfs_object->refcount));

    return error;
}

void
rfs_remove_object(
    struct rfs_object       *rfs_object)
{
    struct rfs_object_table_entry   *table_entry;

    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);

    table_entry = rfs_object_hash_entry( rfs_object->object_table,
                        rcu_access_pointer(rfs_object->system_object));

    DBG_BUG_ON(LIST_POISON2 == rfs_object->hash_list_entry.prev);

    /*
     * make the object non discoverable, 
     * synchronize_rcu() call is not required as
     * the pointer is never dereferenced
     */
    rcu_assign_pointer(rfs_object->system_object, NULL);

    /* spin_lock can't synchronize user context with softirq */
    DBG_BUG_ON(in_softirq());

    spin_lock(&table_entry->lock);
    { /* start of the lock */
        list_del_rcu(&rfs_object->hash_list_entry);
    } /* end of the lock */
    spin_unlock(&table_entry->lock);

    rfs_object->object_table = NULL;

    /*
     * call the rfs_object_put after all current readers completed with
     * rfs_object_get to prevent reference counter dropping to zero before
     * being bumped again
     */
    call_rcu(&rfs_object->rcu_head, rfs_object_put_rcu);
}

#else /* RFS_USE_HASHTABLE */

struct rfs_object*
rfs_get_object_by_system_object(
    struct rfs_radix_tree   *radix_tree,
    const void              *system_object)
{
    struct rfs_object*  object;

    DBG_BUG_ON(!system_object);

    /* spin_lock can't synchronize user context with softirq */
    DBG_BUG_ON(in_softirq());

    rcu_read_lock();
    { /* start of the RCU lock */
        object = radix_tree_lookup(&radix_tree->root, (long)system_object);
        if (object)
            rfs_object_get(object);
    } /* end of the RCU lock */
    rcu_read_unlock();

    return object;
}

int rfs_insert_object(
    struct rfs_radix_tree   *radix_tree,
    struct rfs_object       *rfs_object,
    bool                    check_for_duplicate)
/*
* -EEXIST is returned in case of a duplicate
*/
{
    int    err;

    do {
        rcu_read_lock();
        { /* start of the RCU lock */

            rfs_object_get(rfs_object);
            rfs_object->radix_tree = radix_tree;

            /* spin_lock can't synchronize user context with softirq */
            DBG_BUG_ON(in_softirq());

            spin_lock(&radix_tree->lock);
            {
                err = radix_tree_insert(&radix_tree->root,
                                        (long)rfs_object->system_object,
                                        rfs_object);
            }
            spin_unlock(&radix_tree->lock);

            if (err)
            {
                rfs_object->radix_tree = NULL;
                rfs_object_put(rfs_object);
            }

        } /* end of the RCU lock */
        rcu_read_unlock();

        /*
         * this error can happen when f_op was replaced
         * so release hook was not called, this scenario
         * happens with char devices when __tty_hangup
         * replaces f_op with hung_up_tty_fops
         */
        if (-EEXIST == err) {

            struct rfs_object*  robj_to_remove;

            printk(KERN_CRIT"EEXIST error in rfs_insert_object\n");

            /* remove the stalled object */
            robj_to_remove = rfs_get_object_by_system_object(
                                        radix_tree,
                                        rfs_object->system_object);
            if (robj_to_remove) {

                DBG_BUG_ON(robj_to_remove == rfs_object);

                if (robj_to_remove != rfs_object) {
                    rfs_remove_object(robj_to_remove);
                } else {
                    err = 0; /* carry on */
                }

                rfs_object_put(robj_to_remove);
            }
        }
    } while (-EEXIST == err);

    /*DBG_BUG_ON((-EEXIST == err) && !check_for_duplicate);*/

    return err;
}

void
rfs_remove_object(
    struct rfs_object       *rfs_object)
{
    struct rfs_radix_tree   *radix_tree;

    radix_tree = rfs_object->radix_tree;
    if (radix_tree){

        bool removed;

        /* spin_lock can't synchronize user context with softirq */
        DBG_BUG_ON(in_softirq());

        spin_lock(&radix_tree->lock);
        {
            removed = (rfs_object == radix_tree_delete(&radix_tree->root,
                                                       (long)rfs_object->system_object));
        }
        spin_unlock(&radix_tree->lock);

        DBG_BUG_ON(!removed);

        if (removed) {

            rfs_object->radix_tree = NULL;

            /*
             * call the rfs_object_put after all current readers completed with
             * rfs_object_get to prevent reference counter dropping to zero before
             * being bumped again
             */
            call_rcu(&rfs_object->rcu_head, rfs_object_put_rcu);
        }
    }
    
}

#endif /* RFS_USE_HASHTABLE */

/*---------------------------------------------------------------------------*/

static void
rfs_object_put_rcu(
    struct rcu_head *rcu_head)
{
    struct rfs_object *rfs_object;

    rfs_object = container_of(rcu_head, struct rfs_object, rcu_head);
    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);

    rfs_object_put(rfs_object);
}

/*---------------------------------------------------------------------------*/

/* the object is initialized with a refcount set to 1 */
void
rfs_object_init(
    struct rfs_object       *rfs_object,
    struct rfs_object_type  *type,
    const void              *system_object)
{
    DBG_BUG_ON(type->type >= RFS_TYPE_MAX);
    DBG_BUG_ON(!type->free);
    DBG_BUG_ON(!system_object);

#ifdef RFS_USE_HASHTABLE
    INIT_LIST_HEAD_RCU(&rfs_object->hash_list_entry);
#endif
    refcount_set(&rfs_object->refcount, 1);
    rfs_object->type = type;
    rcu_assign_pointer(rfs_object->system_object, system_object);

#ifdef RFS_DBG
    {
        struct rfs_objects_debug_info  *di = &rfs_objects_debug_info[rfs_object->type->type];

        rfs_object->signature = RFS_OBJECT_SIGNATURE;
        atomic_inc(&di->objects_count);

        /*
         * acquire the spin lcok with disabled softirqs as
         * we need to synchronize with RCU callback which
         * is called from softirq
         */
        spin_lock_bh(&di->lock);
        {
            list_add(&rfs_object->objects_list, &di->objects_list_head);
        }
        spin_unlock_bh(&di->lock);
    }
#endif //RFS_DBG
}

/*---------------------------------------------------------------------------*/

static void
rfs_object_free_rcu(
    struct rcu_head *rcu_head)
{
    struct rfs_object *rfs_object;

    rfs_object = container_of(rcu_head, struct rfs_object, rcu_head);
    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);

#ifdef RFS_DBG
    {
        struct rfs_objects_debug_info  *di = &rfs_objects_debug_info[rfs_object->type->type];

        DBG_BUG_ON(!atomic_read(&di->objects_count));
        atomic_dec(&di->objects_count);

        /* we are in a softirq context */
        spin_lock_bh(&di->lock);
        {
            list_del(&rfs_object->objects_list);
        }
        spin_unlock_bh(&di->lock);
    }
#endif //RFS_DBG

#ifdef RFS_USE_HASHTABLE
    DBG_BUG_ON(rfs_object->object_table);
#else
    DBG_BUG_ON(rfs_object->radix_tree);
#endif

    rfs_object->type->free(rfs_object);
}

/*---------------------------------------------------------------------------*/

void
rfs_object_get(
    struct rfs_object   *rfs_object)
{
    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);
    DBG_BUG_ON(!refcount_read(&rfs_object->refcount));

    refcount_inc(&rfs_object->refcount);
}

/*
 * rfs_object_put can be called in softirq context
 * so do not add any code that might block
 */
void rfs_object_put(
    struct rfs_object   *rfs_object)
{
    DBG_BUG_ON(RFS_OBJECT_SIGNATURE != rfs_object->signature);
    DBG_BUG_ON(!refcount_read(&rfs_object->refcount));

    if (refcount_dec_and_test(&rfs_object->refcount)) {
#ifdef RFS_USE_HASHTABLE
        /*
         * the object must not be in the list, i.e. either never inserted
         * or removed by list_del_rcu
         */
        DBG_BUG_ON(!list_empty(&rfs_object->hash_list_entry) && 
                   LIST_POISON2 != rfs_object->hash_list_entry.prev);
        DBG_BUG_ON(rfs_object->object_table);

        /* the object should be non discoverable */
        DBG_BUG_ON(rfs_object->system_object && !list_empty(&rfs_object->hash_list_entry));
#endif // RFS_USE_HASHTABLE

        call_rcu(&rfs_object->rcu_head, rfs_object_free_rcu);
    }
}

/*---------------------------------------------------------------------------*/

#ifdef RFS_DBG
    #pragma GCC pop_options
#endif // RFS_DBG