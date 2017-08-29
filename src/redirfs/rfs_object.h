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

#ifndef _RFS_OBJECT_H
#define _RFS_OBJECT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include "redirfs.h"

enum rfs_type {
    RFS_TYPE_UNKNOWN,
    RFS_TYPE_RINODE,
    RFS_TYPE_RDENTRY,
    RFS_TYPE_RFILE,
    RFS_TYPE_INODE_OPS,
    RFS_TYPE_DENTRY_OPS,
    RFS_TYPE_FILE_OPS,
    RFS_TYPE_AS_OPS,

    RFS_TYPE_MAX
};

struct rfs_object_table_entry {
    struct list_head   hash_list_head;
    spinlock_t         lock;
};

struct rfs_object_table {
    unsigned long (*index)(unsigned long key); /* returns index in the array for key */
    enum rfs_type                  rfs_type;   /* objects type in the table, might be RFS_TYPE_UNKNOWN*/
    unsigned long                  array_size; /* size of table_entries array */
    struct rfs_object_table_entry  *array; /* pointer to an array */
};

struct rfs_object_type;

struct rfs_object {

#ifdef RFS_DBG
    #define RFS_OBJECT_SIGNATURE 0xABCD0003
    long                    signature;
#endif //RFS_DBG

    refcount_t              refcount;

    /* hast table entry list, RCU */
    struct list_head        hash_list_entry;

    /* rcu callback list */
    struct rcu_head         rcu_head;

    /*
    * a pointer to a related system object
    * like inode, dentry, file etc, set to NULL
    * when the related object is removed from
    * the system as rfs_object might outlive
    * the related system object because of RCU
    */
    void                    *system_object;

    /* a containing object type */
    struct rfs_object_type  *type;

    struct rfs_object_table *object_table;

#ifdef RFS_DBG  
    struct list_head        objects_list;
#endif // RFS_DBG
};

struct rfs_object_type {

    enum rfs_type type;

    /*
     * free is called when the object refernce count
     * drops to zero
     */
    void (*free)(struct rfs_object*);
};

void rfs_object_susbsystem_init(void);

void rfs_object_table_init(
    struct rfs_object_table *rfs_object_table);

void rfs_object_init(
    struct rfs_object       *rfs_object,
    struct rfs_object_type  *type,
    void                    *system_object);

/* refernces an object */
void rfs_object_get(
    struct rfs_object   *rfs_object);

/* releases a reference to an object */
void rfs_object_put(
    struct rfs_object   *rfs_object);

/* inserts an object in a table, the object is retained by the table */
int rfs_insert_object(
    struct rfs_object_table *rfs_object_table,
    struct rfs_object       *rfs_object,
    bool                    check_for_duplicate);

/* removes object from a table and releases a reference */
void rfs_remove_object(
    struct rfs_object       *rfs_object);

/* looks up for an object in a table*/
struct rfs_object* rfs_get_object_by_system_object(
    struct rfs_object_table *rfs_object_table,
    void                    *system_object);

#endif // _RFS_OBJECT_H