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

#ifndef _RFS_HOOKED_OPS_H
#define _RFS_HOOKED_OPS_H

#include "redirfs.h"
#include "rfs_object.h"

struct rfs_file;
struct rfs_inode;
  
#define RFS_OPS_INSERTED (1<<0)
#define RFS_OPS_REMOVED  (1<<1)
#define RFS_OPS_FILE     (1<<2)
#define RFS_OPS_INODE    (1<<3)
#define RFS_OPS_AS       (1<<4)
#define RFS_OPS_DENTRY   (1<<5)

struct rfs_hoperations {

#ifdef RFS_DBG
    #define RFS_HOPERATIONS_SIGNATURE 0xABCD0004
    uint32_t            signature;
#endif /* RFS_DBG */

    struct rfs_object   robject;

    /*
     * a relaxed counter of references
     * can drop to zero and raise again
     */
    atomic_t            keep_alive;

    /*
    * RFS_OPS_* flags
    */
    unsigned int        flags;

    /* a bitfield of hooked operations */
    union {
        unsigned long  f_op_bitfield[BIT_WORD(RFS_OP_f_end-RFS_OP_f_start) + 1];
        unsigned long  i_op_bitfield[BIT_WORD(RFS_OP_i_end-RFS_OP_i_start) + 1];
        unsigned long  a_op_bitfield[BIT_WORD(RFS_OP_a_end-RFS_OP_a_start) + 1];
        unsigned long  d_op_bitfield[BIT_WORD(RFS_OP_d_end-RFS_OP_d_start) + 1];
    };

    /* a pointer to the old operations */
    union {
        const struct file_operations            *f_op; /* referenced */
        const struct inode_operations           *i_op;
        const struct address_space_operations   *a_op;
        const struct dentry_operations          *d_op;
    } old;

    /*
     * the space for the new operations structure is 
     * normally allocated just after the rfs_hoperations
     */
    union {
        struct file_operations              *f_op;
        struct inode_operations             *i_op;
        struct address_space_operations     *a_op;
        struct dentry_operations            *d_op;
    } new;
};

/*---------------------------------------------------------------------------*/

void
rfs_keep_operations(
    struct rfs_hoperations* rfs_hoperations);

void
rfs_unkeep_operations(
    struct rfs_hoperations* rfs_hoperations);

/*---------------------------------------------------------------------------*/

struct rfs_hoperations*
rfs_create_file_ops(
    const struct file_operations *op_old);

struct rfs_hoperations*
rfs_create_inode_ops(
    const struct inode_operations *op_old);

struct rfs_hoperations*
rfs_create_address_space_ops(
    const struct address_space_operations *op_old);

struct rfs_hoperations*
rfs_create_dentry_ops(
    const struct dentry_operations *op_old);

/*---------------------------------------------------------------------------*/
#endif /* _RFS_HOOKED_OPS_H */
