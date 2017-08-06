/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
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

struct rfs_ops *rfs_ops_alloc(void)
{
	struct rfs_ops *rops;
	char *arr;

	rops = kzalloc(sizeof(struct rfs_ops), GFP_KERNEL);
	arr = kzalloc(sizeof(char) * REDIRFS_OP_END, GFP_KERNEL);

	if (!rops || !arr) {
		kfree(rops);
		kfree(arr);
		return ERR_PTR(-ENOMEM);
	}

	rops->arr = arr;
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

	kfree(rops->arr);
	kfree(rops);
}

