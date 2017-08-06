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

static struct rfs_chain *rfs_chain_alloc(int size, int type)
{
	struct rfs_chain *rchain;
	struct rfs_flt **rflts;

	rchain = kzalloc(sizeof(struct rfs_chain), type);
	rflts = kzalloc(sizeof(struct rfs_flt*) * size, type);
	if (!rchain || !rflts) {
		kfree(rchain);
		kfree(rflts);
		return ERR_PTR(-ENOMEM);
	}

	rchain->rflts = rflts;
	rchain->rflts_nr = size;
	atomic_set(&rchain->count, 1);

	return rchain;
}

struct rfs_chain *rfs_chain_get(struct rfs_chain *rchain)
{
	if (!rchain || IS_ERR(rchain))
		return NULL;

	BUG_ON(!atomic_read(&rchain->count));
	atomic_inc(&rchain->count);

	return rchain;
}

void rfs_chain_put(struct rfs_chain *rchain)
{
	int i;

	if (!rchain || IS_ERR(rchain))
		return;

	BUG_ON(!atomic_read(&rchain->count));
	if (!atomic_dec_and_test(&rchain->count))
		return;

	for (i = 0; i < rchain->rflts_nr; i++)
		rfs_flt_put(rchain->rflts[i]);

	kfree(rchain->rflts);
	kfree(rchain);
}

int rfs_chain_find(struct rfs_chain *rchain, struct rfs_flt *rflt)
{
	int i;

	if (!rchain)
		return -1;

	for (i = 0; i < rchain->rflts_nr; i++) {
		if (rchain->rflts[i] == rflt)
			return i;
	}

	return -1;
}

struct rfs_chain *rfs_chain_add(struct rfs_chain *rchain, struct rfs_flt *rflt)
{
	struct rfs_chain *rchain_new;
	int size;
	int i = 0;
	int j = 0;

	if (rfs_chain_find(rchain, rflt) != -1)
		return rfs_chain_get(rchain);

	if (!rchain) 
		size = 1;
	else
		size = rchain->rflts_nr + 1;

	rchain_new = rfs_chain_alloc(size, GFP_KERNEL);
	if (IS_ERR(rchain_new))
		return rchain_new;

	if (!rchain) {
		rchain_new->rflts[0] = rfs_flt_get(rflt);
		return rchain_new;
	}

	while (rchain->rflts[i]->priority < rflt->priority) {
		rchain_new->rflts[j++] = rfs_flt_get(rchain->rflts[i++]);
		if (i == rchain->rflts_nr)
			break;
	}

	rchain_new->rflts[j++] = rfs_flt_get(rflt);

	while (j < rchain_new->rflts_nr) {
		rchain_new->rflts[j++] = rfs_flt_get(rchain->rflts[i++]);
	}

	return rchain_new;
}

struct rfs_chain *rfs_chain_rem(struct rfs_chain *rchain, struct rfs_flt *rflt)
{
	struct rfs_chain *rchain_new;
	int i, j;

	if (rfs_chain_find(rchain, rflt) == -1)
		return rfs_chain_get(rchain);

	if (rchain->rflts_nr == 1)
		return NULL;

	rchain_new = rfs_chain_alloc(rchain->rflts_nr - 1, GFP_KERNEL);
	if (IS_ERR(rchain_new))
		return rchain_new;

	for (i = 0, j = 0; i < rchain->rflts_nr; i++) {
		if (rchain->rflts[i] != rflt)
			rchain_new->rflts[j++] = rfs_flt_get(rchain->rflts[i]);
	}

	return rchain_new;
}

void rfs_chain_ops(struct rfs_chain *rchain, struct rfs_ops *rops)
{
	int i, j;

	if (!rchain)
		return;

	for (i = 0; i < rchain->rflts_nr; i++) {
		for (j = 0; j < REDIRFS_OP_END; j++) {
			if (rchain->rflts[i]->cbs[j].pre_cb)
				rops->arr[j]++;
			if (rchain->rflts[i]->cbs[j].post_cb)
				rops->arr[j]++;
		}
	}
}

int rfs_chain_cmp(struct rfs_chain *rch1, struct rfs_chain *rch2)
{
	int i;

	if (!rch1 && !rch2)
		return 0;

	if (!rch1 || !rch2)
		return -1;

	if (rch1->rflts_nr != rch2->rflts_nr)
		return -1;

	for (i = 0; i < rch1->rflts_nr; i++) {
		if (rch1->rflts[i] != rch2->rflts[i])
			return -1;
	}

	return 0;
}

struct rfs_chain *rfs_chain_join(struct rfs_chain *rch1, struct rfs_chain *rch2)
{
	struct rfs_chain *rch;
	int size;
	int i,k,l;

	if (!rch1 && !rch2)
		return NULL;

	if (!rch1)
		return rfs_chain_get(rch2);

	if (!rch2)
		return rfs_chain_get(rch1);

	if (!rfs_chain_cmp(rch1, rch2))
		return rfs_chain_get(rch1);

	size = rch1->rflts_nr;

	for (i = 0; i < rch2->rflts_nr; i++) {
		if (rfs_chain_find(rch1, rch2->rflts[i]) == -1)
			size++;
	}

	rch = rfs_chain_alloc(size, GFP_KERNEL);
	if (IS_ERR(rch))
		return rch;

	i = k = l = 0;
	while (k != rch1->rflts_nr && l != rch2->rflts_nr) {
		if (rch1->rflts[k]->priority == rch2->rflts[l]->priority) {
			rch->rflts[i++] = rfs_flt_get(rch1->rflts[k++]);
			l++;
		} else if (rch1->rflts[k]->priority < rch2->rflts[l]->priority) {
			rch->rflts[i++] = rfs_flt_get(rch1->rflts[k++]);
		} else
			rch->rflts[i++] = rfs_flt_get(rch2->rflts[l++]);
	}

	while (k != rch1->rflts_nr)
		rch->rflts[i++] = rfs_flt_get(rch1->rflts[k++]);

	while (l != rch2->rflts_nr)
		rch->rflts[i++] = rfs_flt_get(rch2->rflts[l++]);

	return rch;
}

struct rfs_chain *rfs_chain_diff(struct rfs_chain *rch1, struct rfs_chain *rch2)
{
	struct rfs_chain *rch;
	int size;
	int i,j;

	if (!rch1)
		return NULL;

	if (!rch2)
		return rfs_chain_get(rch1);

	size = rch1->rflts_nr;

	for (i = 0; i < rch1->rflts_nr; i++) {
		if (rfs_chain_find(rch2, rch1->rflts[i]) != -1)
			size--;
	}

	if (!size)
		return NULL;

	if (size == rch1->rflts_nr)
		return rfs_chain_get(rch1);

	rch = rfs_chain_alloc(size, GFP_KERNEL);
	if (IS_ERR(rch))
		return rch;

	for (i = 0, j = 0; i < rch1->rflts_nr; i++) {
		if (rfs_chain_find(rch2, rch1->rflts[i]) == -1)
			rch->rflts[j++] = rfs_flt_get(rch1->rflts[i]);
	}

	BUG_ON(j != size);

	return rch;
}

