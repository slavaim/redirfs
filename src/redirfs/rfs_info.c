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

static int rfs_info_add_ops(struct rfs_info *rinfo, struct rfs_chain *rchain)
{
	struct rfs_ops *rops;

	if (!rchain) {
		rinfo->rops = NULL;
		return 0;
	}

	rops = rfs_ops_alloc();
	if (IS_ERR(rops))
		return PTR_ERR(rops);

	rfs_chain_ops(rchain, rops);
	rinfo->rops = rops;

	return 0;
}

struct rfs_info *rfs_info_alloc(struct rfs_root *rroot,
		struct rfs_chain *rchain)
{
	struct rfs_info *rinfo;
	int rv;

	rinfo = kzalloc(sizeof(struct rfs_info), GFP_KERNEL);
	if (!rinfo)
		return ERR_PTR(-ENOMEM);

	rv = rfs_info_add_ops(rinfo, rchain);
	if (rv) {
		kfree(rinfo);
		return ERR_PTR(rv);
	}

	rinfo->rchain = rfs_chain_get(rchain);
	rinfo->rroot = rfs_root_get(rroot);
	atomic_set(&rinfo->count, 1);

	return rinfo;
}

struct rfs_info *rfs_info_get(struct rfs_info *rinfo)
{
	if (!rinfo || IS_ERR(rinfo))
		return NULL;

	BUG_ON(!atomic_read(&rinfo->count));
	atomic_inc(&rinfo->count);

	return rinfo;
}

void rfs_info_put(struct rfs_info *rinfo)
{
	if (!rinfo || IS_ERR(rinfo))
		return;

	BUG_ON(!atomic_read(&rinfo->count));
	if (!atomic_dec_and_test(&rinfo->count))
		return;

	rfs_chain_put(rinfo->rchain);
	rfs_ops_put(rinfo->rops);
	rfs_root_put(rinfo->rroot);
	kfree(rinfo);
}

static struct rfs_info *rfs_info_dentry(struct dentry *dentry)
{
	struct rfs_dentry *rdentry;
	struct rfs_info *rinfo;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return NULL;

	rinfo = rfs_info_get(rdentry->rinfo);

	rfs_dentry_put(rdentry);

	return rinfo;
}

struct rfs_info *rfs_info_parent(struct dentry *dentry)
{
	struct dentry *dparent = NULL;
	struct rfs_info *rinfo = NULL;

	dparent = dget_parent(dentry);
	if (dparent != dentry)
		rinfo = rfs_info_dentry(dparent);
	dput(dparent);

	return rinfo;
}

static int rfs_info_rdentry_add(struct rfs_info *rinfo)
{
	struct rfs_dentry *rdentry;

	rdentry = rfs_dentry_add(rinfo->rroot->dentry, rinfo);
	if (IS_ERR(rdentry))
		return PTR_ERR(rdentry);

	rfs_dentry_set_rinfo(rdentry, rinfo);
	rfs_dentry_put(rdentry);
	return 0;
}

static void rfs_info_rdentry_rem(struct dentry *dentry)
{
	struct rfs_dentry *rdentry;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return;

	spin_lock(&rdentry->lock);
	rfs_info_put(rdentry->rinfo);
	rdentry->rinfo = rfs_info_get(rfs_info_none);
	spin_unlock(&rdentry->lock);

	rfs_dentry_put(rdentry);
}

int rfs_info_add(struct dentry *dentry, struct rfs_info *rinfo,
		struct rfs_flt *rflt)
{
	struct rfs_dcache_data *rdata = NULL;
	int rv = 0;

	rdata = rfs_dcache_data_alloc(dentry, rinfo, rflt);
	if (IS_ERR(rdata))
		return PTR_ERR(rdata);

	rv = rfs_dcache_walk(dentry, rfs_dcache_add, rdata);
	rfs_dcache_data_free(rdata);

	if (!rv)
		rv = rfs_root_walk(rfs_root_add_flt, rflt);

	return rv;
}

int rfs_info_rem(struct dentry *dentry, struct rfs_info *rinfo,
		struct rfs_flt *rflt)
{
	struct rfs_dcache_data *rdata = NULL;
	int rv = 0;

	rdata = rfs_dcache_data_alloc(dentry, rinfo, rflt);
	if (IS_ERR(rdata))
		return PTR_ERR(rdata);

	rv = rfs_dcache_walk(dentry, rfs_dcache_rem, rdata);
	rfs_dcache_data_free(rdata);

	if (!rv)
		rv = rfs_root_walk(rfs_root_rem_flt, rflt);

	return rv;
}

int rfs_info_set(struct dentry *dentry, struct rfs_info *rinfo,
		struct rfs_flt *rflt)
{
	struct rfs_dcache_data *rdata = NULL;
	int rv = 0;

	rdata = rfs_dcache_data_alloc(dentry, rinfo, rflt);
	if (IS_ERR(rdata))
		return PTR_ERR(rdata);

	if (rflt->ops && rflt->ops->move_begin)
		rflt->ops->move_begin();

	rv = rfs_dcache_walk(dentry, rfs_dcache_set, rdata);

	if (rflt->ops && rflt->ops->move_end)
		rflt->ops->move_end();

	rfs_dcache_data_free(rdata);

	return rv;
}

int rfs_info_reset(struct dentry *dentry, struct rfs_info *rinfo)
{
	struct rfs_dcache_data *rdata = NULL;
	int rv = 0;

	rdata = rfs_dcache_data_alloc(dentry, rinfo, NULL);
	if (IS_ERR(rdata))
		return PTR_ERR(rdata);

	rv = rfs_dcache_walk(dentry, rfs_dcache_reset, rdata);
	rfs_dcache_data_free(rdata);

	return rv;
}

int rfs_info_add_include(struct rfs_root *rroot, struct rfs_flt *rflt)
{
	struct rfs_info *rinfo = NULL;
	struct rfs_info *rinfo_old = NULL;
	struct rfs_chain *rchain = NULL;
	int rv = 0;

	if (rroot->rinfo && rfs_chain_find(rroot->rinfo->rchain, rflt) != -1)
		return 0;

	rinfo_old = rfs_info_get(rroot->rinfo);
	if (!rinfo_old)
		rinfo_old = rfs_info_dentry(rroot->dentry);

	if (rinfo_old) 
		rchain = rfs_chain_add(rinfo_old->rchain, rflt);
	else
		rchain = rfs_chain_add(NULL, rflt);

	if (IS_ERR(rchain)) {
		rv = PTR_ERR(rchain);
		goto exit;
	}

	rinfo = rfs_info_alloc(rroot, rchain);
	if (IS_ERR(rinfo)) {
		rv = PTR_ERR(rinfo);
		goto exit;
	}

	if (rinfo_old && rfs_chain_find(rinfo_old->rchain, rflt) != -1)
		rv = rfs_info_set(rroot->dentry, rinfo, rflt);
	else
		rv = rfs_info_add(rroot->dentry, rinfo, rflt);
	if (rv)
		goto exit;

	rfs_root_set_rinfo(rroot, rinfo);
exit:
	rfs_info_put(rinfo_old);
	rfs_info_put(rinfo);
	rfs_chain_put(rchain);
	return rv;
}

int rfs_info_add_exclude(struct rfs_root *rroot, struct rfs_flt *rflt)
{
	struct rfs_info *rinfo = NULL;
	struct rfs_info *rinfo_old = NULL;
	struct rfs_chain *rchain = NULL;
	int rv = 0;

	if (rroot->rinfo && rfs_chain_find(rroot->rinfo->rchain, rflt) == -1)
		return 0;

	rinfo_old = rfs_info_get(rroot->rinfo);
	if (!rinfo_old)
		rinfo_old = rfs_info_dentry(rroot->dentry);

	if (rinfo_old) 
		rchain = rfs_chain_rem(rinfo_old->rchain, rflt);

	if (IS_ERR(rchain)) {
		rv = PTR_ERR(rchain);
		goto exit;
	}

	rinfo = rfs_info_alloc(rroot, rchain);
	if (IS_ERR(rinfo)) {
		rv = PTR_ERR(rinfo);
		goto exit;
	}

	if (rinfo_old) {
		if (rfs_chain_find(rinfo_old->rchain, rflt) == -1)
			rv = rfs_info_set(rroot->dentry, rinfo, rflt);
		else
			rv = rfs_info_rem(rroot->dentry, rinfo, rflt);
	} else
		rv = rfs_info_rdentry_add(rinfo);

	if (rv)
		goto exit;

	rfs_root_set_rinfo(rroot, rinfo);
exit:
	rfs_info_put(rinfo);
	rfs_info_put(rinfo_old);
	rfs_chain_put(rchain);
	return rv;
}

int rfs_info_rem_include(struct rfs_root *rroot, struct rfs_flt *rflt)
{
	struct rfs_info *prinfo = NULL;
	struct rfs_info *rinfo = NULL;
	struct rfs_chain *rchain = NULL;
	int rv = 0;

	rchain = rfs_chain_rem(rroot->rinfo->rchain, rflt);
	if (IS_ERR(rchain))
		return PTR_ERR(rchain);

	rinfo = rfs_info_alloc(rroot, rchain);
	if (IS_ERR(rinfo)) {
		rv = PTR_ERR(rinfo);
		goto exit;
	}

	prinfo = rfs_info_parent(rroot->dentry);

	if (rroot->rinch->rflts_nr == 1 && !rroot->rexch) {
		if (prinfo && rfs_chain_find(prinfo->rchain, rflt) != -1)
			rv = rfs_info_set(rroot->dentry, prinfo, rflt);
		else if (prinfo && prinfo->rchain)
			rv = rfs_info_rem(rroot->dentry, prinfo, rflt);
		else
			rv = rfs_info_rem(rroot->dentry, rinfo, rflt);

		if (!rv)
			rfs_root_set_rinfo(rroot, NULL);

		goto exit;
	}

	if (prinfo && rfs_chain_find(prinfo->rchain, rflt) != -1)
		goto exit;

	rv = rfs_info_rem(rroot->dentry, rinfo, rflt);
	if (rv)
		goto exit;

	rv = rfs_info_rdentry_add(rinfo);
	if (rv)
		goto exit;

	rfs_root_set_rinfo(rroot, rinfo);
exit:
	rfs_info_put(prinfo);
	rfs_info_put(rinfo);
	rfs_chain_put(rchain);
	return rv;
}

int rfs_info_rem_exclude(struct rfs_root *rroot, struct rfs_flt *rflt)
{
	struct rfs_info *prinfo = NULL;
	struct rfs_info *rinfo = NULL;
	struct rfs_chain *rchain = NULL;
	int rv = 0;

	prinfo = rfs_info_parent(rroot->dentry);

	if (rroot->rexch->rflts_nr == 1 && !rroot->rinch) {
		if (prinfo && rfs_chain_find(prinfo->rchain, rflt) != -1)
			rv = rfs_info_add(rroot->dentry, prinfo, rflt);
		else if (prinfo && prinfo->rchain)
			rv = rfs_info_set(rroot->dentry, prinfo, rflt);
		else  
			rfs_info_rdentry_rem(rroot->dentry);

		if (!rv)
			rfs_root_set_rinfo(rroot, NULL);

		goto exit;
	}

	if (!prinfo || rfs_chain_find(prinfo->rchain, rflt) == -1)
		goto exit;

	rchain = rfs_chain_add(rroot->rinfo->rchain, rflt);
	if (IS_ERR(rchain)) {
		rv = PTR_ERR(rchain);
		goto exit;
	}

	rinfo = rfs_info_alloc(rroot, rchain);
	if (IS_ERR(rinfo)) {
		rv = PTR_ERR(rinfo);
		goto exit;
	}

	rv = rfs_info_add(rroot->dentry, rinfo, rflt);
	if (rv)
		goto exit;

	rfs_root_set_rinfo(rroot, rinfo);
exit:
	rfs_info_put(prinfo);
	rfs_info_put(rinfo);
	rfs_chain_put(rchain);
	return rv;
}

