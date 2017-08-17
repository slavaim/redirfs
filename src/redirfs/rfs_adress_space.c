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

#include "rfs.h"

int rfs_readpage(struct file *file, struct page *page)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
    struct rfs_inode *rinode;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rinode = rfile->rdentry->rinode;
    BUG_ON(!rinode);

    rargs.type.id = REDIRFS_REG_AOP_READPAGE;
	rargs.args.a_readpage.file = file;
	rargs.args.a_readpage.page = page;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->a_ops_old && rinode->a_ops_old->readpage) 
			rargs.rv.rv_int = rinode->a_ops_old->readpage(
					rargs.args.a_readpage.file,
					rargs.args.a_readpage.page);
		else
			rargs.rv.rv_int = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

int rfs_readpages(struct file *file, struct address_space *mapping,
                    struct list_head *pages, unsigned int nr_pages)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
    struct rfs_inode *rinode;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rinode = rfile->rdentry->rinode;
    BUG_ON(!rinode);

    rargs.type.id = REDIRFS_REG_AOP_READPAGES;
	rargs.args.a_readpages.file = file;
	rargs.args.a_readpages.mapping = mapping;
    rargs.args.a_readpages.pages = pages;
    rargs.args.a_readpages.nr_pages = nr_pages;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->a_ops_old && rinode->a_ops_old->readpages) 
			rargs.rv.rv_int = rinode->a_ops_old->readpages(
					rargs.args.a_readpages.file,
					rargs.args.a_readpages.mapping,
                    rargs.args.a_readpages.pages,
                    rargs.args.a_readpages.nr_pages);
		else
			rargs.rv.rv_int = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}