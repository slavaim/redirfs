/*
 * RedirFS: Redirecting File System
 * Copyright 2017 Slava Imameev
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

ssize_t rfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct rfs_file *rfile;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
    struct redirfs_args rargs;

	rfile = rfs_file_find(file);
	rinfo = rfs_dentry_get_rinfo(rfile->rdentry);
	rfs_context_init(&rcont, 0);

    rargs.type.id = REDIRFS_REG_FOP_READ;
	rargs.args.f_read.file = file;
	rargs.args.f_read.buf = buf;
	rargs.args.f_read.count = count;
    rargs.args.f_read.pos = pos;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rfile->op_old && rfile->op_old->read) 
			rargs.rv.rv_int = rfile->op_old->read(
					rargs.args.f_read.file,
					rargs.args.f_read.buf,
					rargs.args.f_read.count,
                    rargs.args.f_read.pos);
		else
			rargs.rv.rv_int = -EIO;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_file_put(rfile);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}