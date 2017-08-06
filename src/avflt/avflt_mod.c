/*
 * AVFlt: Anti-Virus Filter
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

#include "avflt.h"

static int __init avflt_init(void)
{
	int rv;

	rv = avflt_check_init();
	if (rv)
		return rv;

	rv = avflt_data_init();
	if (rv)
		goto err_check;

	rv = avflt_rfs_init();
	if (rv)
		goto err_data;

	rv = avflt_sys_init();
	if (rv) 
		goto err_rfs;

	rv = avflt_dev_init();
	if (rv)
		goto err_sys;

	printk(KERN_INFO "Anti-Virus Filter Version "
			AVFLT_VERSION " <www.redirfs.org>\n");
	return 0;

err_sys:
	avflt_sys_exit();
err_rfs:
	avflt_rfs_exit();
err_data:
	avflt_data_exit();
err_check:
	avflt_check_exit();
	return rv;
}

static void __exit avflt_exit(void)
{
	avflt_dev_exit();
	avflt_sys_exit();
	avflt_rfs_exit();
	avflt_data_exit();
	avflt_check_exit();
}

module_init(avflt_init);
module_exit(avflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <frantisek.hrbata@redirfs.org>");
MODULE_DESCRIPTION("Anti-Virus Filter for the RedirFS Framework");

