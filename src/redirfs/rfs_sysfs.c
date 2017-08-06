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

#define rfs_kattr_to_rattr(__kattr) \
	container_of(__kattr, struct redirfs_filter_attribute, attr)

static struct rfs_flt *rfs_sysfs_flt_get(struct rfs_flt *rflt)
{
	spin_lock(&rflt->lock);

	if (atomic_read(&rflt->count) < 3) {
		spin_unlock(&rflt->lock);
		return ERR_PTR(-ENOENT);
	}

	rfs_flt_get(rflt);

	spin_unlock(&rflt->lock);

	return rflt;
}

static ssize_t rfs_flt_show(struct kobject *kobj, struct attribute *attr,
		char *buf)
{
	struct rfs_flt *rflt = rfs_kobj_to_rflt(kobj);
	struct redirfs_filter_attribute *rattr = rfs_kattr_to_rattr(attr);
	ssize_t rv;

	rflt = rfs_sysfs_flt_get(rflt);
	if (IS_ERR(rflt))
		return PTR_ERR(rflt);

	rv = rattr->show(rflt, rattr, buf);

	rfs_flt_put(rflt);

	return rv;
}

static ssize_t rfs_flt_store(struct kobject *kobj, struct attribute *attr,
		const char *buf, size_t count)
{
	struct rfs_flt *rflt = rfs_kobj_to_rflt(kobj);
	struct redirfs_filter_attribute *rattr = rfs_kattr_to_rattr(attr);
	ssize_t rv;

	if (strcmp(attr->name, "unregister") == 0)
		return rattr->store(rflt, rattr, buf, count);

	rflt = rfs_sysfs_flt_get(rflt);
	if (IS_ERR(rflt))
		return PTR_ERR(rflt);

	rv = rattr->store(rflt, rattr, buf, count);

	rfs_flt_put(rflt);

	return rv;
}

static ssize_t rfs_flt_priority_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	struct rfs_flt *rflt = filter;

	return snprintf(buf, PAGE_SIZE, "%d", rflt->priority);
}

static ssize_t rfs_flt_active_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	struct rfs_flt *rflt = filter;

	return snprintf(buf, PAGE_SIZE, "%d",
			atomic_read(&rflt->active));
}

static ssize_t rfs_flt_active_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = filter;
	int act;
	int rv;

	if (sscanf(buf, "%d", &act) != 1)
		return -EINVAL;

	if (act) {
		if (rflt->ops && rflt->ops->activate)
			rv = rflt->ops->activate();
		else
			rv = redirfs_activate_filter(filter);

	} else {
		if (rflt->ops && rflt->ops->deactivate)
			rv = rflt->ops->deactivate();
		else
			rv = redirfs_deactivate_filter(filter);
	}

	if (rv)
		return rv;

	return count;
}

static ssize_t rfs_flt_paths_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	struct rfs_flt *rflt = filter;
	
	return rfs_path_get_info(rflt, buf, PAGE_SIZE);
}

static int rfs_flt_paths_add(redirfs_filter filter, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = filter;
	struct rfs_path *rpath;
	struct redirfs_path_info info;
	struct nameidata nd;
	char *path;
	char type;
	int rv;

	path = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	if (sscanf(buf, "a:%c:%s", &type, path) != 2) {
		kfree(path);
		return -EINVAL;
	}

	if (type == 'i')
		info.flags = REDIRFS_PATH_INCLUDE;

	else if (type == 'e')
		info.flags = REDIRFS_PATH_EXCLUDE;

	else {
		kfree(path);
		return -EINVAL;
	}

	rv = rfs_path_lookup(path, &nd);
	if (rv) {
		kfree(path);
		return rv;
	}

	info.dentry = rfs_nameidata_dentry(&nd);
	info.mnt = rfs_nameidata_mnt(&nd);

	if (!rflt->ops || !rflt->ops->add_path) {
		rpath = redirfs_add_path(filter, &info);
		if (IS_ERR(rpath))
			rv = PTR_ERR(rpath);
		rfs_path_put(rpath);

	} else
		rv = rflt->ops->add_path(&info);

	rfs_nameidata_put(&nd);
	kfree(path);

	return rv;
}

static int rfs_flt_paths_rem(redirfs_filter filter, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = filter;
	struct rfs_path *rpath;
	int id;
	int rv;

	if (sscanf(buf, "r:%d", &id) != 1)
		return -EINVAL;

	rfs_mutex_lock(&rfs_path_mutex);
	rpath = rfs_path_find_id(id);
	if (!rpath) {
		rfs_mutex_unlock(&rfs_path_mutex);
		return -ENOENT;
	}
	rfs_mutex_unlock(&rfs_path_mutex);
	
	if (rflt->ops && rflt->ops->rem_path)
		rv = rflt->ops->rem_path(rpath);
	else
		rv = redirfs_rem_path(filter, rpath);

	rfs_path_put(rpath);

	return rv;
}

static int rfs_flt_paths_rem_name(redirfs_filter filter, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = filter;
	char *path;
	struct nameidata nd;
	struct dentry *dentry;
	struct vfsmount *mnt;
	struct rfs_path *rpath;
	int rv;

	path = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	if (sscanf(buf, "R:%s", path) != 1) {
		kfree(path);
		return -EINVAL;
	}

	rv = rfs_path_lookup(path, &nd);
	if (rv) {
		kfree(path);
		return rv;
	}

	dentry = rfs_nameidata_dentry(&nd);
	mnt = rfs_nameidata_mnt(&nd);

	rfs_mutex_lock(&rfs_path_mutex);
	rpath = rfs_path_find(mnt, dentry);
	if (!rpath) {
		rfs_mutex_unlock(&rfs_path_mutex);
		rfs_nameidata_put(&nd);
		kfree(path);
		return -EINVAL;
	}
	rfs_mutex_unlock(&rfs_path_mutex);

	if (rflt->ops && rflt->ops->rem_path)
		rv = rflt->ops->rem_path(rpath);
	else
		rv = redirfs_rem_path(filter, rpath);

	rfs_path_put(rpath);

	rfs_nameidata_put(&nd);
	kfree(path);

	return rv;
}

static int rfs_flt_paths_clean(redirfs_filter filter, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = filter;
	char clean;
	int rv;

	if (sscanf(buf, "%c", &clean) != 1)
		return -EINVAL;

	if (clean != 'c')
		return -EINVAL;

	if (rflt->ops && rflt->ops->rem_paths)
		rv = rflt->ops->rem_paths();
	else
		rv = redirfs_rem_paths(filter);

	return rv;
}

static ssize_t rfs_flt_paths_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	int rv;

	if (count < 2)
		return -EINVAL;

	if (*buf == 'a')
		rv = rfs_flt_paths_add(filter, buf, count);

	else if (*buf == 'r')
		rv = rfs_flt_paths_rem(filter, buf, count);

	else if (*buf == 'R')
		rv = rfs_flt_paths_rem_name(filter, buf, count);

	else if (*buf == 'c')
		rv = rfs_flt_paths_clean(filter, buf, count);

	else
		rv = -EINVAL;

	if (rv)
		return rv;

	return count;
}

static ssize_t rfs_flt_unregister_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = filter;
	int unreg;
	int rv;

	if (sscanf(buf, "%d", &unreg) != 1)
		return -EINVAL;

	if (unreg != 1)
		return -EINVAL;

	if (rflt->ops && rflt->ops->unregister)
		rv = rflt->ops->unregister();
	else
		rv = redirfs_unregister_filter(filter);

	if (rv)
		return rv;

	return count;
}

static struct redirfs_filter_attribute rfs_flt_priority_attr =
	REDIRFS_FILTER_ATTRIBUTE(priority, 0444, rfs_flt_priority_show, NULL);

static struct redirfs_filter_attribute rfs_flt_active_attr = 
	REDIRFS_FILTER_ATTRIBUTE(active, 0644, rfs_flt_active_show,
			rfs_flt_active_store);

static struct redirfs_filter_attribute rfs_flt_paths_attr = 
	REDIRFS_FILTER_ATTRIBUTE(paths, 0644, rfs_flt_paths_show,
			rfs_flt_paths_store);

static struct redirfs_filter_attribute rfs_flt_unregister_attr = 
	REDIRFS_FILTER_ATTRIBUTE(unregister, 0200, NULL,
			rfs_flt_unregister_store);

static struct attribute *rfs_flt_attrs[] = {
	&rfs_flt_priority_attr.attr,
	&rfs_flt_active_attr.attr,
	&rfs_flt_paths_attr.attr,
	&rfs_flt_unregister_attr.attr,
	NULL
};

static struct kset *rfs_flt_kset;

static struct sysfs_ops rfs_sysfs_ops = {
	.show = rfs_flt_show,
	.store = rfs_flt_store
};

struct kobj_type rfs_flt_ktype = {
	.sysfs_ops = &rfs_sysfs_ops,
	.release = rfs_flt_release,
	.default_attrs = rfs_flt_attrs
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
static struct kobject *rfs_fs_kobj;
static struct kobject *rfs_kobj;

static inline void rfs_kobj_release(struct kobject *kobj)
{
	kfree(kobj);
}

static struct kobj_type rfs_kobj_ktype = {
	.release = rfs_kobj_release
};

int rfs_sysfs_create(void)
{
	int rv;

	rfs_fs_kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
	if (!rfs_fs_kobj)
		return -ENOMEM;

	kobject_init(rfs_fs_kobj);
	rfs_fs_kobj->ktype = &rfs_kobj_ktype;
	rv = kobject_set_name(rfs_fs_kobj, "%s", "fs");
	if (rv) {
		kobject_put(rfs_fs_kobj);
		return rv;
	}

	rv = kobject_register(rfs_fs_kobj);
	if (rv) {
		kobject_put(rfs_fs_kobj);
		return rv;
	}

	rv = -ENOMEM;
	rfs_kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
	if (!rfs_kobj) 
		goto err_fs_kobj;

	kobject_init(rfs_kobj);
	rfs_kobj->ktype = &rfs_kobj_ktype;
	rfs_kobj->parent = rfs_fs_kobj;
	rv = kobject_set_name(rfs_kobj, "%s", "redirfs");
	if (rv) {
		kobject_put(rfs_kobj);
		goto err_fs_kobj;
	}

	rv = kobject_register(rfs_kobj);
	if (rv) {
		kobject_put(rfs_kobj);
		goto err_fs_kobj;
	}

	rv = -ENOMEM;
	rfs_flt_kset = kzalloc(sizeof(struct kset), GFP_KERNEL);
	if (!rfs_flt_kset)
		goto err_rfs_kobj;

	kobject_init(&rfs_flt_kset->kobj);
	rfs_flt_kset->kobj.ktype = &rfs_kobj_ktype;
	rfs_flt_kset->kobj.parent = rfs_kobj;
	rv = kobject_set_name(&rfs_flt_kset->kobj, "%s", "filters");
	if (rv) 
		goto err_kset;

	rv = kset_register(rfs_flt_kset);
	if (rv)
		goto err_kset;

	return 0;

err_kset:
	kset_put(rfs_flt_kset);
err_rfs_kobj:
	kobject_unregister(rfs_kobj);
err_fs_kobj:
	kobject_unregister(rfs_fs_kobj);
	return rv;
}
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
static struct kobject *rfs_kobj;

static inline void rfs_kobj_release(struct kobject *kobj)
{
	kfree(kobj);
}

static struct kobj_type rfs_kobj_ktype = {
	.release = rfs_kobj_release
};

int rfs_sysfs_create(void)
{
	int rv;

	rfs_kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
	if (!rfs_kobj)
		return -ENOMEM;

	kobject_init(rfs_kobj);
	rfs_kobj->ktype = &rfs_kobj_ktype;
	rfs_kobj->parent = &fs_subsys.kset.kobj;
	rv = kobject_set_name(rfs_kobj, "%s", "redirfs");
	if (rv) {
		kobject_put(rfs_kobj);
		return rv;
	}

	rv = kobject_register(rfs_kobj);
	if (rv) {
		kobject_put(rfs_kobj);
		return rv;
	}

	rv = -ENOMEM;
	rfs_flt_kset = kzalloc(sizeof(struct kset), GFP_KERNEL);
	if (!rfs_flt_kset)
		goto err_kobj;

	kobject_init(&rfs_flt_kset->kobj);
	rfs_flt_kset->kobj.ktype = &rfs_kobj_ktype;
	rfs_flt_kset->kobj.parent = rfs_kobj;
	rv = kobject_set_name(&rfs_flt_kset->kobj, "%s", "filters");
	if (rv) 
		goto err_kset;

	rv = kset_register(rfs_flt_kset);
	if (rv)
		goto err_kset;

	return 0;

err_kset:
	kset_put(rfs_flt_kset);
err_kobj:
	kobject_unregister(rfs_kobj);
	return rv;
}
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
static struct kobject *rfs_kobj;

static inline void rfs_kobj_release(struct kobject *kobj)
{
	kfree(kobj);
}

static struct kobj_type rfs_kobj_ktype = {
	.release = rfs_kobj_release
};

int rfs_sysfs_create(void)
{
	int rv;

	rfs_kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
	if (!rfs_kobj)
		return -ENOMEM;

	kobject_init(rfs_kobj);
	rfs_kobj->ktype = &rfs_kobj_ktype;
	rfs_kobj->parent = &fs_subsys.kobj;
	rv = kobject_set_name(rfs_kobj, "%s", "redirfs");
	if (rv) {
		kobject_put(rfs_kobj);
		return rv;
	}

	rv = kobject_register(rfs_kobj);
	if (rv) {
		kobject_put(rfs_kobj);
		return rv;
	}

	rv = -ENOMEM;
	rfs_flt_kset = kzalloc(sizeof(struct kset), GFP_KERNEL);
	if (!rfs_flt_kset)
		goto err_kobj;

	kobject_init(&rfs_flt_kset->kobj);
	rfs_flt_kset->kobj.ktype = &rfs_kobj_ktype;
	rfs_flt_kset->kobj.parent = rfs_kobj;
	rv = kobject_set_name(&rfs_flt_kset->kobj, "%s", "filters");
	if (rv) 
		goto err_kset;

	rv = kset_register(rfs_flt_kset);
	if (rv)
		goto err_kset;

	return 0;

err_kset:
	kset_put(rfs_flt_kset);
err_kobj:
	kobject_unregister(rfs_kobj);
	return rv;
}
#else
static struct kobject *rfs_kobj;

int rfs_sysfs_create(void)
{
	rfs_kobj = kobject_create_and_add("redirfs", fs_kobj);
	if (!rfs_kobj)
		return -ENOMEM;

	rfs_flt_kset = kset_create_and_add("filters", NULL, rfs_kobj);
	if (!rfs_flt_kset) {
		kobject_put(rfs_kobj);
		return -ENOMEM;
	}

	return 0;
}
#endif

int redirfs_create_attribute(redirfs_filter filter,
		struct redirfs_filter_attribute *attr)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	if (!rflt || !attr)
		return -EINVAL;

	return sysfs_create_file(&rflt->kobj, &attr->attr);
}

int redirfs_remove_attribute(redirfs_filter filter,
		struct redirfs_filter_attribute *attr)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	if (!rflt || !attr)
		return -EINVAL;

	sysfs_remove_file(&rflt->kobj, &attr->attr);

	return 0;
}

struct kobject *redirfs_filter_kobject(redirfs_filter filter)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	if (!rflt || IS_ERR(rflt))
		return ERR_PTR(-EINVAL);

	return &rflt->kobj;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
int rfs_flt_sysfs_init(struct rfs_flt *rflt)
{
	int rv;

	rflt->kobj.ktype = &rfs_flt_ktype;
	rflt->kobj.kset = rfs_flt_kset;
	kobject_init(&rflt->kobj);

	rv = kobject_set_name(&rflt->kobj, rflt->name);
	if (rv)
		return rv;

	rv = kobject_add(&rflt->kobj);
	if (rv)
		return rv;

	kobject_uevent(&rflt->kobj, KOBJ_ADD, NULL);

	rfs_flt_get(rflt);

	return 0;
}
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
int rfs_flt_sysfs_init(struct rfs_flt *rflt)
{
	int rv;

	rflt->kobj.ktype = &rfs_flt_ktype;
	rflt->kobj.kset = rfs_flt_kset;
	kobject_init(&rflt->kobj);

	rv = kobject_set_name(&rflt->kobj, rflt->name);
	if (rv)
		return rv;

	rv = kobject_add(&rflt->kobj);
	if (rv)
		return rv;

	kobject_uevent(&rflt->kobj, KOBJ_ADD);

	rfs_flt_get(rflt);

	return 0;
}
#else
int rfs_flt_sysfs_init(struct rfs_flt *rflt)
{
	int rv;

	rflt->kobj.kset = rfs_flt_kset;
	kobject_init(&rflt->kobj, &rfs_flt_ktype);

	rv = kobject_add(&rflt->kobj, NULL, "%s", rflt->name);
	if (rv)
		return rv;

	kobject_uevent(&rflt->kobj, KOBJ_ADD);

	rfs_flt_get(rflt);

	return 0;
}
#endif

void rfs_flt_sysfs_exit(struct rfs_flt *rflt)
{
	kobject_del(&rflt->kobj);
}

EXPORT_SYMBOL(redirfs_create_attribute);
EXPORT_SYMBOL(redirfs_remove_attribute);
EXPORT_SYMBOL(redirfs_filter_kobject);

