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

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,18,0))
static int get_unused_fd(void)
{
	return get_unused_fd_flags(0);
}
#endif

DECLARE_WAIT_QUEUE_HEAD(avflt_request_available);
static DEFINE_SPINLOCK(avflt_request_lock);
static LIST_HEAD(avflt_request_list);
static int avflt_request_accept = 0;
static struct kmem_cache *avflt_event_cache = NULL;
atomic_t avflt_cache_ver = ATOMIC_INIT(0);
atomic_t avflt_event_ids = ATOMIC_INIT(0);

static struct avflt_event *avflt_event_alloc(struct file *file, int type)
{
    struct avflt_inode_data *inode_data;
    struct avflt_root_data *root_data;
    struct avflt_event *event;

    event = kmem_cache_zalloc(avflt_event_cache, GFP_KERNEL);
    if (!event) 
        return ERR_PTR(-ENOMEM);

    INIT_LIST_HEAD(&event->req_list);
    INIT_LIST_HEAD(&event->proc_list);
    init_completion(&event->wait);
    atomic_set(&event->count, 1);
    event->type = type;
    event->id = -1;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
    event->mnt = mntget(file->f_vfsmnt);
    event->f_path_dentry = dget(file->f_dentry);
#else
    path_get(&file->f_path);
    event->f_path = file->f_path;
#endif
    event->flags = file->f_flags;
    event->fd = -1;
    event->pid = current->pid;
    event->tgid = current->tgid;
    event->cache = 1;

    root_data = avflt_get_root_data_inode(file->f_dentry->d_inode);
    inode_data = avflt_get_inode_data_inode(file->f_dentry->d_inode);

    if (root_data) 
        event->root_cache_ver = atomic_read(&root_data->cache_ver);

    event->root_data = avflt_get_root_data(root_data);

    if (inode_data) {
        spin_lock(&inode_data->lock);
        event->cache_ver = inode_data->inode_cache_ver;
        spin_unlock(&inode_data->lock);
    }

    avflt_put_inode_data(inode_data);
    avflt_put_root_data(root_data);

    return event;
}

struct avflt_event *avflt_event_get(struct avflt_event *event)
{
    if (!event || IS_ERR(event))
        return NULL;

    BUG_ON(!atomic_read(&event->count));
    atomic_inc(&event->count);

    return event;
}

void avflt_event_put(struct avflt_event *event)
{
    if (!event || IS_ERR(event))
        return;

    BUG_ON(!atomic_read(&event->count));

    if (!atomic_dec_and_test(&event->count))
        return;

    avflt_put_root_data(event->root_data);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
    mntput(event->mnt);
    dput(event->f_path_dentry);
#else
    path_put(&event->f_path);
#endif
    kmem_cache_free(avflt_event_cache, event);
}

static int avflt_add_request(struct avflt_event *event, int tail)
{
    spin_lock(&avflt_request_lock);

    if (avflt_request_accept == 0) {
        spin_unlock(&avflt_request_lock);
        return 1;
    }

    if (tail)
        list_add_tail(&event->req_list, &avflt_request_list);
    else
        list_add(&event->req_list, &avflt_request_list);

    avflt_event_get(event);
    
    wake_up_interruptible(&avflt_request_available);

    spin_unlock(&avflt_request_lock);

    return 0;
}

void avflt_readd_request(struct avflt_event *event)
{
    if (avflt_add_request(event, 0))
        avflt_event_done(event);
}

static void avflt_rem_request(struct avflt_event *event)
{
    spin_lock(&avflt_request_lock);
    if (list_empty(&event->req_list)) {
        spin_unlock(&avflt_request_lock);
        return;
    }
    list_del_init(&event->req_list);
    spin_unlock(&avflt_request_lock);
    avflt_event_put(event);
}

struct avflt_event *avflt_get_request(void)
{
    struct avflt_event *event;

    spin_lock(&avflt_request_lock);

    if (list_empty(&avflt_request_list)) {
        spin_unlock(&avflt_request_lock);
        return NULL;
    }

    event = list_entry(avflt_request_list.next, struct avflt_event,
            req_list);
    list_del_init(&event->req_list);

    spin_unlock(&avflt_request_lock);

    event->id = atomic_inc_return(&avflt_event_ids);
    return event;
}

static int avflt_wait_for_reply(struct avflt_event *event)
{
    long jiffies;
    int timeout;

    timeout = atomic_read(&avflt_reply_timeout);
    if (timeout)
        jiffies = msecs_to_jiffies(timeout);
    else
        jiffies = MAX_SCHEDULE_TIMEOUT;

    jiffies = wait_for_completion_interruptible_timeout(&event->wait,
            jiffies);

    if (jiffies < 0)
        return (int)jiffies;

    if (!jiffies) {
        printk(KERN_WARNING "avflt: wait for reply timeout with id=%d\n", event->id);
        event->result = AVFLT_FILE_CLEAN;
        event->cache = 0;
    }

    return 0;
}

static void avflt_update_cache(struct avflt_event *event)
{
    struct avflt_inode_data *inode_data;
    struct avflt_root_data *root_data;

    if (!event->cache)
        return;

    if (!atomic_read(&avflt_cache_enabled))
        return;

    root_data = avflt_get_root_data_inode(event->f_path_dentry->d_inode);
    if (!root_data)
        return;

    if (!atomic_read(&root_data->cache_enabled)) {
        avflt_put_root_data(root_data);
        return;
    }

    avflt_put_root_data(root_data);

    inode_data = avflt_attach_inode_data(event->f_path_dentry->d_inode);
    if (!inode_data)
        return;

    spin_lock(&inode_data->lock);
    avflt_put_root_data(inode_data->root_data);
    inode_data->root_data = avflt_get_root_data(event->root_data);
    inode_data->root_cache_ver = event->root_cache_ver;
    inode_data->cache_ver = event->cache_ver;
    inode_data->state = event->result;
    spin_unlock(&inode_data->lock);
    avflt_put_inode_data(inode_data);
}

int avflt_process_request(struct file *file, int type)
{
    struct avflt_event *event;
    int rv = 0;

    event = avflt_event_alloc(file, type);
    if (IS_ERR(event))
        return PTR_ERR(event);

    if (avflt_add_request(event, 1))
        goto exit;

    rv = avflt_wait_for_reply(event);
    if (rv)
        goto exit;

    avflt_update_cache(event);
    rv = event->result;
exit:
    avflt_rem_request(event);
    avflt_event_put(event);
    return rv;
}

void avflt_event_done(struct avflt_event *event)
{
    complete(&event->wait);
}

int avflt_get_file(struct avflt_event *event)
{
    struct file *file;
    int flags;
    int fd;
    char* buff;
    char* buff_s;
    struct path path;

    fd = get_unused_fd();
    if (fd < 0)
        return fd;

    flags = O_RDONLY;
    flags |= event->flags & O_LARGEFILE;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
    file = dentry_open(dget(event->f_path_dentry), mntget(event->mnt), flags);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
    file = dentry_open(dget(event->f_path_dentry), mntget(event->mnt), flags,
            current_cred());
#else
    file = dentry_open(&event->f_path, flags, current_cred());
#endif
    if (IS_ERR(file)) {
        buff = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
        path.mnt = event->mnt;
        path.dentry = event->f_path_dentry;
#else
        path = event->f_path;
#endif
        buff_s = d_path(&path, buff, PAGE_SIZE);
        if (!IS_ERR(buff_s)) {
            avlft_pr_debug("dentry=%p, path=%s", path.dentry, buff_s);
            if (!d_unlinked(path.dentry))
                file = filp_open(buff_s ,flags, 0);
        }
        kfree(buff);
    }
    if (IS_ERR(file)) {
        put_unused_fd(fd);
        return PTR_ERR(file);
    }

    event->file = file;
    event->fd = fd;

    return 0;
}

void avflt_put_file(struct avflt_event *event)
{
    if (event->fd > 0) 
        put_unused_fd(event->fd);

    if (event->file) 
        fput(event->file);

    event->fd = -1;
    event->file = NULL;
}

void avflt_install_fd(struct avflt_event *event)
{
    fd_install(event->fd, event->file);
}

ssize_t avflt_copy_cmd(char __user *buf, size_t size, struct avflt_event *event)
{
    char cmd[256];
    int len;

    len = snprintf(cmd, 256, "id:%d,type:%d,fd:%d,pid:%d,tgid:%d",
            event->id, event->type, event->fd, event->pid,
            event->tgid);
    if (len < 0)
        return len;

    len++;

    if (len > size)
        return -EINVAL;

    if (copy_to_user(buf, cmd, len)) 
        return -EFAULT;

    return len;
}

int avflt_add_reply(struct avflt_event *event)
{
    struct avflt_proc *proc;

    proc = avflt_proc_find(current->tgid);
    if (!proc)
        return -ENOENT;

    avflt_proc_add_event(proc, event);
    avflt_proc_put(proc);

    return 0;
}

int avflt_request_empty(void)
{
    int rv;

    spin_lock(&avflt_request_lock);

    if (list_empty(&avflt_request_list))
        rv = 1;
    else
        rv = 0;

    spin_unlock(&avflt_request_lock);

    return rv;
}

void avflt_start_accept(void)
{
    spin_lock(&avflt_request_lock);
    avflt_request_accept = 1;
    spin_unlock(&avflt_request_lock);
}

void avflt_stop_accept(void)
{
    spin_lock(&avflt_request_lock);
    if (avflt_proc_empty())
        avflt_request_accept = 0;
    spin_unlock(&avflt_request_lock);
}

int avflt_is_stopped(void)
{
    int stopped;

    spin_lock(&avflt_request_lock);
    stopped = avflt_request_accept == 0;
    spin_unlock(&avflt_request_lock);

    return stopped;
}

void avflt_rem_requests(void)
{
    LIST_HEAD(list);
    struct avflt_event *event;
    struct avflt_event *tmp;

    spin_lock(&avflt_request_lock);

    if (avflt_request_accept == 1) {
        spin_unlock(&avflt_request_lock);
        return;

    }

    list_for_each_entry_safe(event, tmp, &avflt_request_list, req_list) {
        list_move_tail(&event->req_list, &list);
        avflt_event_done(event);
    }

    spin_unlock(&avflt_request_lock);

    list_for_each_entry_safe(event, tmp, &list, req_list) {
        list_del_init(&event->req_list);
        avflt_event_put(event);
    }
}

struct avflt_event *avflt_get_reply(const char __user *buf, size_t size)
{
    struct avflt_proc *proc;
    struct avflt_event *event;
    char cmd[256];
    int id;
    int result;
    int cache;
    int rv;

    if (size > 256)
        return ERR_PTR(-EINVAL);

    if (copy_from_user(cmd, buf, size))
        return ERR_PTR(-EFAULT);

    cache = -1;
    /*
     * v0: id:%d,res:%d
     * v1: id:%d,res:%d,cache:%d
     */
    rv = sscanf(buf, "id:%d,res:%d,cache:%d", &id, &result, &cache);
    if (rv != 2 && rv != 3)
        return ERR_PTR(-EINVAL);

    proc = avflt_proc_find(current->tgid);
    if (!proc)
        return ERR_PTR(-ENOENT);

    event = avflt_proc_get_event(proc, id);
    avflt_proc_put(proc);
    if (!event)
        return ERR_PTR(-ENOENT);

    event->result = result;
    
    if (cache != -1)
        event->cache = cache;

    return event;
}

void avflt_invalidate_cache_root(redirfs_root root)
{
    struct avflt_root_data *data;

    if (!root)
        return;

    data = avflt_get_root_data_root(root);
    if (!data)
        return;

    atomic_inc(&data->cache_ver);
    avflt_put_root_data(data);
}

void avflt_invalidate_cache(void)
{
    redirfs_path *paths;
    redirfs_root root;
    int i = 0;

    paths = redirfs_get_paths(avflt);
    if (IS_ERR(paths))
        return;

    while (paths[i]) {
        root = redirfs_get_root_path(paths[i]);
        avflt_invalidate_cache_root(root);
        redirfs_put_root(root);
        i++;
    }

    redirfs_put_paths(paths);
}

int avflt_check_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    avflt_event_cache = kmem_cache_create("avflt_event_cache",
            sizeof(struct avflt_event),
            0, SLAB_RECLAIM_ACCOUNT, NULL, NULL);
#else
    avflt_event_cache = kmem_cache_create("avflt_event_cache",
            sizeof(struct avflt_event),
            0, SLAB_RECLAIM_ACCOUNT, NULL);
#endif

    if (!avflt_event_cache)
        return -ENOMEM;

    return 0;
}

void avflt_check_exit(void)
{
    kmem_cache_destroy(avflt_event_cache);
}

