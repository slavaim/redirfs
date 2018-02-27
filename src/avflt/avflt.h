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

#ifndef _AVFLT_H
#define _AVFLT_H

#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/freezer.h>
#endif
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <redirfs.h>

#define AVFLT_VERSION    "0.7"

#define AVFLT_EVENT_OPEN    1
#define AVFLT_EVENT_CLOSE    2

#define AVFLT_FILE_CLEAN    1
#define AVFLT_FILE_INFECTED    2

struct avflt_event {
    struct list_head req_list;
    struct list_head proc_list;
    struct avflt_root_data *root_data;
    struct completion wait;
    atomic_t count;
    int type;
    int id;
    int result;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
    struct vfsmount *mnt;
    struct dentry *f_path_dentry;
#else
	#ifndef f_dentry
		#define f_dentry f_path.dentry
	#endif
	#define f_path_dentry f_path.dentry
    struct path f_path;
#endif
    unsigned int flags;
    struct file *file;
    int fd;
    int root_cache_ver;
    int cache_ver;
    int cache;
    pid_t pid;
    pid_t tgid;
    int was_removed_from_req_list;
};

struct avflt_event *avflt_event_get(struct avflt_event *event);
void avflt_event_put(struct avflt_event *event);
void avflt_readd_request(struct avflt_event *event);
struct avflt_event *avflt_get_request(void);
int avflt_process_request(struct file *file, int type);
void avflt_event_done(struct avflt_event *event);
int avflt_get_file(struct avflt_event *event);
void avflt_put_file(struct avflt_event *event);
void avflt_install_fd(struct avflt_event *event);
ssize_t avflt_copy_cmd(char __user *buf, size_t size,
        struct avflt_event *event);
int avflt_add_reply(struct avflt_event *event);
int avflt_request_empty(void);
void avflt_start_accept(void);
void avflt_stop_accept(void);
int avflt_is_stopped(void);
void avflt_rem_requests(void);
struct avflt_event *avflt_get_reply(const char __user *buf, size_t size);
int avflt_check_init(void);
void avflt_check_exit(void);

struct avflt_trusted {
    struct list_head list;
    pid_t tgid;
    int open;
};

int avflt_trusted_add(pid_t tgid);
void avflt_trusted_rem(pid_t tgid);
int avflt_trusted_allow(pid_t tgid);
ssize_t avflt_trusted_get_info(char *buf, int size);

struct avflt_proc {
    struct list_head list;
    struct list_head events; 
    spinlock_t lock;
    atomic_t count;
    pid_t tgid;
    int open;
};

struct avflt_proc *avflt_proc_get(struct avflt_proc *proc);
void avflt_proc_put(struct avflt_proc *proc);
struct avflt_proc *avflt_proc_find(pid_t tgid);
struct avflt_proc *avflt_proc_add(pid_t tgid);
void avflt_proc_rem(pid_t tgid);
int avflt_proc_allow(pid_t tgid);
int avflt_proc_empty(void);
void avflt_proc_add_event(struct avflt_proc *proc, struct avflt_event *event);
void avflt_proc_rem_event(struct avflt_proc *proc, struct avflt_event *event);
struct avflt_event *avflt_proc_get_event(struct avflt_proc *proc, int id);
ssize_t avflt_proc_get_info(char *buf, int size);

#define rfs_to_root_data(ptr) \
    container_of(ptr, struct avflt_root_data, rfs_data)

struct avflt_root_data {
    struct redirfs_data rfs_data;
    atomic_t cache_enabled;
    atomic_t cache_ver;
};

struct avflt_root_data *avflt_get_root_data_root(redirfs_root root);
struct avflt_root_data *avflt_get_root_data_inode(struct inode *inode);
struct avflt_root_data *avflt_get_root_data(struct avflt_root_data *data);
void avflt_put_root_data(struct avflt_root_data *data);
struct avflt_root_data *avflt_attach_root_data(redirfs_root root);

#define rfs_to_inode_data(ptr) \
    container_of(ptr, struct avflt_inode_data, rfs_data)

struct avflt_inode_data {
    struct redirfs_data rfs_data;
    struct avflt_root_data *root_data;
    int root_cache_ver;
    int inode_cache_ver;
    int cache_ver;
    int state;
    spinlock_t lock;
};

struct avflt_inode_data *avflt_get_inode_data_inode(struct inode *inode);
struct avflt_inode_data *avflt_get_inode_data(struct avflt_inode_data *data);
void avflt_put_inode_data(struct avflt_inode_data *data);
struct avflt_inode_data *avflt_attach_inode_data(struct inode *inode);
int avflt_data_init(void);
void avflt_data_exit(void);

void avflt_invalidate_cache_root(redirfs_root root);
void avflt_invalidate_cache(void);

int avflt_dev_init(void);
void avflt_dev_exit(void);

int avflt_rfs_init(void);
void avflt_rfs_exit(void);

int avflt_sys_init(void);
void avflt_sys_exit(void);

extern atomic_t avflt_reply_timeout;
extern atomic_t avflt_cache_enabled;
extern redirfs_filter avflt;
extern wait_queue_head_t avflt_request_available;

#ifdef DEBUG
#define avlft_pr_debug(fmt, ...) \
	printk(KERN_INFO "avflt: %s:%d:%s:" pr_fmt(fmt) , __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__)
#else
#define avlft_pr_debug(fmt, ...) \
    no_printk(KERN_INFO "avflt: %s:%d:%s:" pr_fmt(fmt) , __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__)
#endif

#endif

