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

static struct class *avflt_class;
static struct device *avflt_device;
static dev_t avflt_dev;

static int avflt_dev_open_registered(struct inode *inode, struct file *file)
{
    struct avflt_proc *proc;

    if (avflt_proc_empty())
        avflt_invalidate_cache();

    proc = avflt_proc_add(current->tgid);
    if (IS_ERR(proc))
        return PTR_ERR(proc);

    avflt_proc_put(proc);
    avflt_start_accept();
    return 0;
}

static int avflt_dev_open_trusted(struct inode *inode, struct file *file)
{
    return avflt_trusted_add(current->tgid);
}

static int avflt_dev_open(struct inode *inode, struct file *file)
{
    if (file->f_mode & FMODE_WRITE)
        return avflt_dev_open_registered(inode, file);

    return avflt_dev_open_trusted(inode, file);
}

static int avflt_dev_release_registered(struct inode *inode, struct file *file)
{
    avflt_proc_rem(current->tgid);
    if (!avflt_proc_empty())
        return 0;

    avflt_stop_accept();
    avflt_rem_requests();
    return 0;
}

static int avflt_dev_release_trusted(struct inode *inode, struct file *file)
{
    avflt_trusted_rem(current->tgid);
    return 0;
}

static int avflt_dev_release(struct inode *inode, struct file *file)
{
    if (file->f_mode & FMODE_WRITE)
        return avflt_dev_release_registered(inode, file);

    return avflt_dev_release_trusted(inode, file);
}

static ssize_t avflt_dev_read(struct file *file, char __user *buf,
        size_t size, loff_t *pos)
{
    struct avflt_event *event;
    ssize_t len;
    ssize_t rv;

    if (!(file->f_mode & FMODE_WRITE))
        return -EINVAL;

    event = avflt_get_request();
    if (!event)
        return 0;

    rv = avflt_get_file(event);
    if (rv)
        goto error;

    rv = len = avflt_copy_cmd(buf, size, event);
    if (rv < 0)
        goto error;

    rv = avflt_add_reply(event);
    if (rv)
        goto error;
    avlft_pr_debug("%s", buf);

    avflt_install_fd(event);
    avflt_event_put(event);
    return len;
error:
    avflt_put_file(event);
    avflt_readd_request(event);
    avflt_event_put(event);
    return rv;
}

static ssize_t avflt_dev_write(struct file *file, const char __user *buf,
        size_t size, loff_t *pos)
{
    struct avflt_event *event;
    const char* iter = buf;
    const char* delimeter = memchr(iter, '\0', size);
      
    while(delimeter) {
        event = avflt_get_reply(iter, delimeter + 1 - iter);
        avlft_pr_debug("%s", iter);
        if (IS_ERR(event))
            return PTR_ERR(event);

        avflt_event_done(event);
        avflt_event_put(event);
        iter = delimeter + 1;
        if (iter - buf < size) {
            delimeter = memchr(iter, '\0', size - (iter - buf));
        } else {
            break;
        }
    }
    return iter - buf;
}

static unsigned int avflt_poll(struct file *file, poll_table *wait)
{
    unsigned int mask;

    poll_wait(file, &avflt_request_available, wait);

    mask = POLLOUT | POLLWRNORM;

    if (!avflt_request_empty())
        mask |= POLLIN | POLLRDNORM;

    return mask;
}

static struct file_operations avflt_fops = {
    .owner = THIS_MODULE,
    .open = avflt_dev_open,
    .release = avflt_dev_release,
    .read = avflt_dev_read,
    .write = avflt_dev_write,
    .poll = avflt_poll
};

int avflt_dev_init(void)
{
    int major;

    major = register_chrdev(0, "avflt", &avflt_fops);
    if (major < 0)
        return major;

    avflt_dev = MKDEV(major, 0);

    avflt_class = class_create(THIS_MODULE, "avflt");
    if (IS_ERR(avflt_class)) {
        unregister_chrdev(major, "avflt");
        return PTR_ERR(avflt_class);
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
    avflt_device = device_create(avflt_class, NULL, avflt_dev, "avflt");
#else
    avflt_device = device_create(avflt_class, NULL, avflt_dev, NULL, "avflt");
#endif
    if (IS_ERR(avflt_device)) {
        class_destroy(avflt_class);
        unregister_chrdev(major, "avflt");
        return PTR_ERR(avflt_device);
    }

    return 0;
}

void avflt_dev_exit(void)
{
    device_destroy(avflt_class, avflt_dev);
    class_destroy(avflt_class);
    unregister_chrdev(MAJOR(avflt_dev), "avflt");
}

