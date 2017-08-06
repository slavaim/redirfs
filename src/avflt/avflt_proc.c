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

static LIST_HEAD(avflt_proc_list);
static DEFINE_SPINLOCK(avflt_proc_lock);

static LIST_HEAD(avflt_trusted_list);
static DEFINE_SPINLOCK(avflt_trusted_lock);

static struct avflt_trusted *avflt_trusted_alloc(pid_t tgid)
{
	struct avflt_trusted *trusted;

	trusted = kzalloc(sizeof(struct avflt_trusted), GFP_KERNEL);
	if (!trusted)
		return ERR_PTR(-ENOMEM);

	trusted->tgid = tgid;
	trusted->open = 1;

	return trusted;
}

static void avflt_trusted_free(struct avflt_trusted *trusted)
{
	kfree(trusted);
}

static struct avflt_trusted *avflt_trusted_find(pid_t tgid)
{
	struct avflt_trusted *trusted;

	list_for_each_entry(trusted, &avflt_trusted_list, list) {
		if (trusted->tgid == tgid)
			return trusted;
	}

	return NULL;
}

int avflt_trusted_add(pid_t tgid)
{
	struct avflt_trusted *trusted;
	struct avflt_trusted *found;

	trusted = avflt_trusted_alloc(tgid);
	if (IS_ERR(trusted))
		return PTR_ERR(trusted);

	spin_lock(&avflt_trusted_lock);

	found = avflt_trusted_find(tgid);
	if (found) {
		found->open++;
		avflt_trusted_free(trusted);

	} else
		list_add_tail(&trusted->list, &avflt_trusted_list);

	spin_unlock(&avflt_trusted_lock);

	return 0;
}

void avflt_trusted_rem(pid_t tgid)
{
	struct avflt_trusted *found;

	spin_lock(&avflt_trusted_lock);

	found = avflt_trusted_find(tgid);
	if (!found)
		goto exit;

	if (--found->open)
		goto exit;

	list_del_init(&found->list);

	avflt_trusted_free(found);
exit:
	spin_unlock(&avflt_trusted_lock);
}

int avflt_trusted_allow(pid_t tgid)
{
	struct avflt_trusted *found;

	spin_lock(&avflt_trusted_lock);
	found = avflt_trusted_find(tgid);
	spin_unlock(&avflt_trusted_lock);

	if (found)
		return 1;

	return 0;
}

static struct avflt_proc *avflt_proc_alloc(pid_t tgid)
{
	struct avflt_proc *proc;

	proc = kzalloc(sizeof(struct avflt_proc), GFP_KERNEL);
	if (!proc)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&proc->list);
	INIT_LIST_HEAD(&proc->events);
	spin_lock_init(&proc->lock);
	atomic_set(&proc->count, 1);
	proc->tgid = tgid;
	proc->open = 1;
	
	return proc;
}

struct avflt_proc *avflt_proc_get(struct avflt_proc *proc)
{
	if (!proc || IS_ERR(proc))
		return NULL;

	BUG_ON(!atomic_read(&proc->count));
	atomic_inc(&proc->count);

	return proc;
}

void avflt_proc_put(struct avflt_proc *proc)
{
	struct avflt_event *event;
	struct avflt_event *tmp;

	if (!proc || IS_ERR(proc))
		return;

	BUG_ON(!atomic_read(&proc->count));
	if (!atomic_dec_and_test(&proc->count))
		return;

	list_for_each_entry_safe(event, tmp, &proc->events, proc_list) {
		list_del_init(&event->proc_list);
		avflt_readd_request(event);
		avflt_event_put(event);
	}

	kfree(proc);
}

static struct avflt_proc *avflt_proc_find_nolock(pid_t tgid)
{
	struct avflt_proc *found = NULL;
	struct avflt_proc *proc;

	list_for_each_entry(proc, &avflt_proc_list, list) {
		if (proc->tgid == tgid) {
			found = avflt_proc_get(proc);
			break;
		}
	}

	return found;
}

struct avflt_proc *avflt_proc_find(pid_t tgid)
{
	struct avflt_proc *proc;

	spin_lock(&avflt_proc_lock);
	proc = avflt_proc_find_nolock(tgid);
	spin_unlock(&avflt_proc_lock);

	return proc;
}

struct avflt_proc *avflt_proc_add(pid_t tgid)
{
	struct avflt_proc *proc;
	struct avflt_proc *found;

	proc = avflt_proc_alloc(tgid);
	if (IS_ERR(proc))
		return proc;

	spin_lock(&avflt_proc_lock);

	found = avflt_proc_find_nolock(tgid);
	if (found) {
		found->open++;
		spin_unlock(&avflt_proc_lock);
		avflt_proc_put(proc);
		return found;
	}

	list_add_tail(&proc->list, &avflt_proc_list);
	avflt_proc_get(proc);

	spin_unlock(&avflt_proc_lock);

	return proc;
}

void avflt_proc_rem(pid_t tgid)
{
	struct avflt_proc *proc;

	spin_lock(&avflt_proc_lock);

	proc = avflt_proc_find_nolock(tgid);
	if (!proc) {
		spin_unlock(&avflt_proc_lock);
		return;
	}

	if (--proc->open) {
		spin_unlock(&avflt_proc_lock);
		return;
	}

	list_del(&proc->list);
	spin_unlock(&avflt_proc_lock);
	avflt_proc_put(proc);
	avflt_proc_put(proc);
}

int avflt_proc_allow(pid_t tgid)
{
	struct avflt_proc *proc;

	proc = avflt_proc_find(tgid);
	if (proc) {
		avflt_proc_put(proc);
		return 1;
	}

	return 0;
}

int avflt_proc_empty(void)
{
	int empty;

	spin_lock(&avflt_proc_lock);
	empty = list_empty(&avflt_proc_list);
	spin_unlock(&avflt_proc_lock);

	return empty;
}

void avflt_proc_add_event(struct avflt_proc *proc, struct avflt_event *event)
{
	spin_lock(&proc->lock);

	list_add_tail(&event->proc_list, &proc->events);
	avflt_event_get(event);

	spin_unlock(&proc->lock);
}

void avflt_proc_rem_event(struct avflt_proc *proc, struct avflt_event *event)
{
	spin_lock(&proc->lock);

	if (list_empty(&event->proc_list)) {
		spin_unlock(&proc->lock);
		return;
	}

	list_del_init(&event->proc_list);

	spin_unlock(&proc->lock);

	avflt_event_put(event);
}

struct avflt_event *avflt_proc_get_event(struct avflt_proc *proc, int id)
{
	struct avflt_event *found = NULL;
	struct avflt_event *event;

	spin_lock(&proc->lock);

	list_for_each_entry(event, &proc->events, proc_list) {
		if (event->id == id) {
			found = event;
			break;
		}
	}

	if (found)
		list_del_init(&event->proc_list);

	spin_unlock(&proc->lock);

	return found;
}

ssize_t avflt_proc_get_info(char *buf, int size)
{
	struct avflt_proc *proc;
	ssize_t len = 0;

	spin_lock(&avflt_proc_lock);

	list_for_each_entry(proc, &avflt_proc_list, list) {
		len += snprintf(buf + len, size - len, "%d", proc->tgid) + 1;
		if (len >= size) {
			len = size;
			break;
		}
	}

	spin_unlock(&avflt_proc_lock);

	return len;
}

ssize_t avflt_trusted_get_info(char *buf, int size)
{
	struct avflt_trusted *trusted;
	ssize_t len = 0;

	spin_lock(&avflt_trusted_lock);

	list_for_each_entry(trusted, &avflt_trusted_list, list) {
		len += snprintf(buf + len, size - len, "%d", trusted->tgid) + 1;
		if (len >= size) {
			len = size;
			break;
		}
	}

	spin_unlock(&avflt_trusted_lock);

	return len;
}

