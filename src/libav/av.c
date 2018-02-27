/*
 *          Copyright Frantisek Hrbata 2008 - 2010.
 *          Copyright Jozef Kralik 2018 - 2018
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 */

#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "av.h"

static int av_open_conn(struct av_connection *conn, int flags)
{
    if (!conn) {
        errno = EINVAL;
        return -1;
    }

    if ((conn->fd = open("/dev/avflt", flags)) == -1)
        return -1;

    return 0;
}

int av_register(struct av_connection *conn)
{
    return av_open_conn(conn, O_RDWR);
}

int av_unregister(struct av_connection *conn)
{
    if (!conn) {
        errno = EINVAL;
        return -1;
    }

    if (close(conn->fd) == -1)
        return -1;

    return 0;
}

int av_register_trusted(struct av_connection *conn)
{
    return av_open_conn(conn, O_RDONLY);
}

int av_unregister_trusted(struct av_connection *conn)
{
    return av_unregister(conn);
}

int av_set_result(struct av_event *event, int res)
{
    if (!event) {
        errno = EINVAL;
        return -1;
    }

    if (res != AV_ACCESS_ALLOW && res != AV_ACCESS_DENY) {
        errno = EINVAL;
        return -1;
    }

    event->res = res;

    return 0;
}

int av_set_cache(struct av_event *event, int cache)
{
    if (!event) {
        errno = EINVAL;
        return -1;
    }

    if (cache != AV_CACHE_ENABLE && cache != AV_CACHE_DISABLE) {
        errno = EINVAL;
        return -1;
    }

    event->cache = cache;

    return 0;
}

int av_get_filename(struct av_event *event, char *buf, int size)
{
    char fn[256];

    if (!event || !buf) {
        errno = EINVAL;
        return -1;
    }

    memset(fn, 0, 256);
    memset(buf, 0, size);
    snprintf(fn, 255, "/proc/%d/fd/%d", getpid(), event->fd);

    if (readlink(fn, buf, size - 1) == -1)
        return -1;

    return 0;
}

ssize_t av_parse_request_from_buf(struct av_event *event, const char* buf, size_t size)
{
    const char* delimeter;

    if (!buf || !event || !size) {
        errno = EINVAL;
        return -1;
    }
    delimeter = memchr(buf, '\0', size);
    if (!delimeter) {
        errno = EINVAL;
        return -1;
    }
    if (sscanf(buf, "id:%d,type:%d,fd:%d,pid:%d,tgid:%d",
           &event->id, &event->type, &event->fd,
           &event->pid, &event->tgid) != 5)
        return -1;
    return delimeter+1 - buf;
}

ssize_t av_set_reply_to_buf(char* buf, size_t size, const struct av_event *event)
{
    ssize_t r;

    if (!buf || !size || !event) {
        errno = EINVAL;
        return -1;
    }

    r = snprintf(buf, size, "id:%d,res:%d,cache:%d", event->id, event->res,
        event->cache);

    if (r < 0) {
        return -1;
    }
    if (r == (ssize_t)size) {
        errno = ENOSPC;
        return -1;
    }
    return r+1;
}
