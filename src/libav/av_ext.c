/*
 *          Copyright Frantisek Hrbata 2008 - 2010.
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

int av_request(struct av_connection *conn, struct av_event *event, int timeout)
{
    struct timeval tv;
    struct timeval *ptv;
    char buf[256];
    fd_set rfds;
    int rv = 0;

    if (!conn || !event || timeout < 0) {
        errno = EINVAL;
        return -1;
    }

    FD_ZERO(&rfds);
    FD_SET(conn->fd, &rfds);

    if (timeout) {
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout - (tv.tv_sec * 1000)) * 1000;
        ptv = &tv;
    } else
        ptv = NULL;

    while (!rv) {
        rv = select(conn->fd + 1, &rfds, NULL, NULL, ptv);
        if (rv == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (rv == -1)
            return -1;

        rv = read(conn->fd, buf, 256);
        if (rv == -1)
            return -1;
    }

    if (av_parse_request_from_buf(event, buf, sizeof(buf))<0)
       return -1;

    event->res = 0;
    event->cache = AV_CACHE_ENABLE;

    return 0;
}

int av_reply(struct av_connection *conn, struct av_event *event)
{
    char buf[256];
    ssize_t len;

    if (!conn || !event) {
        errno = EINVAL;
        return -1;
    }

    len = av_set_reply_to_buf(buf, sizeof(buf), event);
    if (len < 0)
       return -1;

    if (write(conn->fd, buf, len) == -1)
        return -1;

    if (close(event->fd) == -1)
        return -1;

    return 0;
}
