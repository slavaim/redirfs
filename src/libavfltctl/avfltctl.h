/*
 *          Copyright Frantisek Hrbata 2008 - 2010.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 */

#ifndef __AVFLTCTL_H__
#define __AVFLTCTL_H__

#include <rfsctl.h>

#define AVFLTCTL_PATH_INCLUDE RFSCTL_PATH_INCLUDE
#define AVFLTCTL_PATH_EXCLUDE RFSCTL_PATH_EXCLUDE

struct avfltctl_path {
    int type;
    int id;
    char *name;
    int cache;
};

struct avfltctl_filter {
    struct avfltctl_path **paths;
    char *name;
    pid_t *registered;
    pid_t *trusted;
    int priority;
    int active;
    int timeout;
    int cache;
};

#ifdef __cplusplus
extern "C" {
#endif

struct avfltctl_filter *avfltctl_get_filter(void);
void avfltctl_put_filter(struct avfltctl_filter *filter);
int avfltctl_add_path(const char *path, int type);
int avfltctl_rem_path(int id);
int avfltctl_del_paths(void);
int avfltctl_unregister(void);
int avfltctl_activate(void);
int avfltctl_deactivate(void);
int avfltctl_invalidate_cache(void);
int avfltctl_enable_cache(void);
int avfltctl_disable_cache(void);
int avfltctl_invalidate_path_cache(int id);
int avfltctl_enable_path_cache(int id);
int avfltctl_disable_path_cache(int id);
int avfltctl_set_timeout(int timeout);

#ifdef __cplusplus
}
#endif

#endif

