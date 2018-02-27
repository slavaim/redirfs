/*
 *          Copyright Frantisek Hrbata 2008 - 2010.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 */

#ifndef __RFSCTL_H__
#define __RFSCTL_H__

#define RFSCTL_PATH_INCLUDE    1
#define RFSCTL_PATH_EXCLUDE    2

struct rfsctl_path {
    int type;
    int id;
    char *name;
};

struct rfsctl_filter {
    struct rfsctl_path **paths;
    char *name;
    int priority;
    int active;
};

#ifdef __cplusplus
extern "C" {
#endif

struct rfsctl_filter *rfsctl_get_filter(const char *name);
void rfsctl_put_filter(struct rfsctl_filter *filter);
struct rfsctl_filter **rfsctl_get_filters(void);
void rfsctl_put_filters(struct rfsctl_filter **filters);
int rfsctl_add_path(const char *name, const char *path, int type);
int rfsctl_rem_path(const char *name, int id);
int rfsctl_rem_path_name(const char *name, const char *path);
int rfsctl_del_paths(const char *name);
int rfsctl_unregister(const char *name);
int rfsctl_activate(const char *name);
int rfsctl_deactivate(const char *name);
int rfsctl_read_data(const char *fltname, const char *filename, char *buf,
        int size);
int rfsctl_write_data(const char *fltname, const char *filename, char *buf,
        int size);

#ifdef __cplusplus
}
#endif

#endif

