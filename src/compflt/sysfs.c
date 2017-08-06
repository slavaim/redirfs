#include <linux/sysfs.h>
#include "compflt.h"

#define CFLT_ATTR(__name, __mode)       \
struct attribute cflt_attr_##__name = { \
        .name = __stringify(__name),    \
        .mode = __mode,                 \
        .owner = THIS_MODULE            \
};

struct kobject *cflt_root_ko;

static struct kobject cflt_settings_ko;
static struct kobj_type cflt_settings_ktype;
static struct sysfs_ops cflt_settings_sops;

static CFLT_ATTR(method, 0644);
static CFLT_ATTR(blksize, 0644);

static struct attribute *cflt_settings_attrs[] = {
        &cflt_attr_method,
        &cflt_attr_blksize,
        NULL
};

static ssize_t cflt_sysfs_settings_show(struct kobject *kobj, struct attribute *attr,
                char *buf)
{
        int len;
        cflt_debug_printk("compflt: [f:cflt_sysfs_settings_show]\n");

        if (!strcmp(attr->name, "method"))
                len = cflt_comp_method_get(buf, PAGE_SIZE);
        else if (!strcmp(attr->name, "blksize"))
                len = cflt_file_blksize_get(buf, PAGE_SIZE);
        else
                return -EINVAL;

        return len;
}

static ssize_t cflt_sysfs_settings_store(struct kobject *kobj, struct attribute *attr,
                const char *buf, size_t size)
{
        cflt_debug_printk("compflt: [f:cflt_sysfs_settings_store]\n");

        if (!strcmp(attr->name, "method"))
                cflt_comp_method_set(buf);
        else if (!strcmp(attr->name, "blksize"))
                cflt_file_blksize_set(simple_strtol(buf, (char**)NULL, 10));

        return size; // this is ok for now
}

int cflt_sysfs_init (void)
{
        int err;

        cflt_debug_printk("compflt: [f:cflt_sysfs_init]\n");

        err = rfs_get_kobject(compflt, &cflt_root_ko);
        if (err)
                return err;

        memset(&cflt_settings_ko, 0, sizeof(cflt_settings_ko));
        memset(&cflt_settings_ktype, 0, sizeof(cflt_settings_ktype));
        memset(&cflt_settings_sops, 0, sizeof(cflt_settings_sops));

        cflt_settings_sops.show = cflt_sysfs_settings_show;
        cflt_settings_sops.store = cflt_sysfs_settings_store;

        cflt_settings_ktype.release = NULL;
        cflt_settings_ktype.default_attrs = cflt_settings_attrs;
        cflt_settings_ktype.sysfs_ops = &cflt_settings_sops;

        kobject_set_name(&cflt_settings_ko, "%s", "settings");
        cflt_settings_ko.parent = cflt_root_ko;
        cflt_settings_ko.ktype = &cflt_settings_ktype;

        if ((err = kobject_register(&cflt_settings_ko)))
                return err;

        return 0;
}

void cflt_sysfs_deinit(void)
{
        cflt_debug_printk("compflt: [f:cflt_sysfs_deinit]\n");
        kobject_unregister(&cflt_settings_ko);
}
