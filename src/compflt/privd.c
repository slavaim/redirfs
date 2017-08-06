#include <linux/slab.h>
#include "../redirfs/redirfs.h"
#include "compflt.h"

#define CACHE_NAME "cflt_privd"

static struct kmem_cache *cflt_privd_cache = NULL;
atomic_t privd_cache_cnt;
wait_queue_head_t privd_cache_w;

struct list_head cflt_privd_list;
spinlock_t cflt_privd_list_l = SPIN_LOCK_UNLOCKED;

inline struct cflt_privd *cflt_privd_from_rfs(struct rfs_priv_data *rfs_data)
{
        cflt_debug_printk("compflt: [f:cflt_privd_from_rfs]\n");
        return container_of(rfs_data, struct cflt_privd, rfs_data);
}

int cflt_privd_cache_init(void)
{
        cflt_debug_printk("compflt: [f:cflt_privd_cache_init]\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
        cflt_privd_cache = kmem_cache_create(CACHE_NAME, sizeof(struct cflt_privd), 0, 0, NULL, NULL);
#else
        cflt_privd_cache = kmem_cache_create(CACHE_NAME, sizeof(struct cflt_privd), 0, 0, NULL);
#endif

        if (!cflt_privd_cache)
                return -ENOMEM;

        init_waitqueue_head(&privd_cache_w);
        atomic_set(&privd_cache_cnt, 0);

        INIT_LIST_HEAD(&cflt_privd_list);

        return 0;
}

void cflt_privd_deinit(struct cflt_privd *pd)
{
        cflt_debug_printk("compflt: [f:cflt_privd_deinit]\n");

        spin_lock(&cflt_privd_list_l);
        list_del(&(pd->all));
        spin_unlock(&cflt_privd_list_l);

        rfs_put_data(&pd->rfs_data);

        kmem_cache_free(cflt_privd_cache, pd);

        if(atomic_dec_and_test(&privd_cache_cnt)) {
                wake_up_interruptible(&privd_cache_w);
        }
}

void cflt_privd_cache_deinit(void)
{
        struct cflt_privd *pd;
        struct cflt_privd *tmp;

        cflt_debug_printk("compflt: [f:cflt_privd_cache_deinit]\n");

        list_for_each_entry_safe(pd, tmp, &cflt_privd_list, all) {
                cflt_privd_deinit(pd);
        }

        wait_event_interruptible(privd_cache_w, !atomic_read(&privd_cache_cnt));
        kmem_cache_destroy(cflt_privd_cache);
}


static void cflt_privd_free_cb(struct rfs_priv_data *rfs_data)
{
        struct cflt_privd *pd;

        cflt_debug_printk("compflt: [f:cflt_privd_free_cb]\n");
        
        pd = cflt_privd_from_rfs(rfs_data);
        cflt_privd_deinit(pd);
}

struct cflt_privd *cflt_privd_init(struct cflt_file *fh)
{
        struct cflt_privd *pd;
        int err;

        cflt_debug_printk("compflt: [f:cflt_privd_init]\n");

        pd = kmem_cache_alloc(cflt_privd_cache, GFP_KERNEL);
        if (!pd) {
                printk(KERN_ERR "compflt: failed to alloc private data\n");
                return NULL;
        }

        err = rfs_init_data(&pd->rfs_data, compflt, cflt_privd_free_cb);
        if (err) {
                kmem_cache_free(cflt_privd_cache, pd);
                return NULL;
        }

        atomic_inc(&privd_cache_cnt);

        pd->fh = fh;

        spin_lock(&cflt_privd_list_l);
        list_add(&(pd->all), &(cflt_privd_list));
        spin_unlock(&cflt_privd_list_l);

        return pd;
}
