#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include "compflt.h"

#define CACHE_NAME "cflt_block"

static struct kmem_cache *cflt_block_cache = NULL;
atomic_t block_cache_cnt;
wait_queue_head_t block_cache_w;

int cflt_block_cache_init(void)
{
        cflt_debug_printk("compflt: [f:cflt_block_cache_init]\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
        cflt_block_cache = kmem_cache_create(CACHE_NAME, sizeof(struct cflt_block), 0, 0, NULL, NULL);
#else
        cflt_block_cache = kmem_cache_create(CACHE_NAME, sizeof(struct cflt_block), 0, 0, NULL);
#endif

        if (!cflt_block_cache)
                return -ENOMEM;

        init_waitqueue_head(&block_cache_w);
        atomic_set(&block_cache_cnt, 0);

        return 0;
}

void cflt_block_cache_deinit(void)
{
        cflt_debug_printk("compflt: [f:cflt_block_cache_deinit]\n");

        wait_event_interruptible(block_cache_w, !atomic_read(&block_cache_cnt));
        kmem_cache_destroy(cflt_block_cache);
}

struct cflt_block* cflt_block_init(void)
{
        struct cflt_block *blk;

        cflt_debug_printk("compflt: [f:cflt_block_init]\n");

        blk = kmem_cache_alloc(cflt_block_cache, GFP_KERNEL);

        if (!blk) {
                printk(KERN_ERR "compflt: failed to allocate a block\n");
                return NULL;
        }

        blk->data_u = blk->data_c = NULL;
        blk->par = NULL;
        blk->type = CFLT_BLK_NORM;
        atomic_set(&blk->dirty, 0);
        blk->off_u = blk->off_c = 0;
        blk->size_u = blk->size_c = 0;

        INIT_LIST_HEAD(&blk->file);

        return blk;
}

void cflt_block_deinit(struct cflt_block *blk)
{
        cflt_debug_printk("compflt: [f:cflt_block_deinit]\n");

        kmem_cache_free(cflt_block_cache, blk);
}

// sets 'off' to the start of the next header (or 0 if last)
int cflt_block_read_header(struct file *f, struct cflt_block *blk, loff_t *off)
{
        int rv = 0;
        int boff = 0;
        char buf[CFLT_BH_SIZE]; // max size

        cflt_debug_printk("compflt: [f:cflt_block_read_header]\n");

        memset(buf, 0, sizeof(buf));
        blk->off_c = *off;

        rv = cflt_orig_read(f, buf, sizeof(buf), off);
        if (!rv) {
                return -1;
        }

        memcpy((char*)&blk->type, buf+boff, sizeof(u8));
        boff += sizeof(u8);

        // rest is block-type specific
        switch (blk->type) {
        case CFLT_BLK_FREE:
                // +--------------------+
                // | T | 0000 | SC | 00 |
                // +--------------------+
                blk->off_u = 0;
                boff += sizeof(u32);
                memcpy(&blk->size_c, buf+boff, sizeof(u16));
                blk->size_u = 0;
                break;
        case CFLT_BLK_NORM:
                // +--------------------+
                // | T | OFFU | SC | SU |
                // +--------------------+
                memcpy(&blk->off_u, buf+boff, sizeof(u32));
                boff += sizeof(u32);
                memcpy(&blk->size_c, buf+boff, sizeof(u16));
                boff += sizeof(u16);
                memcpy(&blk->size_u, buf+boff, sizeof(u16));
                break;
        default:
                BUG();
                break;
        }

        cflt_debug_block(blk);

        *off = blk->off_c+CFLT_BH_SIZE+blk->size_c;
        return 0;
}

int cflt_block_write_header(struct file *f, struct cflt_block *blk)
{
        loff_t off;
        char buf[CFLT_BH_SIZE]; // max size
        int boff = 0;
        int rv = 0;

        cflt_debug_printk("compflt: [f:cflt_block_write_header]\n");

        if (!atomic_read(&blk->dirty))
                return 0;

        memcpy(buf+boff, &blk->type, sizeof(u8));
        boff += sizeof(u8);

        // rest is block-type specific
        switch (blk->type) {
        case CFLT_BLK_FREE:
                // +--------------------+
                // | T | 0000 | SC | 00 |
                // +--------------------+
                memset(buf+boff, 0, sizeof(u32));
                boff += sizeof(u32);
                memcpy(buf+boff, &blk->size_c, sizeof(u16));
                boff += sizeof(u16);
                memset(buf+boff, 0, sizeof(u16));
                break;
        case CFLT_BLK_NORM:
                // +--------------------+
                // | T | OFFU | SC | SU |
                // +--------------------+
                memcpy(buf+boff, &blk->off_u, sizeof(u32));
                boff += sizeof(u32);
                memcpy(buf+boff, &blk->size_c, sizeof(u16));
                boff += sizeof(u16);
                memcpy(buf+boff, &blk->size_u, sizeof(u16));
                break;
        default:
                BUG();
                break;
        }

        off = blk->off_c;
        rv = cflt_orig_write(f, buf, sizeof(buf), &off);
        if (!rv) {
                printk(KERN_ERR "compflt: failed to write header\n");
                return -1;
        }
        atomic_set(&blk->dirty, 0);

        return 0;
}

static int cflt_block_read_c(struct file *f, struct cflt_block *blk)
{
        loff_t off_data = blk->off_c + CFLT_BH_SIZE;

        cflt_debug_printk("compflt: [f:cflt_block_read_c]\n");

        cflt_orig_read(f, blk->data_c, blk->size_c, &off_data);

        return 0;
}

int cflt_block_read(struct file *f, struct cflt_block *blk, struct crypto_comp *tfm)
{
        int err = 0;

        cflt_debug_printk("compflt: [f:cflt_block_read]\n");

        blk->data_c = kmalloc(blk->size_c, GFP_KERNEL);
        if (!blk->data_c)
                return -ENOMEM;

        if ((err = cflt_block_read_c(f, blk))) {
                printk(KERN_ERR "compflt: failed to read block error: %i\n", err);
                return err;
        }

        if ((err = cflt_decomp_block(tfm, blk))) {
                printk(KERN_ERR "compflt: failed to decompress block error: %i\n", err);
                return err;
        }

        kfree(blk->data_c);
        return err;
}

int cflt_block_write(struct file *f, struct cflt_block *blk, struct crypto_comp *tfm)
{
        int err = 0;
        loff_t off_data;
        size_t old = blk->size_c;

        cflt_debug_printk("compflt: [f:cflt_block_write]\n");

        err = cflt_comp_block(tfm, blk);
        if (err)
                return err;

        cflt_file_place_block(blk, old);

        off_data = blk->off_c + CFLT_BH_SIZE;
        cflt_orig_write(f, blk->data_c, blk->size_c, &off_data);

        kfree(blk->data_c);
        return err;
}
