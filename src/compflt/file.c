#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include "../redirfs/redirfs.h"
#include "compflt.h"

#define CACHE_NAME "cflt_file"

static struct kmem_cache *cflt_file_cache = NULL;
atomic_t file_cache_cnt;
wait_queue_head_t file_cache_w;

struct list_head cflt_file_list;
spinlock_t cflt_file_list_l = SPIN_LOCK_UNLOCKED;

static unsigned int cflt_blksize = CFLT_DEFAULT_BLKSIZE;


void cflt_file_truncate(struct cflt_file *fh)
{
        cflt_debug_printk("compflt: [f:cflt_file_truncate] i=%li\n", fh->inode->i_ino);

        fh->size_u = 0;
        fh->method = cflt_cmethod;
        fh->blksize = cflt_blksize;
        atomic_set(&fh->dirty, 0);
        atomic_set(&fh->compressed, 0);
}

// deinit all block belonging to this file
inline void cflt_file_clr_blks(struct cflt_file *fh)
{
        struct cflt_block *blk;
        struct cflt_block *tmp;

        cflt_debug_printk("compflt: [f:cflt_file_clr_blks]\n");

        list_for_each_entry_safe(blk, tmp, &fh->blks, file) {
                list_del(&blk->file);
                cflt_block_deinit(blk);
        }
}

// alloc and initialize a (struct cflt_file)
static struct cflt_file* cflt_file_init(struct inode *inode)
{
        struct cflt_file *fh;

        cflt_debug_printk("compflt: [f:cflt_file_init] i=%li\n", inode->i_ino);

        fh = kmem_cache_alloc(cflt_file_cache, GFP_KERNEL);
        if (!fh) {
                printk(KERN_ERR "compflt: failed to alloc file header\n");
                return NULL;
        }
        atomic_inc(&file_cache_cnt);

        INIT_LIST_HEAD(&fh->blks);

        init_waitqueue_head(&fh->ref_w);
        spin_lock_init(&fh->lock);
        atomic_set(&fh->cnt, 0);
        atomic_set(&fh->dirty, 0);
        atomic_set(&fh->compressed, 0);
        fh->inode = inode;
        fh->size_u = 0;
        fh->method = cflt_cmethod;
        fh->blksize = cflt_blksize;

        spin_lock(&cflt_file_list_l);
        list_add(&(fh->all), &(cflt_file_list));
        spin_unlock(&cflt_file_list_l);

        return fh;
}

// dealloc a (struct cflt_file) and remove from master file list
static void cflt_file_deinit(struct cflt_file *fh)
{
	unsigned long flags;

        cflt_debug_printk("compflt: [f:cflt_file_deinit] i=%li\n", fh->inode->i_ino);

        wait_event_interruptible(fh->ref_w, !atomic_read(&fh->cnt));

        //TODO: irqsave not needed anymore ? (doesnt get called from the rfs
        // callback now)
        spin_lock_irqsave(&cflt_file_list_l, flags);
        list_del(&fh->all);
        spin_unlock_irqrestore(&cflt_file_list_l, flags);

        cflt_file_clr_blks(fh);

        kmem_cache_free(cflt_file_cache, fh);

        if(atomic_dec_and_test(&file_cache_cnt)) {
                wake_up_interruptible(&file_cache_w);
        }
}

/*
// callback registered with redirfs
static inline void cflt_file_deinit_cb(void *data)
{
        cflt_file_deinit((struct cflt_file*)data);
}
*/

int cflt_file_cache_init(void)
{
        cflt_debug_printk("compflt: [f:cflt_file_cache_init]\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
        cflt_file_cache = kmem_cache_create(CACHE_NAME, sizeof(struct cflt_file), 0, 0, NULL, NULL);
#else
        cflt_file_cache = kmem_cache_create(CACHE_NAME, sizeof(struct cflt_file), 0, 0, NULL);
#endif

        if (!cflt_file_cache)
                return -ENOMEM;

        init_waitqueue_head(&file_cache_w);
        atomic_set(&file_cache_cnt, 0);

        INIT_LIST_HEAD(&cflt_file_list);

        return 0;
}

static void cflt_file_update_size(struct cflt_file *fh)
{
        struct cflt_block *blk;

        spin_lock(&fh->lock);
        fh->size_u = 0;
        list_for_each_entry(blk, &fh->blks, file) {
                fh->size_u += blk->size_u;
        }
        spin_unlock(&fh->lock);
}

void cflt_file_cache_deinit(void)
{
        struct cflt_file *fh;
        struct cflt_file *tmp;

        cflt_debug_printk("compflt: [f:cflt_file_cache_deinit]\n");

        list_for_each_entry_safe(fh, tmp, &cflt_file_list, all) {
                cflt_file_deinit(fh);
        }

        wait_event_interruptible(file_cache_w, !atomic_read(&file_cache_cnt));
        kmem_cache_destroy(cflt_file_cache);
}

// Add the block to the right spot in the blks list after it was moved within
// the file (cflt_file_place_old_blk)
// @blk: block to (re)place in the list
static void cflt_file_readd_blk(struct cflt_block *blk)
{
        list_del(&blk->file);
        cflt_file_add_blk(blk->par, blk);
}

// Add @block to @fh->blks list in order of off_c
// @fh: struct cflt_file to which we are adding the block
// @blk: added block
void cflt_file_add_blk(struct cflt_file *fh, struct cflt_block *blk)
{
        struct cflt_block *aux;
        struct list_head *head = NULL;

        cflt_debug_printk("compflt: [f:cflt_file_add_blk] i=%li\n", fh->inode->i_ino);

        head = &fh->blks;
        list_for_each_entry(aux, &fh->blks, file) {
                if (aux->off_c > blk->off_c)
                        head = &aux->file;
        }

        list_add_tail(&blk->file, head);

        blk->par = fh;
}

void cflt_file_del_blk(struct cflt_block *blk)
{
        list_del(&blk->file);
}

// read all block headers from file
int cflt_file_read_block_headers(struct file *f, struct cflt_file *fh)
{
        int err = 0;
        loff_t off = CFLT_FH_SIZE;
        struct cflt_block *blk;

        cflt_debug_printk("compflt: [f:cflt_file_read_block_headers]\n");

        while(!err) {
                blk = cflt_block_init();
                if (!blk) {
                        // TODO: change cflt_block_init prototype to return the error
                        err = -ENOMEM;
                        printk(KERN_ERR "compflt: failed to init a block\n");
                        return err;
                }

                err = cflt_block_read_header(f, blk, &off);
                if (err)
                        cflt_block_deinit(blk);
                else 
                        cflt_file_add_blk(fh, blk);
        }

        return err;
}

// write headers of all blocks to file
void cflt_file_write_block_headers(struct file *f, struct cflt_file *fh)
{
        struct cflt_block *blk;

        cflt_debug_printk("compflt: [f:cflt_block_write_block_headers]\n");

        //spin_lock(&fh->lock);
        list_for_each_entry(blk, &fh->blks, file) {
                cflt_block_write_header(f, blk);
        }
        //spin_unlock(&fh->lock);
}

// TODO: change to return int , and move cflt_file to params
// try to find the cflt_file corresponding to @inode in the cache
// @inode: inode to match with an cflt_file
struct cflt_file *cflt_file_find(struct inode *inode)
{
        struct cflt_privd *pd;
        struct rfs_priv_data *rfs_data;
        int err;

        cflt_debug_printk("compflt: [f:cflt_file_find] i=%li\n", inode->i_ino);

        err = rfs_get_data_inode(compflt, inode, &rfs_data);
        if (err)
                return NULL;

        pd = cflt_privd_from_rfs(rfs_data);

        return pd->fh;
}

// if the cflt_file is not in the cache and f is set then try to read it from
// the file
struct cflt_file *cflt_file_get(struct inode *inode, struct file *f)
{
        struct cflt_file *fh = NULL;
        struct cflt_privd *pd = NULL;
        struct rfs_priv_data *exist = NULL;

        cflt_debug_printk("compflt: [f:cflt_file_get] i=%li\n", inode->i_ino);

        fh = cflt_file_find(inode);
        if (!fh && f) {
                fh = cflt_file_init(inode);

                if (!fh)
                        return NULL;

                if (cflt_file_read(f, fh)) {
                        // not an error (file doesnt exist or not copressed)
                        printk(KERN_ERR "compflt: failed to read file header\n");
                        cflt_file_deinit(fh);
                        return NULL;
                }

                // TODO: this can fail ... returns NULL atm ?
                pd = cflt_privd_init(fh);

                rfs_attach_data_inode(compflt, inode, &pd->rfs_data, &exist);
                if (atomic_read(&fh->compressed))
                        cflt_file_read_block_headers(f, fh);

        }

        if (fh) {
                atomic_inc(&fh->cnt);
                cflt_file_update_size(fh);
        }

        return fh;
}

void cflt_file_put(struct cflt_file *fh)
{
        BUG_ON(!atomic_read(&fh->cnt));

        if(atomic_dec_and_test(&fh->cnt)) {
                wake_up_interruptible(&fh->ref_w);
        }
}


int cflt_file_blksize_set(unsigned long int new)
{
        if (new >= CFLT_BLKSIZE_MIN && new <= CFLT_BLKSIZE_MAX && !(new%CFLT_BLKSIZE_MOD)) {
                cflt_blksize = new;
                printk(KERN_INFO "compflt: block size set to %li bytes\n", new);
        }
        else {
                printk(KERN_INFO "compflt: block size %li is out of the permitted range\n", new);
        }

        return 0;
}

int cflt_file_blksize_get(char* buf, int bsize)
{
        int len = 0;
        len = sprintf(buf, "%i\n", cflt_blksize);
        return len;
}

int cflt_file_read(struct file *f, struct cflt_file *fh)
{
        char buf[CFLT_FH_SIZE];
        loff_t off = 0;
        int boff = 0;
        int rv = 0;

        cflt_debug_printk("compflt: [f:cflt_file_read] i=%li\n", fh->inode->i_ino);

        rv = cflt_orig_read(f, buf+boff, sizeof(buf), &off);
        if(rv < sizeof(CFLT_MAGIC)-1 || memcmp(buf, CFLT_MAGIC, sizeof(CFLT_MAGIC)-1)) {
                atomic_set(&fh->dirty, 1);
                return 0;
        }
        atomic_set(&fh->compressed, 1);
        boff += sizeof(CFLT_MAGIC)-1;
        memcpy(&fh->method, buf+boff, sizeof(u8));
        boff += sizeof(u8);
        memcpy(&fh->blksize, buf+boff, sizeof(u32));

        return 0;
}

struct cflt_block* cflt_file_last_blk(struct cflt_file *fh)
{
        struct cflt_block *aux;

        if (list_empty(&fh->blks))
                return NULL;

        list_for_each_entry(aux, &fh->blks, file) {
                if (list_is_last(&aux->file, &fh->blks))
                        return aux;
        }

        BUG();
        return NULL; // just to shut-up the compiler
}

// place a new block in the file (set off_c)
// @blk: new block (off_u, size_u and size_c have to be valid)
static int cflt_file_place_new_block(struct cflt_block *new)
{
        struct cflt_block *aux;

        cflt_debug_printk("--- placing new block ---\n");

        // try to find a free block
        // TODO: optimize to use the block that has the smallest size difference
        list_for_each_entry(aux, &new->par->blks, file) {
                if (aux->type == CFLT_BLK_FREE && aux->size_c > new->size_c) {
                        cflt_debug_printk("using an existing free block\n");

                        aux->size_c -= new->size_c;
                        new->off_c = aux->off_c;

                        if (unlikely(aux->size_c)) {
                                cflt_file_del_blk(aux);
                                cflt_block_deinit(aux);
                        }
                        else { // some free space left
                                aux->off_c = new->off_c+CFLT_BH_SIZE+new->size_c;
                                atomic_set(&aux->dirty, 1);
                        }
                        atomic_set(&new->dirty, 1);
                        return 0;
                }
        }

        cflt_debug_printk("placing at the end of file\n");
        aux = cflt_file_last_blk(new->par);

        if (!aux) { // first block
                cflt_debug_printk("as first block\n");
                new->off_c = CFLT_FH_SIZE;
        }
        else {
                new->off_c = aux->off_c+CFLT_BH_SIZE+aux->size_c;
        }

        atomic_set(&new->dirty, 1);

        cflt_debug_printk("--- ^^^^^^^^^^^^^^^^^ ---\n");

        return 0;
}

static int cflt_file_place_old_block(struct cflt_block *blk, unsigned int size_c_old)
{
        struct cflt_block *aux;
        struct cflt_block *new;
        struct cflt_file *fh = blk->par;
        int size_diff = blk->size_c - size_c_old;
        unsigned int off_aux = 0;

        cflt_debug_printk("--- placing old block ---\n");

        // TODO: merge these too conditions after debug
        if (unlikely(!size_diff)) {
                cflt_debug_printk("same size , no action\n");
        }
        else if (list_is_last(&blk->file, &fh->blks)) {
                cflt_debug_printk("last block, no action\n");
        }
        else if (size_diff < 0) { // shrink
                cflt_debug_printk("smaller\n");

                // move it if we cant fit a free block in the free space
                if (-size_diff <= CFLT_BH_SIZE+1)
                        goto move;

                // create free block
                new = cflt_block_init();
                new->type = CFLT_BLK_FREE;
                new->off_c = blk->off_c+CFLT_BH_SIZE+blk->size_c;
                new->size_c = -size_diff;
                atomic_set(&new->dirty, 1);
                cflt_file_add_blk(blk->par, new);

                atomic_set(&blk->dirty, 1);
        }
        else { // grow
                cflt_debug_printk("bigger\n");

                // expand if the next block is free and has enough space
                aux = list_entry(blk->file.next, struct cflt_block, file);
                if (aux->type == CFLT_BLK_FREE && aux->size_c > size_diff) {
                        aux->off_c += size_diff;
                        aux->size_c -= size_diff;
                        atomic_set(&aux->dirty, 1);
                }
                else
                        goto move;
        }

        cflt_debug_printk("--- ^^^^^^^^^^^^^^^^^ ---\n");
        return 0;

move:
        // move if the previous block is free and has enough space
        aux = list_entry(blk->file.prev, struct cflt_block, file);
        if (aux && aux->type == CFLT_BLK_FREE && aux->size_c > size_diff) {
                cflt_debug_printk("using previous free block\n");
                blk->off_c -= size_diff;
                atomic_set(&blk->dirty, 1);
                aux->size_c -= size_diff;
                atomic_set(&aux->dirty, 1);
                goto end;
        }

        // try to find a suitable free block anywhere
        list_for_each_entry(aux, &blk->par->blks, file) {
                if (aux->type == CFLT_BLK_FREE && aux->size_c > blk->size_c) {
                        cflt_debug_printk("using any free block\n");
                        aux->size_c = size_c_old;

                        off_aux = aux->off_c;
                        aux->off_c = blk->off_c;
                        blk->off_c = off_aux;

                        atomic_set(&blk->dirty, 1);
                        atomic_set(&aux->dirty, 1);
                        goto end;
                }
        }

        cflt_debug_printk("moving to the end of file\n");

        // move to the end of the file
        aux = cflt_file_last_blk(blk->par);

        // create free block
        new = cflt_block_init();
        new->type = CFLT_BLK_FREE;
        new->off_c = blk->off_c;
        new->size_c = size_c_old;
        atomic_set(&new->dirty, 1);
        cflt_file_add_blk(blk->par, new);

        blk->off_c = aux->off_c+CFLT_BH_SIZE+aux->size_c;
        atomic_set(&blk->dirty, 1);

        cflt_file_readd_blk(blk);

        cflt_debug_file(blk->par);

end:
        cflt_debug_printk("--- ^^^^^^^^^^^^^^^^^ ---\n");
        return 0;
}


// place the block within the file
// @blk: block to move with new size_c
// @size_c_old: blocks' old size_c value
int cflt_file_place_block(struct cflt_block *blk, unsigned int size_c_old)
{
        if (!size_c_old) // new block
                return cflt_file_place_new_block(blk);
        else // old block
                return cflt_file_place_old_block(blk, size_c_old);
}

void cflt_file_write(struct file *f, struct cflt_file *fh)
{
        loff_t off = 0;
        char buf[CFLT_FH_SIZE];
        int boff = 0;

        cflt_debug_printk("compflt: [f:cflt_file_write] i=%li\n", fh->inode->i_ino);

        if (!atomic_read(&fh->dirty))
                return;

        memcpy(buf+boff, CFLT_MAGIC, sizeof(CFLT_MAGIC)-1);
        boff += sizeof(CFLT_MAGIC)-1;
        memcpy(buf+boff, &fh->method, sizeof(u8));
        boff += sizeof(u8);
        memcpy(buf+boff, &fh->blksize, sizeof(u32));
        cflt_orig_write(f, buf, sizeof(buf), &off);

        atomic_set(&fh->dirty, 0);
}
