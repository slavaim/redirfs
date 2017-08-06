#include <linux/kernel.h>
#include "compflt.h"

#ifdef CFLT_DEBUG

void cflt_debug_block(struct cflt_block *blk)
{
        printk("[block] %i@%i -> %i@%i F=%i\n",
        (int)blk->size_c, (int)blk->off_c, (int)blk->size_u, (int)blk->off_u,
        (blk->type == CFLT_BLK_FREE));
}

void cflt_debug_file_header(struct cflt_file *fh)
{
        printk("[file] ino=%li compressed=%i dirty=%i method=%i blksize=%i size=%i\n",
                        fh->inode->i_ino, atomic_read(&fh->compressed),
                        atomic_read(&fh->dirty), fh->method, fh->blksize,
                        (int)fh->size_u);
}

void cflt_debug_file(struct cflt_file *fh)
{
        struct cflt_block *blk;

        printk("---------- file ----------\n");
        cflt_debug_file_header(fh);
        list_for_each_entry(blk, &fh->blks, file) {
                cflt_debug_block(blk);
        }
        printk("---------- ^^^^ ----------\n");
}

void cflt_hexdump(void *buf, unsigned int len)
{
        int i = 0;

        while (len--) {
                if (!(i % 16)) {
                        if (i) printk("\n");
                        printk("%07x ", i);
                }
                printk("%02x ", *(u8 *)buf++);
                i++;
        }
        printk("\n");
}

#endif
