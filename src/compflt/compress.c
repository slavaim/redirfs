#include <linux/crypto.h>
#include "compflt.h"

// cryptoapi doesnt provide a way to iterate over all registered methods.
char *cflt_method_known[] = { "", "deflate", "lzf", "bzip2", "rle", "null", NULL };
unsigned int cflt_cmethod = 0;

struct crypto_comp *cflt_comp_init(unsigned int mid)
{
        struct crypto_comp *tfm = NULL;

        cflt_debug_printk("compflt: [f:comp_init]\n");

        // initialize compression method
        if (!crypto_has_alg(cflt_method_known[mid], 0, 0)) {
                printk(KERN_ERR "compflt: compression method %s "
                                "unavailable\n", cflt_method_known[mid]);
                return NULL;
        }

        tfm = crypto_alloc_comp(cflt_method_known[mid], 0, 0);
        if (tfm == NULL) {
                printk(KERN_ERR "compflt: failed to alloc %s "
                                "compression method\n", cflt_method_known[mid]);
                return NULL;
        }

        return tfm;
}

inline void cflt_comp_deinit(struct crypto_comp *tfm)
{
        crypto_free_comp(tfm);
}

int cflt_decomp_block(struct crypto_comp *tfm, struct cflt_block *blk)
{
        int rv = 0;

        cflt_debug_printk("compflt: [f:decomp_block]\n");

	memset(blk->data_u, 0, blk->par->blksize);

	if ((rv = crypto_comp_decompress(tfm, blk->data_c, blk->size_c, blk->data_u, &blk->size_u))) {
                printk(KERN_ERR "compflt: failed to decompress data block error: %i\n", rv);
                kfree(blk->data_u);
                return rv;
        }

        cflt_debug_printk("compflt: [f:decomp_block] decompressed %i bytes | ratio=%i:%i\n", blk->size_c, blk->size_c, blk->size_u);

        return rv;
}

int cflt_comp_block(struct crypto_comp *tfm, struct cflt_block *blk)
{
        int rv = 0;
        unsigned int size_c;

        cflt_debug_printk("compflt: [f:comp_block]\n");

        size_c = 2*blk->par->blksize;
        blk->data_c = kmalloc(size_c, GFP_KERNEL);
        if (!blk->data_c)
                return -ENOMEM;

	memset(blk->data_c, 0, size_c);
        if ((rv = crypto_comp_compress(tfm, blk->data_u, blk->size_u, blk->data_c, &size_c))) {
                printk(KERN_ERR "compflt: failed to compress data block error: %i\n", rv);
                kfree(blk->data_c);
                return rv;
        }

        cflt_debug_printk("compflt: [f:comp_block] compressed %i bytes | ratio=%i:%i\n", blk->size_u, size_c, blk->size_u);

        blk->size_c = size_c;

        return rv;
}

int cflt_comp_method_get(char* buf, int bsize)
{
        int len = 0;

        if (strlen(cflt_method_known[cflt_cmethod]) > bsize)
                return 0;

        len = sprintf(buf, "%s\n", cflt_method_known[cflt_cmethod]);
        return len;
}

int cflt_comp_method_set(const char* buf)
{
        char **p = cflt_method_known;
        int i = 1;

        p++; // skip 1st 'dummy' entry
        while (*p) {
                if (!strcmp(*p, buf) && strlen(*p) == strlen(buf)) {
                        if (crypto_has_alg(*p, 0, 0)) {
                                cflt_cmethod = i;
                                printk(KERN_INFO "compflt: compression method set to '%s'\n", *p);
                                return 0;
                        }
                        else {
                                printk(KERN_INFO "compflt: compression method '%s' unavailable\n", *p);
                        }
                        break;
                }
                p++; i++;
        }

        return -1;
}
