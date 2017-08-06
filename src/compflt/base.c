#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include "../redirfs/redirfs.h"
#include "compflt.h"
#include "path.h"

char version[] = "0";

static char *in_cmethod = CFLT_DEFAULT_METHOD;
module_param(in_cmethod, charp, 0000);
MODULE_PARM_DESC(in_cmethod, "Initial compression method to use");

static int in_blksize = CFLT_DEFAULT_BLKSIZE;
module_param(in_blksize, int, 0000);
MODULE_PARM_DESC(in_blksize, "Initial block size to use");

static enum rfs_retv cflt_f_pre_llseek(rfs_context context, struct rfs_args *args)
{
        struct file *f = args->args.f_llseek.file;
        struct cflt_file *fh;

        cflt_debug_printk("compflt: [pre_llseek] i=%li\n",
                        f->f_dentry->d_inode->i_ino);

        fh = cflt_file_get(f->f_dentry->d_inode, f);
        if (!fh)
                return RFS_CONTINUE;

        cflt_debug_file_header(fh);

        if (!atomic_read(&fh->compressed))
                goto end;

        cflt_debug_printk("compflt: setting inode->i_size to %i\n", fh->size_u);
        mutex_lock(&f->f_dentry->d_inode->i_mutex);
        i_size_write(f->f_dentry->d_inode, fh->size_u);
        mutex_unlock(&f->f_dentry->d_inode->i_mutex);

end:
        cflt_file_put(fh);
        return RFS_CONTINUE;
}

static enum rfs_retv cflt_f_pre_open(rfs_context context, struct rfs_args *args)
{
        struct file *f = args->args.f_open.file;
        struct inode *inode = args->args.f_open.inode;
        struct cflt_file *fh;

        cflt_debug_printk("compflt: [pre_open i=%li\n", inode->i_ino);

        if (f->f_flags & O_TRUNC) {
                fh = cflt_file_get(inode, NULL);
                if (fh) {
                        cflt_file_clr_blks(fh);
                        cflt_file_truncate(fh);
                        cflt_file_put(fh);
                }
        }

        return RFS_CONTINUE;
}

static enum rfs_retv cflt_f_post_release(rfs_context context, struct rfs_args *args)
{
        struct inode *inode = args->args.f_release.inode;
        struct file *f = args->args.f_release.file;
        struct cflt_file *fh;

        cflt_debug_printk("compflt: [post_release] i=%li\n", inode->i_ino);

        fh = cflt_file_get(inode, NULL);
        if (!fh)
                return RFS_CONTINUE;

        if (atomic_read(&fh->compressed)) {
                cflt_file_write(f, fh);
                cflt_file_write_block_headers(f, fh);
        }

        cflt_file_put(fh);

        return RFS_CONTINUE;
}

static enum rfs_retv cflt_f_pre_read(rfs_context context, struct rfs_args *args)
{
        struct file *f = args->args.f_read.file;
        size_t count = args->args.f_read.count;
        loff_t *pos = args->args.f_read.pos;
        char __user *dst = args->args.f_read.buf;
        size_t *op_rv = &args->retv.rv_ssize;
        struct cflt_file *fh;
        enum rfs_retv rv = RFS_CONTINUE;

        cflt_debug_printk("compflt: [pre_read] i=%li | pos=%i len=%i\n", f->f_dentry->d_inode->i_ino, (int)*pos, count);

        fh = cflt_file_get(f->f_dentry->d_inode, f);
        if (!fh)
                return RFS_CONTINUE;

        cflt_debug_file(fh);

        if (!atomic_read(&fh->compressed)) {
                printk(KERN_INFO "compflt: file not compressed\n");
                goto end;
        }

        if (!cflt_cmethod) {
                printk(KERN_ERR "compflt: no compression method set\n");
                goto end;
        }

        if (cflt_read(f, fh, *pos, &count, dst)) {
                goto end;
        }

        *op_rv = count;
        *pos += *op_rv;

        cflt_debug_printk("compflt: [pre_read] returning: count=%i pos=%i\n", *op_rv, (int)*pos);

        rv = RFS_STOP;
end:
        cflt_file_put(fh);
        return rv;
}

static enum rfs_retv cflt_f_pre_write(rfs_context context, struct rfs_args *args)
{
        struct file *f = args->args.f_write.file;
        unsigned char *src = (unsigned char *) args->args.f_write.buf;
        size_t count = args->args.f_write.count;
        loff_t *pos = args->args.f_write.pos;
        size_t *op_rv = &args->retv.rv_ssize;
        struct cflt_file *fh;
        enum rfs_retv rv = RFS_CONTINUE;

        cflt_debug_printk("compflt: [pre_write] i=%li | pos=%i len=%i\n", f->f_dentry->d_inode->i_ino, (int)*pos, count);

        fh = cflt_file_get(f->f_dentry->d_inode, f);
        if (!fh)
                return RFS_CONTINUE;

        cflt_debug_file_header(fh);

        if (!atomic_read(&fh->compressed) && fh->size_u != 0) {
                printk(KERN_INFO "compflt: file not compressed\n");
                goto end;
        }

        if (!cflt_cmethod) {
                printk(KERN_ERR "compflt: no compression method set\n");
                goto end;
        }

        if (f->f_flags & O_APPEND) {
                *pos = fh->size_u;
                // we write all over the file
                f->f_flags &= ~O_APPEND;
        }

        if (cflt_write(f, fh, *pos, &count, src)) {
                return RFS_CONTINUE;
        }

        *op_rv = count;
        *pos += *op_rv;

        cflt_debug_file(fh);
        cflt_debug_printk("compflt: [pre_write] returning: count=%i pos=%i\n", *op_rv, (int)*pos);

        rv = RFS_STOP;
end:
        cflt_file_put(fh);
        return rv;
}

// ====================================

rfs_filter compflt;
static struct rfs_path_info path_info = {CFLT_INC_DIR, RFS_PATH_INCLUDE|RFS_PATH_SUBTREE};
static struct rfs_filter_info flt_info = {"compflt", 999, 0};
static struct rfs_op_info ops_info[] = {
        {RFS_REG_FOP_OPEN, cflt_f_pre_open, NULL},
        {RFS_REG_FOP_RELEASE, NULL, cflt_f_post_release},
        {RFS_REG_FOP_LLSEEK, cflt_f_pre_llseek, NULL},
        {RFS_REG_FOP_READ, cflt_f_pre_read, NULL},
        {RFS_REG_FOP_WRITE, cflt_f_pre_write, NULL},
        {RFS_OP_END, NULL, NULL}
};

static int __init compflt_init(void)
{
        int err;

        err = rfs_register_filter(&compflt, &flt_info);
        if (err) {
                printk(KERN_ERR "compflt: registration failed: error %d\n", err);
                goto error;
        }

        err = cflt_privd_cache_init();
        if (err) {
                printk(KERN_ERR "compflt: private data cache initialization failed: error %d\n", err);
                goto error;
        }

        err = cflt_block_cache_init();
        if (err) {
                printk(KERN_ERR "compflt: block cache initialization failed: error %d\n", err);
                goto error;
        }

        err = cflt_file_cache_init();
        if (err) {
                printk(KERN_ERR "compflt: cflt_file cache initialization failed: error %d\n", err);
                goto error;
        }

        err = cflt_sysfs_init();
        if (err) {
                printk(KERN_ERR "compflt: /sys initialization failed: error %d\n", err);
                goto error;
        }

        err = rfs_set_operations(compflt, ops_info);
        if (err) {
                printk(KERN_ERR "compflt: set operations failed: error %d\n", err);
                goto error;
        }

        err = rfs_set_path(compflt, &path_info);
        if (err) {
                printk(KERN_ERR "compflt: include path failed: error %d\n", err);
                goto error;
        }

        err = rfs_activate_filter(compflt);
        if (err) {
                printk(KERN_ERR "compflt: filter activation failed: error %d\n", err);
                goto error;
        }

        printk(KERN_INFO "compflt: loaded version %s\n", version);

        cflt_comp_method_set(in_cmethod);
        if (!cflt_cmethod)
                cflt_comp_method_set(CFLT_DEFAULT_METHOD);
        if (!cflt_cmethod)
                printk(KERN_WARNING "compflt: failed to set initial compress method\n");

        cflt_file_blksize_set(in_blksize);

        return 0;

error:
        if (rfs_unregister_filter(compflt))
                printk(KERN_ERR "compflt: unregistration failed: error %d\n", err);

        return err;
}

static void __exit compflt_exit(void)
{
        int err;

        cflt_sysfs_deinit();

	err = rfs_unregister_filter(compflt);
	if (err)
                printk(KERN_ERR "compflt: unregistration failed: error %d\n", err);

        cflt_privd_cache_deinit();
        cflt_file_cache_deinit();
        cflt_block_cache_deinit();
}

module_init(compflt_init);
module_exit(compflt_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Jan Podrouzek <xpodro01@stud.fit.vutbr.cz>");
MODULE_DESCRIPTION("Compression filter for the RedirFS Framework");
