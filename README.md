# RedirFS
This is an attempt to resurrect and extend the discontinued redirfs project from https://github.com/fhrbata/redirfs

What's new:
 - the ```redirfs.ko``` module was made compilable up to 4.14 kernel
 - some fixies to ```vfsmount``` usage
 - complete set of ```file_operations```
 - ```address_space_operations``` support
 - shared object for hooked operations instead of a per-object structure
 - new object model to manage reference counting
 - character devices operations (requires adding /dev path as ```redirfs_add_path``` doesn't cross mount points)
 - debug build without optimization (make modules_debug)
