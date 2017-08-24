# RedirFS
This is an attempt to resurrect and extend the discontinued redirfs project from https://github.com/fhrbata/redirfs

Milestones
 - the redirfs.ko module was made compilable up to 4.12 kernel
 - some fixies to vfsmount usage
 - complete set of file_operations
 - address_space_operations support
 - character devices operations (requires adding /dev path as ```redirfs_add_path``` doesn't cross mount points)
 - debug build without optimization (make modules_debug)
