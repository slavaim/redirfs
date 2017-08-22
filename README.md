# RedirFS
This is an attempt to resurrect and extend the discontinued redirfs project from https://github.com/fhrbata/redirfs

Milestones
 - the redirfs module was made compilable up to 4.12 kernel. Some hooks are missing ( like rename2 ).
 - some fixies to vfsmount usage
 - read and read_iter hooks were added
 - address_space_operations hooks support was added
 - character devices hooks (requires adding /dev path as ```redirfs_add_path``` doesn't cross mount points)
 - debug build without optimization (make modules_debug)
