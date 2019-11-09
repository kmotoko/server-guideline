## Disable Unused Filesystems
Create `/etc/modprobe.d/dev-sec.conf` file with the following contents:
```
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
```
Do not disable `vfat` as it is necessary for EFI.
Do not disable `squashfs` as it is necessary for `snap`.

### InSpec Checks
Ignore inspec warning about `vfat` as it is used for EFI.

## Secure Shared Memory
For the first field in `fstab`, which is the device/filesystem, quoting from the `man page`:
"For filesystems with no storage, any string can be used, and  will  show  up  in df  output, for example. Typical usage is `proc' for procfs; `mem', `none', or `tmpfs' for tmpfs. ".
Edit `/etc/fstab` and add the following to the end to mount in read-only mode:
```
# Secure shared memory
none     /run/shm     tmpfs     defaults,ro     0     0
```
or if it causes problems, you can mount it read/write but without a permission to execute:
```
# Secure shared memory
none     /run/shm     tmpfs     rw,noexec,nosuid,nodev     0     0
```
As the `man page` says above, you could also use `tmpfs` instead of `none`.
Remount it to check:
`sudo mount -o remount /run/shm`
