## Date and Time
Set the timezone to UTC, install and config a network sync tool. Before it used to be `ntp` daemon but with systemd it is `timesyncd`. Config file can be found in `/etc/systemd/timesyncd.conf`. Check date, time and network sync status with `timedatectl`. If timezone is not correct, do `timedatectl list-timezones` to see the names of timezones and set it via `sudo timedatectl set-timezone your_time_zone`. If `timedatectl` show that sync is disabled, enable it via:
```shell
sudo timedatectl set-ntp on
sudo systemctl restart systemd-timesyncd.service
```

## Apt
By default, apt sources list uses http. Convert it to https.
Do `apt-get update && apt-get install apt-transport-https`, then you can replace `http://` in `/etc/apt/sources.list` with `https://`.
After that test it with `apt-get update`.
Configure `sources.list` to include only the security updates and not the feature updates.


## Linux User Account Management
### Existing Users
Set owner of the `$HOME` to you and remove the world-readable bit:
```shell
chown myuser:myuser $HOME
chmod 750 $HOME
```
### adduser.conf Modifications
`adduser` is the recommended way for adding users. Change the default permissions for the users that **will be** created. This has no effect on existing users. Change `DIR_MODE` in `/etc/adduser.conf`:
```
DIR_MODE=0750
```

### login.defs Modifications
In addition to `adduser` command, there is an older (and discouraged) one, `useradd`. Change the `UMASK` value there to prevent accidental bypasses.

`/etc/login.defs` has shadow password suite configuration e.g. max number of days a password can be used, default permissions when a user creates a file (UMASK value) etc. UMASK value notation is like the opposite of file permission notation. If UMASK is 022, then corresponding file permission is 644 and folder permission is 755. Change the values to the following:
```
UMASK 027
PASS_MAX_DAYS 60
PASS_MIN_DAYS 7
```
**Important:** The new UMASK value affects newly created users, so do it before creating any additional user.
**Important:** Note that (from login.defs comments):
> If USERGROUPS_ENAB is set to "yes", that will modify this UMASK default value for private user groups, i. e. the uid is the same as gid, and username is
the same as the primary group name: for these, the user permissions will be used as group permissions, e. g. 022 will become 002.

Since the group and the owner will be the same for home dirs, our goal is not affected and 'other' users will not have any permission.

### Password Quality
Use `pam_pwquality` instead of  the older `pam_cracklib` module.
`sudo apt-get install libpam-pwquality`
Edit `/etc/pam.d/common-password` (Debian/Ubuntu). Note that in other distros(CentOS/RedHat) it can be `/etc/pam.d/system-auth` or `/etc/pam.d/system-auth`, therefore do some research for those before using the following. It is important to leave some fallback modules. Example module names are `pam_unix.so `, `pam_deny.so` etc. Find the first line that a module config is written e.g. `password	[success=1 default=ignore]	pam_unix.so obscure sha512`. Add the following before that line. If the line already contains `pam_pwquality.so` as the module, edit the line instead of adding a new one.

```
password    requisite      pam_pwquality.so retry=4 minlen=20 minclass=4 maxrepeat=3 maxsequence=4 ucredit=-2 lcredit=-2 dcredit=-2 ocredit=-1 difok=4 gecoscheck=1 reject_username enforce_for_root
```
Add the following to the end of `pam_unix.so` module line:
`use_authtok try_first_pass remember=5` so that it uses the password passed from `pam_pwquality` instead of prompting a new one. Note: `obscure sha512` should also be there, if not add it.

Not clear if it is needed to set `/etc/security/pwquality.conf`.

Password expiration config to be added.

### Create a non-root user
Log-in to the server via ssh.
```shell
sudo apt-get update
sudo apt-get install sudo  # if not installed by default
adduser example_user
adduser example_user sudo  # add to sudoers (group name diff for CentOS!)
exit  # disconnect from server
ssh example_user@xxx.x.xx.xx  # log back in as limited user
```

## Create High Entropy
**Important:** There are many online tutorials/answers to increase entropy in headless environments. Many are not reliable in cryptographic terms, make sure that the source is trusted and validate the method from different sources. Arch wiki is an excellent source for this topic.

Needed for any sort of encryption, SSL/TLS... In virtualized headless environments, good-quality high entropy is problematic. `haveged` and/or `rng-tools` can be used to create entropy in headless environments. However, `haveged` should be used very carefully as it is not suitable for virtualized environments. Arch wiki recommends that:
> Unless you have a specific reason to not trust any hardware random number generator on your system, you should try to use them with the rng-tools first and if it turns out not to be enough (or if you do not have a hardware random number generator available), then use Haveged.

So try `rng-tools` first. Before doing anything, check available entropy to get an idea: `cat /proc/sys/kernel/random/entropy_avail`. At least in Debian Buster (10), note that there are three packages with names `rng-tools`, `rng-tools-debian` and `rng-tools5`. The upstream version is `rng-tools5`, I prefer installing that version.
Then:
```shell
# In a None-Debian OS, you might need to replace rng-tools5 with rng-tools
sudo apt-get install rng-tools5
# might be called rng-tools.service depending on distro/package
# e.g. rng-tools-debian
sudo systemctl start rngd.service
sudo systemctl enable rngd.service
# Check status to see if rng-tools is complaining about sth
sudo systemctl status rngd.service
```
Check if `rngd` has a source of entropy: `sudo rngd -v`. If the cluster does not have any external TPM chip, it is normal to see `Unable to open file: /dev/tpm0`. If you see `DRNG` entropy source, it is an Intel ‘hardware approach to high-quality, high-performance entropy and random number generation’ using the RDRAND processor instruction, which is good. Check if your processor has RDRAND instruction by `cat /proc/cpuinfo | grep rdrand`. RDRAND presence can also be checked by `sudo dmesg | grep -i crng`. If the output has something like `random: crng done (trusting CPU's manufacturer)`, then it is present. Another type of random number generator that you might see is VirtIO RNG, which is exposed by QEMU. To check VirtIO RNG, issue `cat /sys/devices/virtual/misc/hw_random/rng_available`, it will output something like `virtio_rng`. This is usually not applicable to cloud servers, but sometimes (especially in modern laptops and desktops) you have other hardware-backed RNGs, which are called Trusted Platform Modules (TPMs). You can check if one exists in your system via `cat /sys/devices/virtual/misc/hw_random/rng_available`, the output will be like `tpm-rng-0` or `tpm-rng`. Another indication of HWRNG is the presence of `/dev/hwrng` and/or `/dev/tpm0`. If everything is fine and you have at least one hardware RNG source (i.e. RDRAND, VirtIO RNG, TPM...) move on.

Check if it is working correctly. The first command should give instantaneous output when `rng-tools` working correctly. Without it, outputted `dd` speed would be extremely low (<10KB/s). The second command executes a test of 1000 passes, you should get a maximum of 1-2 failures.
```
dd if=/dev/random of=/dev/null bs=1024 count=1 iflag=fullblock
rngtest -c 1000 </dev/random
```

**Note**: If you have access to the BIOS settings of the platform, you might want to check if TPM or the other RNG generation-related settings are disabled.
