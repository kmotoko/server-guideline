## Mandatory Access Control
Do not use 2 Linux Security module at the same time, i.e. SELinux and Apparmor. CentOS comes with SELinux by default. In Debian/Ubuntu, it is better to go with Apparmor.

`sudo apt-get install apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra`

Below needed for Debian < 10 but should not for Ubuntu.
```shell
sudo mkdir -p /etc/default/grub.d
echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT apparmor=1 security=apparmor"' | sudo tee /etc/default/grub.d/apparmor.cfg
sudo update-grub
```
then reboot.
Check apparmor status by `sudo aa-status` or `sudo apparmor_status`.
