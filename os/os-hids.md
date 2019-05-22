## Rootkit
### rkhunter
```shell
sudo apt-get install rkhunter
sudo rkhunter --update  # update data files
sudo rkhunter --propupd  # set baseline
sudo rkhunter -c --skip-keypress --report-warnings-only --enable all --disable none  # run
```
Configure `rkhunter` in `/etc/rkhunter.conf`
```
UPDATE_MIRRORS=1
MIRRORS_MODE=0
WEB_CMD="wget --read-timeout=180"
MAIL-ON-WARNING="your_user@domain.com"
MAIL_CMD=mail -s "[rkhunter] Warnings found for ${HOST_NAME}"
SCRIPTWHITELIST="/usr/sbin/adduser"
SCRIPTWHITELIST="/usr/bin/ldd"
SCRIPTWHITELIST="/usr/bin/unhide.rb"
SCRIPTWHITELIST="/bin/which"
ALLOWHIDDENDIR="/dev/.udev"
ALLOWHIDDENDIR="/dev/.static"
ALLOWHIDDENDIR="/dev/.initramfs"
ALLOWHIDDENFILE="/dev/.blkid.tab"
ALLOWHIDDENFILE="/dev/.blkid.tab.old"
ALLOWDEVFILE="/dev/.udev/rules.d/root.rules"
```
Run `sudo rkhunter --config-check`. If everything OK, run `sudo rkhunter -c --skip-keypress --report-warnings-only --enable all --disable none`. Check the warnings. Update the database: `sudo rkhunter --propupd`.

Edit `/etc/default/rkhunter.conf`:
```
# Ensures that rkhunter --propupd is run automatically after software updates
APT_AUTOGEN="true"
```
Add `rkhunter` to crontab. First check if there is any crontab for root by `sudo crontab -l`. Then, `sudo crontab -e`. **Important:** Since the configuration auto-runs `--propupd` after apt upgrades, it is important to check apt packages just before the upgrade process. So check also apt upgrade timings.
At the end of the file (crontab), add:
```
00 04 * * * /usr/bin/rkhunter --update --nocolors --skip-keypress
10 04 * * * /usr/bin/rkhunter --cronjob --report-warnings-only
```

which means it will run at 4:00AM.
