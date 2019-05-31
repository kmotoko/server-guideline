## Logwatch
Install via: `sudo apt-get install logwatch`
If does not exist, create: `sudo mkdir /var/cache/logwatch`
If there is no config file in `/etc/logwatch/conf/`: `sudo cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/`
**Important:** Never ever edit conf files in `/usr/share/`. These are default configs and will be overridden by updates. Also valid for other packages.
```
LogDir = /var/log
TmpDir = /var/cache/logwatch
Output = mail
MailTo = sysadmin@mydomain.com
MailFrom = sysadmin@mydomain.com
Format = html
Range = Yesterday
# Process even if a log is archived
Archive = yes
Detail = Medium
Service = All

# Separate entries by hostname
SplitHosts = yes
HostLimit = no
# Send a single e-mail for everything
MultiEmail = no
```
List of services logwatch covers: `ls -l /usr/share/logwatch/scripts/services`
You can specify multiple `MailTo` with spaces in between the addresses.
`Archive = yes` is important as logwatch can miss logs that are rotated.
