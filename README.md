## Table of Contents
+ [Work in Progress](#work-in-progress)
+ [Create a non-root user](#create-a-non-root-user)
+ [SSH](#ssh)
    + [SSH keys](#ssh-keys)
    + [SSH daemon config](#ssh-daemon-config)
    + [SSH client config](#ssh-client-config)
+ [Firewall](#firewall)
+ [Prevent IP Spoofing](#prevent-ip-spoofing)
+ [Sysctl Config](#sysctl-config)
+ [Mandatory Access Control](#mandatory-access-control)
+ [Linux User Account Management](#linux-user-account-management)
+ [Secure Shared Memory](#secure-shared-memory)
+ [Date and Time](#date-and-time)
+ [DNS Security](#dns-security)
    + [DNSSEC](#dnssec)
    + [DKIM, SPF and DMARC records](#dkim,-spf-and-dmarc-records)
+ [SSL/TLS security](#ssl/tls-security)
+ [Rootkit](#rootkit)
    + [rkhunter](#rkhunter)
+ [MySQL](#mysql)
    + [Initial Setup](#initial-setup)
    + [General and Security Config](#general-and-security-config)
    + [Check the Config and Other Settings](#check-the-config-and-other-settings)
    + [Last Touch](#last-touch)

## Work in Progress
+ In SSH daemon config: `AllowStreamLocalForwarding no  # it does not exist in the man page`
+ SSH: 2fa implementation
+ IP spoofing protection: check nsswitch config (could not find corresponding key at this time).
+ Sysctl config: `kernel.sysrq` should it be disabled.
+ Sysctl config: Fine tune mentioned variables.
+ Date and time: Check where the default NTP server list is.
+ DMARC: Check how to implement a DMARC record.
+ rkhunter: Re-check docs
+ Mysql: Better error handling and character encoding stuff
+ Kernel: Auto restart at kernel panic
+ Updates: Unattended upgrades for security patches (or should it be unattended???).
+ iptables: Rate limiting and cloudflare dilemma, since they do not forward client IPs.
+ iptables: Only allow connections from cloudflare.
+ Nginx and Gunicorn setup and config.
+ Logwatch and tiger, lynis etc... or any other HIDS.
+ Zabbix: local_infile permission and mysqld config --> Is this config necessary?
+ Zabbix: subdomain, ssl, lets encrypt docs.
+ Zabbix: Zabbix agent in the client machine.
+ Add references.

## Create a non-root user
Log-in to the server via ssh.
```shell
sudo apt-get update
sudo apt-get install sudo  # if not installed by default
adduser example_user
adduser example_user sudo  # add to sudoers
exit  # disconnect from server
ssh example_user@xxx.x.xx.xx # log back in as limited user
```

## SSH
### SSH keys
In your **local computer**:
```shell
ssh-keygen -t ed25519 -o -a 500 -C "put your comment" -f $HOME/.ssh/id_ed25519_SUFFIX
# ATTENTION: Be sure to upload your public key not the private.
ssh-copy-id -i $HOME/.ssh/id_ed25519_SUFFIX.pub {username}@{remotePublicIPAddress}
```

Set file permissions:
```shell
sudo chmod 700 ~/.ssh
sudo chmod 600 ~/.ssh/authorized_keys
```

Log out and log back in.
Note end-of-validation of the certificates, so that you can renew it before expiration.
### SSH daemon config
In the server, create a group to hold users that have ssh access:
```
sudo groupadd ssh-user
sudo usermod -a -G ssh-user <username>
```
In the server:, edit `/etc/ssh/sshd_config` to include the following
```
IgnoreRhosts yes
AddressFamily inet  # listen only on IPV4. Could be "AddressFamily inet6" for ipv6. This only affects sshd.
LogLevel INFO
StrictModes yes
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
HostbasedAuthentication no
HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa
# Idle client timeout
ClientAliveInterval 900
# Number of times to send the encrypted alive message before disconnecting clients if no response are received
ClientAliveCountMax 0
AllowGroups ssh-user
# Disable SSH version 1
Protocol 2
Port 2112
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
MaxSessions 8
MaxStartups 8
MaxAuthTries 8
UseDNS No
X11Forwarding No  # opens a channel from the server back to the client and the server can send X11 commands back to the client
# Port-forwarding (SSH tunneling)-related
# These are important security concerns
AllowTcpForwarding no
AllowStreamLocalForwarding no  # Check this back, it does not exist in the man page
GatewayPorts no
PermitTunnel no
```

Then restart the sshd:
```shell
sudo systemctl status sshd
sudo systemctl enable sshd
sudo systemctl restart sshd
```

### SSH client config
```
Host *
    Port 2112
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    UseRoaming no
    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
    PubkeyAuthentication yes
    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
```

To test: `sshd -t`

Sources:

<https://www.booleanworld.com/set-ssh-keys-linux-unix-server/>

<https://securit.se/2012/01/english-configure-ssh-high-security/>

## Firewall
```shell
sudo apt-get update
sudo apt-get install iptables iptables-persistent
```
Check if any default rules exist:
```shell
sudo iptables -L -nv  # list numerically and in verbose mode
sudo ip6tables -L -nv
```
Below is an through example, keep the necessary lines for the server type of choice.
**Note**: MySQL listens for 3306, PostgreSQL listens for 5432.
```shell
# Block NULL packages
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
# XMAS packet
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
# Drop all new TCP conn that are not SYN (SYN flood)
iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
# Drop INVALID packages
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
# Rate limit new tcp conn (SYN flood)
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit <LIMIT_1>/second --limit-burst <LIMIT_2> -j ACCEPT
# SMURF attack. This is not necessary if blocking all icmp
sudo iptables -A INPUT -p icmp -m limit --limit <LIMIT_3>/second --limit-burst <LIMIT_4> -j ACCEPT

sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -p tcp -s <SOURCE_IP> --dport <SSH_PORT> -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -i <INTERFACE> -p tcp -s <SOURCE_IP> --dport 3306 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport <SSH_PORT> -m conntrack --ctstate ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -o <INTERFACE> -p tcp --sport 3306 -m conntrack --ctstate ESTABLISHED -j ACCEPT

sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
```

Note on loadbalancers (Linode)
```
# Allow incoming Longview connections from longview.linode.com
-A INPUT -s 96.126.119.66 -m state --state NEW -j ACCEPT

# Allow incoming NodeBalancer connections
-A INPUT -s 192.168.255.0/24 -m state --state NEW -j ACCEPT
```
Also check:
<http://www.robertopasini.com/index.php/2-uncategorised/650-linux-iptables-block-common-attacks>
<https://support.hostway.com/hc/en-us/articles/360002236980-How-To-Set-Up-a-Basic-Iptables-Firewall-on-Centos-6>
<https://www.cyberciti.biz/tips/linux-iptables-10-how-to-block-common-attack.html>
<https://linoxide.com/firewall/block-common-attacks-iptables/>

If your firewall's built-in policy function is set to "drop" and your firewall rules are ever flushed (reset), or if certain matching rules are removed, your services will instantly become inaccessible remotely. This is often a good idea when setting policy for non-critical services so that your server is not exposed to malicious traffic if the rules are removed.

## Prevent IP Spoofing
`/etc/host.conf` looks like this:
```
# The "order" line is only used by old versions of the glibc library.
​order hosts,bind
​multi on
```
Change it to:
```
# The "order" line is only used by old versions of the glibc library.
​order bind,hosts
​nospoof on
```
Also check IP spoofing prevention in IPtables and networking layer.
Also remember that `/etc/nsswitch.conf` takes precendence over `host.conf` if `glibc > 2.4` for controlling the `order` of host lookups.

## Sysctl Config
Change the kernel parameters at runtime. **Note:** From version 207 and 21x, systemd only applies settings from `/etc/sysctl.d/*.conf`. If you had customized `/etc/sysctl.conf`, you need to rename it as `/etc/sysctl.d/99-sysctl.conf`. If you had e.g. `/etc/sysctl.d/foo`, you need to rename it to `/etc/sysctl.d/foo.conf`.
Edit the appropriate file to include the following:
```
###
### GENERAL SYSTEM SECURITY OPTIONS ###
###

# Controls the System Request debugging functionality of the kernel
# Check this value
#kernel.sysrq = 0

# Enable ExecShield protection
kernel.randomize_va_space = 2

# Restrict core dumps
fs.suid_dumpable = 0

# Hide exposed kernel pointers
kernel.kptr_restrict = 1

###
### Deprecated/Not-in-use keys for security
###

# The contents of /proc/<pid>/maps and smaps files are only visible to
# readers that are allowed to ptrace() the process
# kernel.maps_protect = 1

# Enable ExecShield protection
# kernel.exec-shield = 1

###
### IMPROVE SYSTEM MEMORY MANAGEMENT ###
###

# Do less swapping
# If RAM is 1GB, dirty_ratio=10 is a sane value (meaning 1GB*0.1=100MB)
# For higher RAMs, it can be a bit lower. 100-500MB as a result is a sane value.
vm.swappiness = 30
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5

# 50% overcommitment of available memory
vm.overcommit_ratio = 50
vm.overcommit_memory = 0

# Set maximum amount of memory allocated to shm to 512MB
kernel.shmmax = 536870912
kernel.shmall = 536870912

# Keep at least 128MB of free RAM space available
vm.min_free_kbytes = 131072

###
### GENERAL NETWORK SECURITY OPTIONS ###
###

#Prevent SYN attack, enable SYNcookies (they will kick-in when the max_syn_backlog reached)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Disables packet forwarding
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

# Disables IP source routing
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable IP spoofing protection, turn on source route verification
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP Redirect Acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Enable Log Spoofed Packets, Source Routed Packets, Redirect Packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Decrease the time default value for tcp_fin_timeout connection
net.ipv4.tcp_fin_timeout = 15

# Decrease the time default value for connections to keep alive
net.ipv4.tcp_keepalive_time = 450
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_keepalive_intvl = 15

# Don't relay bootp
net.ipv4.conf.all.bootp_relay = 0

# Don't proxy arp for anyone
net.ipv4.conf.all.proxy_arp = 0

# Turn on the tcp_timestamps, accurate timestamp make TCP congestion control algorithms work better
net.ipv4.tcp_timestamps = 1

# Don't ignore directed pings
# Useful for monitoring tools etc.
# Might want to limit requests/s in iptables
net.ipv4.icmp_echo_ignore_all = 0

# Enable ignoring broadcasts request
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable bad error message Protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Allowed local port range
net.ipv4.ip_local_port_range = 16384 65535

# Enable a fix for RFC1337 - time-wait assassination hazards in TCP
net.ipv4.tcp_rfc1337 = 1

# Do not auto-configure IPv6
net.ipv6.conf.all.autoconf=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.eth0.autoconf=0
net.ipv6.conf.eth0.accept_ra=0

###
### TUNING NETWORK PERFORMANCE ###
###

# Use BBR TCP congestion control and set tcp_notsent_lowat to 16384 to ensure HTTP/2 prioritization works optimally
# Do a 'modprobe tcp_bbr' first (kernel > 4.9)
# Fall-back to htcp if bbr is unavailable (older kernels)
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384

# For servers with tcp-heavy workloads, enable 'fq' queue management scheduler (kernel > 3.12)
# This also relates to TCP BBR congestion control, be careful if changing from fq
net.core.default_qdisc = fq

# Turn on the tcp_window_scaling
net.ipv4.tcp_window_scaling = 1

# try to reuse time-wait connections, but don't recycle them (recycle can break clients behind NAT)
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1

# Limit the maximum memory used to reassemble IP fragments (CVE-2018-5391)
net.ipv4.ipfrag_low_thresh = 196608
net.ipv6.ip6frag_low_thresh = 196608
net.ipv4.ipfrag_high_thresh = 262144
net.ipv6.ip6frag_high_thresh = 262144

# How many times to retry killing an alive TCP connection
net.ipv4.tcp_retries2 = 15
net.ipv4.tcp_retries1 = 3

# Avoid falling back to slow start after a connection goes idle
# keeps our cwnd large with the keep alive connections (kernel > 3.6)
net.ipv4.tcp_slow_start_after_idle = 0

# This will enusre that immediatly subsequent connections use the new values
# ALWAYS COMES LAST
net.ipv4.route.flush = 1
net.ipv6.route.flush = 1
```
Use `sudo sysctl --system` to apply settings. **Important:** Check and make sure if the new config sticks after reboot (`sudo sysctl --all`).

**Note**: `kernel.exec-shield` and `kernel.maps_protect` keys are extremely important. However, `kernel.maps_protect` became non-optional in kernel 2.6.27 and `kernel.exec-shield` exists in RedHat/CentOS, currently not in Debain 9 at least. But you can still do `kernel.randomize_va_space = 2` for Debian/Ubuntu. Do not change `vm.mmap_min_addr` without extreme care as it has security implications, as long as you are using a fairly modern kernel (includes Debian 9, Ubuntu 16.04 and newer) the default should be fine. Also, `fs.file-max` should be fine with the defaults.

**Variable parameters:**Some of the parameters can change depending on the server specs (especially RAM). You need to adjust those according to the actual server. It would be a good idea to check the default parameter before changing those, as for some parameters the linux kernel adjust them automatically depending on the available resources.

**Load the tcp_bbr module:** This is used in the sysctl.conf above. You can do `sudo modprobe tcp_bbr`, and the to stick it across reboots, add `/etc/modules-load.d/tcp_bbr.conf` file and just add the following line in it `tcp_bbr`. This is systemd-modules-load.service and it reads files from the above directory which contain kernel modules to load during boot in a static list. Then reboot and check if it is loaded by `sudo lsmod | grep tcp`. Actually, modern kernels loads modules as needed, but just to be safe...


```
###
### TUNING NETWORK PERFORMANCE EXTRA OPTIONS###
###

# Increase number of incoming connections
# SOMAXCONN provides an upper limit on the value of the backlog
net.core.somaxconn = 24576

# Increase number of incoming connections backlog
net.core.netdev_max_backlog = 12288
net.core.dev_weight = 64

# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
net.ipv4.tcp_max_tw_buckets = 1440000

# Limit number of orphans, each orphan can eat up to (max wmem) of unswappable memory
# This amount should change with RAM amount
# For 8GB, 32K should be fine
net.ipv4.tcp_max_orphans = 16384
net.ipv4.tcp_orphan_retries = 2
```

The following options were in  Network Performance, but removed since it is not that wise to make a lot of customizations which can be error-prone in the long run. **Use the memory-related options with extreme care, since tweaking them might need considerably higher memory.**
```
# Increase the read-buffer space allocatable
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.udp_rmem_min = 16384
net.core.rmem_default = 262144
net.core.rmem_max = 16777216

# Increase the write-buffer-space allocatable
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_wmem_min = 16384
net.core.wmem_default = 262144
net.core.wmem_max = 16777216

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 65535

# don't cache ssthresh from previous connection
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1

# Increase size of RPC datagram queue length
net.unix.max_dgram_qlen = 50

# Don't allow the arp table to become bigger than this
net.ipv4.neigh.default.gc_thresh3 = 2048

# Tell the gc when to become aggressive with arp table cleaning.
# Adjust this based on size of the LAN. 1024 is suitable for most /24 networks
net.ipv4.neigh.default.gc_thresh2 = 1024

# Adjust where the gc will leave arp table alone - set to 32.
net.ipv4.neigh.default.gc_thresh1 = 32

# Adjust to arp table gc to clean-up more often
net.ipv4.neigh.default.gc_interval = 30

# Increase TCP queue length
net.ipv4.neigh.default.proxy_qlen = 96
net.ipv4.neigh.default.unres_qlen = 6

# Enable Explicit Congestion Notification (RFC 3168), disable it if it doesn't work for you
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_reordering = 3

# Allow the TCP fastopen flag to be used, beware some firewalls do not like TFO! (kernel > 3.7)
net.ipv4.tcp_fastopen = 3
```

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

## Linux User Account Management
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

## Date and Time
Set the timezone to UTC, install and config a network sync tool. Before it used to be `ntp` daemon but with systemd it is `timesyncd`. Config file can be found in `/etc/systemd/timesyncd.conf`. Check date, time and network sync status with `timedatectl`. If timezone is not correct, do `timedatectl list-timezones` to see the names of timezones and set it via `sudo timedatectl set-timezone your_time_zone`.

## DNS Security
### DNSSEC
From ICANN:
> DNSSEC strengthens authentication in DNS using digital signatures based on public key cryptography. With DNSSEC, it's not DNS queries and responses themselves that are cryptographically signed, but rather DNS data itself is signed by the owner of the data. Every DNS zone has a public/private key pair. The zone owner uses the zone's private key to sign DNS data in the zone and generate digital signatures over that data. As the name "private key" implies, this key material is kept secret by the zone owner. The zone's public key, however, is published in the zone itself for anyone to retrieve. Any recursive resolver that looks up data in the zone also retrieves the zone's public key, which it uses to validate the authenticity of the DNS data. The resolver confirms that the digital signature over the DNS data it retrieved is valid. If so, the DNS data is legitimate and is returned to the user. If the signature does not validate, the resolver assumes an attack, discards the data, and returns an error to the user. DNSSEC adds two important features to the DNS protocol:
> 1) Data origin authentication allows a resolver to cryptographically verify that the data it received actually came from the zone where it believes the data originated.
> 2) Data integrity protection allows the resolver to know that the data hasn't been modified in transit since it was originally signed by the zone owner with the zone's private key.

From Google:
> Domain Name System Security Extensions (DNSSEC) help protect your domain from domain name server (DNS) threats, like cache poison attacks and DNS spoofing.

**Important:** Do not change your name servers while DNSSEC is enabled. If you do, your domain may not resolve.

Enable DNSSEC from your domain registrar.
Then, to verify, use the tools following: [Verisign DNSSEC Debugger](https://dnssec-debugger.verisignlabs.com/), [ViewDNS](https://viewdns.info/).

### DKIM, SPF and DMARC records
All three of them help to secure your mail exchange, also fighting spam. These can be set in the DNS settings of the registrar. Check the record keys with the external mail provider. [Yandex SPF](https://yandex.com/support/domain/set-mail/spf.html), [Yandex DKIM](https://yandex.com/support/domain/set-mail/dkim.html).
**Important:** Key length is important for the DKIM record. Regularly check if your mail external provider updates the key length so that you can set the new public key in the DNS records.
Tools to check if you properly implemented: [DKIM checker](https://www.dmarcanalyzer.com/dkim/dkim-check/), [SPF checker](https://www.dmarcanalyzer.com/spf/checker/), [DMARC checker](https://www.dmarcanalyzer.com/dmarc/dmarc-record-check/)

## SSL/TLS security
Regularly check [Mozilla Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS) for updates and compatibility across devices and browsers about TLS. As of 2019, It is not wise to use TLS <= v1.1 for high security sites.
Check [SSLlabs TLS deployment best practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices).
Mozilla has a nice tool to generate TLS config file for web servers: [Mozilla SSL/TLS config generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/). Tweak the file as needed. One important factor is the OpenSSL version used in the server, as it would be a limiting factor on the ciphers and TLS versions supported.
Use [Qualys SSL Server Test](https://www.ssllabs.com/ssltest/) to see if everything properly implemented.

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

## MySQL
### Initial Setup
``` shell
sudo apt update
sudo apt install mysql-server
sudo mysql_secure_installation  # safer defaults
# mysql_install_db (below) might not be necessary depending on the distro
# In that case, you should get a "File exists" error or alike
sudo mysql_install_db  # or in later MySQL versions: sudo mysqld --initialize
```
### General and Security Config
+ Use `mysql_secure_installation`.
+ Check the reading order of configfiles from `mysqld --help`.
+ Set `default_password_lifetime=0` in config for the web app accounts so that their passwords never expire. Instead change passwords periodically yourself. Per user expiry can be set by:
```
ALTER USER 'username'@'mysql_client_IP' PASSWORD EXPIRE INTERVAL 0 DAY;
FLUSH PRIVILEGES;  # reload the stored user information
```
Remember that even if you edit the config file, if you do not restart `mysqld`, it will not take effect for the users created in subsequent steps. Thus quickly edit `/etc/mysql/my.cnf` to include the following:
```
[mysqld]
default_password_lifetime=0
```
Restart by `sudo systemctl restart mysqld`

+ MySQL Root account should never be used to connect a web app/monitoring server to a MySQL server. Create other accounts with restrictive privileges for these purposes. **If using Django, create two users: one for the daily usage with very restrictive permissions, the other for migrations.**. In general, use a different user for each web applications connecting to the database. If one application gets compromised and the attacker has access to the database, they will not be able to access other databases.
```
CREATE USER 'remote_user'@'mysql_client_IP' IDENTIFIED BY 'password' REQUIRE SSL;
FLUSH PRIVILEGES;  # reload the stored user information
```
Most of the time, a user needs SELECT, INSERT, UPDATE, DELETE permissions. However, during Django migrations, it might need CREATE, ALTER, DROP etc. So only allow necessary permissions from the web app.
```
GRANT SELECT, INSERT, UPDATE, DELETE ON db_name.* TO 'sqluser_name_1'@'mysql_client_IP';
FLUSH PRIVILEGES;
GRANT SELECT, INSERT, UPDATE, DELETE, ALTER, CREATE, CREATE TEMPORARY TABLES, DROP, EVENT, EXECUTE, INDEX, LOCK TABLES, REFERENCES, TRIGGER ON db_name.* TO 'sqluser_name_2'@'mysql_client_IP';
FLUSH PRIVILEGES;
EXIT;
```
+ mysqld should never be run as linux root user. Check config files in mysql `/etc/my.cnf`, `/etc/mysql/conf.d/`, `/etc/mysql/my.cnf` and `/etc/mysql/mysql.conf.d/`. mysqld uses only the first `--user` option. So if the first config file that is being read has this option, **subsequent config files won't be able to override this setting.** Assuming `/etc/my.cnf` is the first existing config being read, include:
```
[mysqld]
user=mysql
```
+ Prevent local filesystem access of the mysql user, Disable symbolic links to tables, Enforce encrypted connections, Specify bind address by editing `/etc/mysql/my.cnf` to include (place after includedirs to prevent being overridden):

```
[mysqld]
bind-address=IPv4_or_IPv6_address  # default is 127.0.0.1
local_infile=0  # prevent reading files on the local filesystem even if the user has FILE privilege
# Require clients to connect either using SSL
# or through a local socket file
require_secure_transport=ON
symbolic-links=0
tls_version=TLSv1.2
```
+ Clear and disable the command history in `~/.mysql_history` since it might contain sensitive info:
```
rm -f $HOME/.mysql_history
ln -s /dev/null $HOME/.mysql_history
```
+ Close all the mysql cmd prompts and restart: `sudo systemctl restart mysqld`.

### Check the Config and Other Settings
+ Make sure apparmor profile is loaded by `sudo apparmor_status`.
+ Check user accounts (anonymous user etc.), the SSL variables, current connection status (encrypted or not), and user privileges. Login via `mysql -u root -p`
```
SELECT User, Host, Authentication_String FROM mysql.user;
SHOW VARIABLES LIKE '%ssl%';
STATUS;
SHOW GRANTS FOR 'demouser'@'localhost';
```
+ Try to connect insecurely, the access should be denied:
```
mysql -u remote_user -p -h mysql_server_IP --ssl-mode=disabled
```
+ Check the ports and addresses for mysql: `netstat –ntulp | grep mysql`
+ Run a few sql command and check the history file.
+ Check the file permissions on config files and `/usr/local/mysql/data`, they should not be world-writable.

### Last Touch
Change the mysql `root` account name.
```
UPDATE mysql.user SET user=<newrootname> WHERE user='root';
FLUSH PRIVILEGES;
```

## Determine and disable running services
Check network services: `sudo ss -atpu`. Check system services and daemons: `sudo systemctl list-units --all`

## Zabbix
This config assumes that the MySQL database for Zabbix is on the same machine. This is the simplest solution as this server is to be used only for monitoring. Zabbix server requires LAMP stack (Linux, Apache, MySQL, PHP). First, install and config LAMP on the machine that will monitor.

### Install and Config LAMP stack
First do the security config: SSH, iptables, sysctl etc.

```shell
sudo apt-get update
sudo apt-get install apache2 mysql-server php libapache2-mod-php php-mysql
```
Edit `/etc/apache2/mods-enabled/dir.conf`, move `index.php` to the first position after `DirectoryIndex` so that Apache will first look for PHP files.

Restart and check:
```shell
sudo systemctl restart apache2
sudo systemctl status apache2
```


### Zabbix Server
On the machine that will monitor:
```shell
sudo apt update
sudo apt install zabbix-server-mysql zabbix-frontend-php
```
Configure MySQL before going any further. Since MySQL is on the same machine, omit the MySQL configs that changes settings related to `SSL/TLS` since it will be local. Also, do not forget to change settings according to `localhost` from `REMOTE_IP`, and you may leave the `Port` with the default config.
Create a new database for Zabbix, create a Zabbix user for MySQL, set up the schema and import the data into the Zabbix database:
```
mysql -uroot -p
mysql> CREATE DATABASE zabbix CHARACTER SET utf8 collate utf8_bin;
mysql> CREATE USER 'zabbix'@'localhost' IDENTIFIED BY 'your_zabbix_mysql_password';
mysql> FLUSH PRIVILEGES;
mysql> GRANT SELECT, INSERT, UPDATE, DELETE, ALTER, CREATE, CREATE TEMPORARY TABLES, DROP, EVENT, EXECUTE, INDEX, LOCK TABLES, REFERENCES, TRIGGER ON zabbix.* TO 'zabbix'@'localhost';
mysql> FLUSH PRIVILEGES;
mysql> EXIT;
zcat /usr/share/doc/zabbix-server-mysql/create.sql.gz | mysql -uzabbix -p zabbix
```
Edit `/etc/zabbix/zabbix_server.conf` and type `DBPassword` and `DBName`. `DBHost` already default to `localhost`.
Edit `sudo nano /etc/zabbix/apache.conf` and enter correct `php_value date.timezone`.
Restart, check and enable at startup:
```shell
sudo systemctl restart apache2
sudo systemctl start zabbix-server
sudo systemctl status zabbix-server
sudo systemctl enable zabbix-server
```

The rest is GUI config, go to `http://zabbix_server_domain_or_IP/zabbix/`. Check <https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-zabbix-to-securely-monitor-remote-servers-on-ubuntu-18-04> if you have questions for GUI config.
