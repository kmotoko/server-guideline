## Table of Contents
+ [Work in Progress](#work-in-progress)
+ [Create a non-root user](#create-a-non-root-user)
+ [Create High Entropy](#create-high-entropy)
+ [Network Config](#network-config)
+ [SSH](#ssh)
    + [SSH keys](#ssh-keys)
    + [SSH daemon config](#ssh-daemon-config)
    + [SSH client config](#ssh-client-config)
+ [Firewall](#firewall)
+ [Prevent IP Spoofing](#prevent-ip-spoofing)
+ [Disable Unused Filesystems](#disable-unused-filesystems)
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
+ [Nginx](#nginx)
+ [MySQL](#mysql)
    + [Initial Setup](#initial-setup)
    + [General and Security Config](#general-and-security-config)
    + [Check the Config and Other Settings](#check-the-config-and-other-settings)
    + [Last Touch](#last-touch)
+ [Zabbix](#Zabbix)
  + [Install and Config LAMP Stack](#install-and-config-lamp-stack)
  + [Zabbix Server](#zabbix-server)
  + [Zabbix Agent](#zabbix-agent)
+ [Useful Commands](#useful-commands)


## Work in Progress
+ In SSH daemon config: `AllowStreamLocalForwarding no  # it does not exist in the man page`
+ SSH: 2fa implementation
+ IP spoofing protection: check nsswitch config (could not find corresponding key at this time).
+ Sysctl config: Fine tune mentioned variables.
+ Date and time: Check where the default NTP server list is.
+ DMARC: Check how to implement a DMARC record.
+ rkhunter: Re-check docs
+ Updates: Unattended upgrades for security patches (or should it be unattended???).
+ iptables: Rate limiting and cloudflare dilemma, since they do not forward client IPs.
+ iptables: Only allow http/https connections from cloudflare.
+ iptables: limit logging
+ Nginx and Gunicorn setup and config.
+ Logwatch and tiger, lynis etc... or any other HIDS.
+ Zabbix: subdomain, ssl, lets encrypt docs.
+ Zabbix: Zabbix agent in the client machine.
+ Zabbix: Apache security
+ Zabbix: Check https://www.zabbix.com/documentation/4.0/manual/installation/requirements/best_practices
+ Add references.

## Create a non-root user
Log-in to the server via ssh.
```shell
sudo apt-get update
sudo apt-get install sudo  # if not installed by default
adduser example_user
adduser example_user sudo  # add to sudoers
exit  # disconnect from server
ssh example_user@xxx.x.xx.xx  # log back in as limited user
```

## Create High Entropy
**Important:** There are many online tutorials/answers to increase entropy in headless environments. Many are not reliable in cryptographic terms, make sure that the source is trusted and validate the method from different sources. Arch wiki is an excellent source for this topic.

Needed for any sort of encryption, SSL/TLS... In virtualized headless environments, good-quality high entropy is problematic. `haveged` and/or `rng-tools` can be used to create entropy in headless environments. However, `haveged` should be used very carefully as it is not suitable for virtualized environments. Arch wiki recommends that:
> Unless you have a specific reason to not trust any hardware random number generator on your system, you should try to use them with the rng-tools first and if it turns out not to be enough (or if you do not have a hardware random number generator available), then use Haveged.

So try `rng-tools` first. Before doing anything, check available entropy to get an idea: `cat /proc/sys/kernel/random/entropy_avail`.
Then:
```shell
sudo apt-get install rng-tools
# might be called rngd.service
sudo systemctl start rng-tools.service
sudo systemctl enable rng-tools.service
```
Check if `rngd` has a source of entropy: `sudo rngd -v`. If the cluster does not have any external TPM chip, it is normal to see `Unable to open file: /dev/tpm0`. If you see `DRNG` entropy source, it is an Intel ‘hardware approach to high-quality, high-performance entropy and random number generation’ using the RDRAND processor instruction, which is good. Check if your processor has RDRAND instruction by `cat /proc/cpuinfo | grep rdrand`. If everything is fine move on.

Check if it is working correctly. The first command should give instantaneous output when `rng-tools` working correctly. Without it, outputted `dd` speed would be extremely low (<10KB/s). The second command executes a test of 1000 passes, you should get a maximum of 1-2 failures.
```
dd if=/dev/random of=/dev/null bs=1024 count=1 iflag=fullblock
rngtest -c 1000 </dev/random
```

## Network Config
After Ubuntu >=17.10, a new tool called `netplan` is used, instead of `/etc/network/interfaces`. Configs resides in `/etc/netplan/`. Depending on the cloud/vps provider, naming of config files might change e.g. `01-netcfg.yaml` or `50-cloud-init.yaml` etc. There you can configure static IP addresses, nameservers, network interfaces and so on. Usually it is pre-configured with cloud/vps providers, you might tweak it though.

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
```shell
sudo groupadd ssh-user
sudo usermod -a -G ssh-user <username>
```
In the server:, edit `/etc/ssh/sshd_config` to include the following
```
IgnoreRhosts yes
AddressFamily inet  # listen only on IPV4. Could be "AddressFamily inet6" for ipv6. This only affects sshd.
LogLevel VERBOSE
SyslogFacility AUTH
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
ClientAliveInterval 300
# Number of times to send the encrypted alive message before disconnecting clients if no response are received
ClientAliveCountMax 3
AllowGroups ssh-user
# Disable SSH version 1
Protocol 2
Port 2112
ListenAddress <Public_or_Priv_IP>
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KerberosAuthentication no
KerberosOrLocalPasswd no
KerberosTicketCleanup yes
GSSAPIAuthentication no
GSSAPICleanupCredentials yes
IgnoreUserKnownHosts yes
LoginGraceTime 30s
MaxSessions 10
MaxStartups 10:30:100
MaxAuthTries 2
UseDNS no
X11UseLocalhost yes
X11Forwarding no  # opens a channel from the server back to the client and the server can send X11 commands back to the client
# Port-forwarding (SSH tunneling)-related
# These are important security concerns
AllowTcpForwarding no
AllowStreamLocalForwarding no  # Check this back, it does not exist in the man page
AllowAgentForwarding no
GatewayPorts no
PermitTunnel no
TCPKeepAlive no
PrintLastLog no
Banner none
DebianBanner no
```
Remove all permissions from group and others (but not the owner) on `/etc/ssh/sshd_config`: `sudo chmod 600 /etc/ssh/sshd_config`

Then restart the sshd:
```shell
sudo systemctl enable sshd
sudo systemctl restart sshd
```

### SSH client config
```
Host *
    PermitLocalCommand no
    Tunnel no
    GSSAPIAuthentication no
    GSSAPIDelegateCredentials no
    HostbasedAuthentication no
    ForwardX11 no
    ForwardAgent no
    CheckHostIP yes
    Protocol 2
    BatchMode no
    Port 2112
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    UseRoaming no
    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
    PubkeyAuthentication yes
    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
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
**Note**: MySQL listens on 3306, PostgreSQL on 5432, Zabbix agent on 10050.
```shell
# Block NULL packages
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
# XMAS packet
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
# Drop all new TCP conn that are not SYN (SYN flood)
sudo iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
# Drop INVALID packages
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
# Rate limit new tcp conn (SYN flood)
sudo iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit <LIMIT_1>/second --limit-burst <LIMIT_2> -j ACCEPT
# SMURF attack. This is not necessary if blocking all icmp
sudo iptables -A INPUT -p icmp -m limit --limit <LIMIT_3>/second --limit-burst <LIMIT_4> -j ACCEPT

sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -i <INTERFACE> -p tcp -s <SOURCE_IP> --dport <SSH_PORT> -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -i <INTERFACE> -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -i <INTERFACE> -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -i <INTERFACE> -p tcp -s <SOURCE_IP> --dport 3306 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -i <INTERFACE> -p tcp -s <SOURCE_IP> --dport 10050 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -o <INTERFACE> -p tcp --sport <SSH_PORT> -m conntrack --ctstate ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -o <INTERFACE> -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -o <INTERFACE> -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -o <INTERFACE> -p tcp --sport 3306 -m conntrack --ctstate ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -o <INTERFACE> -p tcp --sport 10050 -m conntrack --ctstate ESTABLISHED -j ACCEPT

sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
```
Save the changes, otherwise lost on reboot (do this after every addition/removal):
```shell
sudo dpkg-reconfigure iptables-persistent
reboot
```
Check by `sudo iptables -L -nv`. Rules should be under `/etc/iptables/rules.v4` and `/etc/iptables/rules.v6`.

**IMPORTANT:** Do similarly (e.g. change IP4-type addresses to IP6) for `ip6tables` for IPv6 rules.

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

## Disable Unused Filesystems
Create `/etc/modprobe.d/dev-sec.conf` file with the following contents:
```
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
```
Do not disable `vfat` as it is necessary for EFI.

## Sysctl Config
Change the kernel parameters at runtime. **Note:** From version 207 and 21x, systemd only applies settings from `/etc/sysctl.d/*.conf`. If you had customized `/etc/sysctl.conf`, you need to rename it as `/etc/sysctl.d/99-sysctl.conf`. If you had e.g. `/etc/sysctl.d/foo`, you need to rename it to `/etc/sysctl.d/foo.conf`.
Edit the appropriate file to include the following:
```
###
### GENERAL SYSTEM SECURITY OPTIONS ###
###

# Restart after X seconds in case of kernel panic
kernel.panic = 20

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

# Disable acceptance of IPv6 router solicitations messages
net.ipv6.conf.default.router_solicitations = 0

# Disable Accept Router Preference from router advertisement
net.ipv6.conf.default.accept_ra_rtr_pref = 0

# Disable learning Prefix Information from router advertisement
net.ipv6.conf.default.accept_ra_pinfo = 0

# Disable learning Hop limit from router advertisement
net.ipv6.conf.default.accept_ra_defrtr = 0

# Disable neighbor solicitations to send out per address
net.ipv6.conf.default.dad_transmits = 0

# Assign one global unicast IPv6 addresses to each interface
net.ipv6.conf.default.max_addresses = 1

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

# Modes for sending replies in response to received ARP requests that resolve local target IP addresses
net.ipv4.conf.all.arp_ignore = 1

# Restriction levels for announcing the local source IP address from IP packets in ARP requests sent on interface
net.ipv4.conf.all.arp_announce = 2

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

# ICMP ratelimit
# Affected ICMP types defines in icmp_ratemask
net.ipv4.icmp_ratelimit = 100

# ICMP ratemask
net.ipv4.icmp_ratemask = 88089

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

Before appyling the settings, disable `apport` automatic crash report generation (at least in Ubuntu 18.04).
This service overrides `fs.suid_dumpable` value. Thus do:
```
sudo systemctl stop apport.service
sudo systemctl disable apport.service
sudo systemctl mask apport.service
```
To be double sure, also change the `enabled` value to `0` in `/etc/default/apport`.

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

Removed the following as it can cause serious data loss in the event of data loss. Instead of disabling, you should physically secure the device.
```
# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0
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

## Nginx
```shell
sudo apt update
sudo apt install nginx
sudo systemctl enable nginx
```
By default, nginx serves files from `/var/www/html` dir. It is highly recommended to configure nginx with the *server blocks* (apache equivalent: *virtual host*), which allow a single web server to serve multiple websites if needed.
+ Credentials Storage Location/SSL certificate: `mkdir /root/certs/example.com/`, move your certificate(s) and key(s) into that folder.
Restrict permissions on the key file: `chmod 400 /root/certs/example.com/example.com.key`.
+ A Diffie-Hellman parameter is a set of randomly generated data used when establishing Perfect Forward Secrecy during initiation of an HTTPS connection. The default size is usually 1024 or 2048 bits, depending on the server’s OpenSSL version, but a 4096 bit key will provide greater security.
```
cd /root/certs/example.com
openssl genpkey -genparam -algorithm DH -out /root/certs/example.com/dhparam4096.pem -pkeyopt dh_paramgen_prime_len:4096
```

Generate configs like:
+ Create root directory at `/var/www/example.com/`
+ Create and config `/etc/nginx/conf.d/example.com.conf`
```
server {
    listen              <public_ipv4>:80;
    listen              [<public_ipv6>]:80;
    server_name         example.com www.example.com;
    return 301          https://example.com$request_uri;
    return 301          https://www.example.com$request_uri;
    }

server {
    listen              <public_ipv4>:443 ssl http2 default_server;
    listen              [<public_ipv6>]:443 ssl http2 default_server;
    server_name         example.com www.example.com;
    root                /var/www/example.com;
    index               index.html;

    location / {
         proxy_cache    one;
            proxy_pass  http://localhost:8000;
    }

    gzip             on;
    gzip_comp_level  3;
    gzip_types       text/plain text/css application/javascript image/*;
}
```
+ Changes we want nginx to apply universally are in the http block of `/etc/nginx/nginx.conf`:
Static content compression: Enable `gzip` compression only for certain content (images, HTML, and CSS). Do not do this for other file types as it might lead to exploits (CRIME and BREACH).
Disable server tokens to remove nginx version display to public. Unlike other directives, an add_header directive is not inherited from parent configuration blocks. If you have the directive in both, an add_header directive in a server block will override any in your http area. Replace ip-address and port with the URL and port of the upstream service whose files you wish to cache. For example, you would fill in 127.0.0.1:9000 if using WordPress. Directives you want NGINX to apply to all sites on your server should go into the http block of nginx.conf, including SSL/TLS directives. The directives below assume one website, or all sites on the server, using the same certificate and key. .pem format can also be used. SSL/TLS handshakes use a non-negligible amount of CPU power, so minimizing the amount of handshakes which connecting clients need to perform will reduce your system’s processor use. One way to do this is by increasing the duration of keepalive connections from 60 to 75 seconds. Maintain a connected client’s SSL/TLS session for 10 minutes before needing to re-negotiate the connection. OCSP Stapling, when enabled, NGINX will make OCSP requests on behalf of connecting browsers. The response received from the OCSP server is added to NGINX’s browser response, which eliminates the need for browsers to verify a certificate’s revocation status by connecting directly to an OCSP server.


```
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;

    server_tokens       off;
    keepalive_timeout   75;

    add_header          Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header          X-Content-Type-Options nosniff;
    add_header          X-Frame-Options SAMEORIGIN;
    add_header          X-XSS-Protection "1; mode=block";

    ssl_certificate     /root/certs/example.com/example.com.crt;
    ssl_certificate_key /root/certs/example.com/example.com.key;
    ssl_ciphers         ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_dhparam         /root/certs/example.com/dhparam4096.pem;
    ssl_prefer_server_ciphers on;
    ssl_protocols       TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /root/certs/example.com/cert.crt;

    proxy_cache_path /var/www/example.com/cache/ keys_zone=one:10m inactive=60m use_temp_path=off;
}
```
`sudo nginx -s reload`
`openssl s_client -connect example.org:443 -tls1 -tlsextdebug -status`
The return response should show a field of OCPS response data.


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
Remember that even if you edit the config file, if you do not restart `mysql daemon`, it will not take effect for the users created in subsequent steps. Thus quickly edit `/etc/mysql/my.cnf` to include the following:
```
[mysqld]
default_password_lifetime=0
```
Restart by `sudo systemctl restart mysql`

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
# set bind-address so that it listens on that ip and interface
bind_address="DB_server_private_IPv4_or_IPv6"  # default is 127.0.0.1
sql-mode="TRADITIONAL"
transaction-isolation="READ-COMMITTED"
default-storage-engine="InnoDB"
character_set_server="utf8mb4"
collation_server="utf8mb4_unicode_ci"
character-set-client-handshake=OFF
local_infile=OFF  # prevent reading files on the local filesystem even if the user has FILE privilege
symbolic-links=OFF
```
Restart `sudo systemctl restart mysql`.
+ Generate TLS Certicate and Keys
In the **DB server machine**:
```
# Generates in /var/lib/mysql
sudo mysql_ssl_rsa_setup --uid=mysql
# In modern MySQL versions, it auto checks for the cert and keys in mysql folders
sudo systemctl restart mysql
```
Get the contents of `var/lib/mysql/ca.pem`, `/var/lib/mysql/client-cert.pem`, and `/var/lib/mysql/client-key.pem` as we will need them to configure the client machine.

Establish trust in the **DB client machine**:
```
mkdir ~/client-ssl
chmod 700 ~/client-ssl
# Copy the contents from the corresponding files from the last step in these files
nano ~/client-ssl/ca.pem
nano ~/client-ssl/client-cert.pem
nano ~/client-ssl/client-key.pem
```
Test the connection:
`mysql -u remote_user -p -h mysql_server_IP --ssl-mode=REQUIRED --ssl-ca=~/client-ssl/ca.pem --ssl-cert=~/client-ssl/client-cert.pem --ssl-key=~/client-ssl/client-key.pem`
Then if successful, in MySQL command prompt, check:
```
SHOW VARIABLES LIKE '%ssl%';
STATUS;
```
+ Enforce encryption. In `[mysqld]` section of `/etc/mysql/my.cnf` of the **DB server machine** add:
```
# Require clients to connect either using SSL
# or through a local socket file
require_secure_transport=ON
```
Restart `sudo systemctl restart mysql`.

In the **DB client machine**, add to the `[client]` section of `/etc/mysql/my.cnf`:
```
[client]
ssl-mode="REQUIRED"
ssl-ca="/path/to/client-ssl/ca.pem"
ssl-cert="/path/to/client-ssl/client-cert.pem"
ssl-key="/path/to/client-ssl/client-key.pem"
bind-address="DB_client_private_IPv4_or_IPv6"
default-character-set="utf8mb4"
# prevent reading files on the local filesystem even if the user has FILE privilege
local-infile=0
```
Then test the connection as before.
**Important:** When setting the paths and permissions for the ssl certs and keys in the client machine, consider the user that is running django. It is the one that at least needs the read permissions. However, you can give the write permissions to root.

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
+ On the machine that will monitor:
```shell
sudo apt update
sudo apt install zabbix-server-mysql zabbix-frontend-php
```
+ Configure MySQL before going any further. Since MySQL is on the same machine, omit the MySQL configs that changes settings related to `SSL/TLS` since it will be local. Also, do not forget to change settings according to `localhost` from `REMOTE_IP`, and you may leave the `Port` with the default config.
**IMPORTANT:** Although the true UTF8 encoding is utf8mb4 for MySQL (and utf8 is an alias for utf8mb3 in MySQL 5.7), the character set used below is utf8 and it is retrieved from Zabbix docs. Thus, it is not wise to change it according to the MySQL part of this documentation, in which it is suggested to use utf8mb4.
+ Create a new database for Zabbix, create a Zabbix user for MySQL, set up the schema and import the data into the Zabbix database:
```
mysql -uroot -p
mysql> CREATE DATABASE zabbix CHARACTER SET utf8 collate utf8_bin;
mysql> CREATE USER 'zabbix'@'localhost' IDENTIFIED BY 'your_zabbix_mysql_password';
mysql> FLUSH PRIVILEGES;
mysql> GRANT SELECT, INSERT, UPDATE, DELETE, ALTER, ALTER ROUTINE, CREATE, CREATE ROUTINE, CREATE TEMPORARY TABLES, CREATE VIEW, DROP, EVENT, EXECUTE, INDEX, LOCK TABLES, REFERENCES, SHOW VIEW, TRIGGER ON zabbix.* TO 'zabbix'@'localhost';
mysql> FLUSH PRIVILEGES;
mysql> EXIT;
zcat /usr/share/doc/zabbix-server-mysql/create.sql.gz | mysql -uzabbix -p zabbix
```
+ Edit `/etc/zabbix/zabbix_server.conf` and include:
```
DBHost=localhost
DBName=zabbix
DBUser=zabbix
DBPassword=<password>
# Only listen on localhost
# We do not need push from zabbix agents
ListenIP=127.0.0.1
```
+ Add appropriate `iptables` rules.
+ Edit `sudo nano /etc/zabbix/apache.conf` and enter correct `php_value date.timezone`.
+ Restart, check and enable at startup:
```shell
sudo systemctl restart apache2
sudo systemctl start zabbix-server
sudo systemctl status zabbix-server
sudo systemctl enable zabbix-server
```

The rest is GUI config, **but before that configure Zabbix agent in the target machines**. The following URL should now be active: `http://zabbix_server_domain_or_IP/zabbix/`. Check <https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-zabbix-to-securely-monitor-remote-servers-on-ubuntu-18-04> if you have questions for GUI config.

### Zabbix Agent
+ Install it into the target machines:
```shell
sudo apt-get update
sudo apt-get install zabbix-agent
```
+ Encrypt the connection between the agent and the Zabbix server. **Important:** Check the pre-shared key (PSK) size limits from [Zabbix PSK Docs](https://www.zabbix.com/documentation/4.0/manual/encryption/using_pre_shared_keys). Do not forget to choose your version. Depending on the crypto lib, max allowed PSK size differs, use the max. to determine which lib your version depends on, check the dependencies of the apt package. Generate a PSK: `sudo openssl rand -hex <NUM_BYTES> > /etc/zabbix/zabbix_agentd.psk` (openssl here is independent of the lib used when compiling Zabbix). Replace `<NUM_BYTES>` with an allowed size for your crypto lib. It could be 256 bytes for example.
+ Edit `/etc/zabbix/zabbix_agentd.conf` to include (**Remember to change `TLSPSKIdentity` if the same name exists on another machine**):
```
# Set Server to acccept only from that IP
# Pay attention to selecting the IP of the server on the private network interface
Server=zabbix_server_ip_address
# ListenIP is the machine the agent is running
# Pay attention to selecting the IP on the private network interface
ListenIP=ip_on_priv_interface
EnableRemoteCommands=0
TLSConnect=psk
TLSAccept=psk
TLSPSKFile=/etc/zabbix/zabbix_agentd.psk
TLSPSKIdentity=PSK001
```
+ Check the file permissions on:
```
ls -l /etc/zabbix/zabbix_agentd.conf
ls -l /etc/zabbix/zabbix_agentd.psk
```
Ideally, make `zabbix_agentd.psk` (created by you) file permissions same as `zabbix_agentd.conf`.
+ Restart
```shell
sudo systemctl restart zabbix-agent
sudo systemctl enable zabbix-agent
sudo systemctl status zabbix-agent
```
+ Add appropriate `iptables` rules. By default, Zabbix agent waits for connections on port `10050` from Zabbix server. Also configure the Zabbix server machine to allow outgoing connections on that port. Do not forget to specify the network interface for private networking.
+ Go to `http://zabbix_server_domain_or_IP/zabbix/` and configure a new host, with the newly generated PSK. Then configure notifications etc. from the GUI.

## Useful Commands
```shell
hostname -A  # display all FQDN
hostname -I  # display all network addresses of the host
netstat -i  # show network interfaces
grep -rHin "string to be searched" /where/to/search  # search all text files for a string
```
