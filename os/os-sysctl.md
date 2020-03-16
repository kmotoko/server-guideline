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

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# Restrict ptrace scope
# 2=only admin can ptrace
# 2 is good for production servers
kernel.yama.ptrace_scope = 2

# Protect links on the filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

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
vm.swappiness = 30

# Consensus: 10% for 1GB = 100MB, for 16GB 500MB is sane
# Once you set dirty_ratio, a 1:2 ratio between
# dirty_ratio : dirty_background_ratio is reasonable
# Note that higher ratio values may increase performance
# but it also increases the risk of data loss
vm.dirty_ratio = 8
vm.dirty_background_ratio = 4

# Rule for minimum free KB of RAM: (installed_mem / num_of_cores) * 0.06
vm.min_free_kbytes = 251658

# On Debian 10, the default = 100
# Decreased values might increase performance
# NEVER EVER set it to 0
vm.vfs_cache_pressure = 50

# 50% overcommitment of available memory
vm.overcommit_ratio = 50
vm.overcommit_memory = 0

# Set maximum amount of memory allocated to shm to 512MB
kernel.shmmax = 536870912
kernel.shmall = 536870912


###
### GENERAL NETWORK SECURITY OPTIONS ###
###

# Do not allow unprivileged users to run code in the kernel through BPF
kernel.unprivileged_bpf_disabled = 1

# Previously, it was recommended to disable the BPF JIT compiler
# Some Spectre variants make use BPF interpreter
# Thus, in newer kernels, BPF JIT compiler is always ON
# if you set it to ON, also use hardening
# bpf_jit_harden = 1 means harden the unprivileged code
# Full hardening (value=2) might cripple some tracing/debugging functions
net.core.bpf_jit_enable = 1
net.core.bpf_jit_harden = 2

# Prevent SYN attack, enable SYNcookies (they will kick-in when the max_syn_backlog reached)
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
# Mode '1': reply only if the target IP address is local address configured on the incoming interface
net.ipv4.conf.all.arp_ignore = 1

# Restriction levels for announcing the local source IP address from IP packets in ARP requests sent on interface
# Mode '2': ignore the source address in the IP packet and try to select local address that we prefer for talks with the target host
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

# Disable logging martian packages
# Otherwise it might cause DOS
net.ipv4.conf.default.log_martians = 0
net.ipv4.conf.all.log_martians = 0

# Do not auto-configure IPv6
net.ipv6.conf.all.autoconf=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.default.accept_ra=0


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

# This will ensure that immediately subsequent connections use the new values
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

**Load the tcp_bbr module:** This is used in the sysctl.conf above. You can do `sudo modprobe tcp_bbr`, and to stick it across reboots, add `/etc/modules-load.d/tcp_bbr.conf` file and just add the following line in it `tcp_bbr`. This is systemd-modules-load.service and it reads files from the above directory which contain kernel modules to load during boot in a static list. Then reboot and check if it is loaded by `sudo lsmod | grep tcp`. Actually, modern kernels loads modules as needed, but just to be safe...


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

Removed the following as it can cause serious data loss. Instead of disabling, you should physically secure the device.
```
# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0
```
