## Network Config
After Ubuntu >=17.10, a new tool called `netplan` is used, instead of `/etc/network/interfaces`. Configs resides in `/etc/netplan/`. Depending on the cloud/vps provider, naming of config files might change e.g. `01-netcfg.yaml` or `50-cloud-init.yaml` etc. There you can configure static IP addresses, nameservers, network interfaces and so on. Usually it is pre-configured with cloud/vps providers, you might tweak it though.


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
