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
Rules should be under `/etc/iptables/rules.v4` and `/etc/iptables/rules.v6`.
**Note**: MySQL listens on 3306, PostgreSQL on 5432, Zabbix agent on 10050.

After modifying the rules, activate the ruleset:
```shell
sudo iptables-restore < /etc/iptables/rules.v4
sudo ip6tables-restore < /etc/iptables/rules.v6
```

Save the changes, otherwise lost on reboot:
```shell
sudo dpkg-reconfigure iptables-persistent
reboot
```

Check by `sudo iptables -L -nv`.

**IMPORTANT:** Do similarly (e.g. change IP4-type addresses to IP6) for `ip6tables` for IPv6 rules.

Also check:
<http://www.robertopasini.com/index.php/2-uncategorised/650-linux-iptables-block-common-attacks>
<https://support.hostway.com/hc/en-us/articles/360002236980-How-To-Set-Up-a-Basic-Iptables-Firewall-on-Centos-6>
<https://www.cyberciti.biz/tips/linux-iptables-10-how-to-block-common-attack.html>
<https://linoxide.com/firewall/block-common-attacks-iptables/>

If your firewall's built-in policy function is set to "drop" and your firewall rules are ever flushed (reset), or if certain matching rules are removed, your services will instantly become inaccessible remotely. This is often a good idea when setting policy for non-critical services so that your server is not exposed to malicious traffic if the rules are removed.
