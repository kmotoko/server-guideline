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
