Follow this order when configuring a server:
1. Do everything in `intro/` folder.
2. Do everything in `networking/` folder.
3. Do everything in `os/` folder.
4. Do `ssh` in `services/` folder.
5. Do appropriate service in `services/` folder.

## Work in Progress
+ In SSH daemon config: `AllowStreamLocalForwarding no  # it does not exist in the man page`.
+ SSH: 2fa implementation.
+ IP spoofing protection: check nsswitch config (could not find corresponding key at this time).
+ Sysctl config: Fine tune the mentioned variables.
+ DMARC: Check how to implement a DMARC record.
+ Updates: Unattended upgrades for security patches (or should it be unattended?).
+ iptables: Rate limiting and cloudflare dilemma, since they do not forward client IPs.
+ iptables: Only allow http/https connections from cloudflare.
+ iptables: Limit logging, martians.
+ Nginx and Gunicorn setup and config.
+ Logwatch and Tiger, lynis etc... or any other HIDS.
+ Zabbix: Subdomain, ssl, lets encrypt docs.
+ Zabbix: Zabbix agent in the client machine.
+ Zabbix: Apache security.
+ Zabbix: Check https://www.zabbix.com/documentation/4.0/manual/installation/requirements/best_practices
+ Check IDSs: Lynis, ossec, tiger, tripwire, aide, snort.
+ Check InputTCPServerStreamDriverPermittedPeer options for rysylog server and ActionSendStreamDriverPermittedPeer option in rsyslog client.
+ Replace wazuh with ossec.
+ OpenVPN 2-factor auth.
+ Postfix and logwatch mail sending config.
+ Password expiration config to be added to the password quality.
+ For the password quality section: Not clear if it is needed to set `/etc/security/pwquality.conf`.
+ Add references.

## Determine and disable running services
Check network services: `sudo ss -atpu`. Check system services and daemons: `sudo systemctl list-units --all`

## Useful Commands
```shell
hostname -A  # display all FQDN
hostname -I  # display all network addresses of the host
netstat -i  # show network interfaces
grep -rHin "string to be searched" /where/to/search  # search all text files for a string
```
