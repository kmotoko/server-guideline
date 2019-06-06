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
    + [InSpec Checks](#inspec-checks)
+ [Login.defs Modifications](#login.defs-modifications)
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
    + [InSpec Checks](#inspec-checks)
+ [Zabbix](#Zabbix)
  + [Install and Config LAMP Stack](#install-and-config-lamp-stack)
  + [Zabbix Server](#zabbix-server)
  + [Zabbix Agent](#zabbix-agent)
+ [Useful Commands](#useful-commands)

Follow this order when configuring a server:
1. Do everything in `intro/` folder.
2. Do everything in `networking/` folder.
3. Do everything in `os/` folder.
4. Do `ssh` in `services/` folder.
5. Do appropriate service in `services/` folder.

## Work in Progress
+ In SSH daemon config: `AllowStreamLocalForwarding no  # it does not exist in the man page`
+ SSH: 2fa implementation
+ IP spoofing protection: check nsswitch config (could not find corresponding key at this time).
+ Sysctl config: Fine tune mentioned variables.
+ DMARC: Check how to implement a DMARC record.
+ rkhunter: Re-check docs
+ Updates: Unattended upgrades for security patches (or should it be unattended???).
+ iptables: Rate limiting and cloudflare dilemma, since they do not forward client IPs.
+ iptables: Only allow http/https connections from cloudflare.
+ iptables: limit logging, martians
+ Nginx and Gunicorn setup and config.
+ Logwatch and tiger, lynis etc... or any other HIDS.
+ Zabbix: subdomain, ssl, lets encrypt docs.
+ Zabbix: Zabbix agent in the client machine.
+ Zabbix: Apache security
+ Zabbix: Check https://www.zabbix.com/documentation/4.0/manual/installation/requirements/best_practices
+ Check IDSs: Lynis, ossec, tiger, tripwire, aide, snort
+ Check InputTCPServerStreamDriverPermittedPeer options for rysylog server and ActionSendStreamDriverPermittedPeer option in rsyslog client.
+ Replace wazuh with ossec
+ OpenVPN 2-factor auth
+ Postfix and logwatch mail sending config
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
