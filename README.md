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
+ Check IDSs: Lynis, ossec, tiger, tripwire, aide, snort
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
