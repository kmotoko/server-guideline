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
