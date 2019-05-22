## MySQL
### Initial Setup
``` shell
sudo apt update
sudo apt install mysql-server
sudo mysql_secure_installation  # safer defaults
# mysql_install_db (below) might not be necessary depending on the distro
# In that case, you should get a "File exists" error or alike
sudo mysql_install_db  # or in later MySQL versions: sudo mysqld --initialize
sudo systemctl enable mysql
sudo systemctl start mysql
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

**Important:** This assumes `/var/log/mysql/` directory exists for the general logs. Check it first.
```
[mysqld]
user=mysql  # include again
# set bind-address so that it listens on that ip and interface
bind_address="DB_server_private_IPv4_or_IPv6"  # default is 127.0.0.1
sql-mode="TRADITIONAL"
transaction-isolation="READ-COMMITTED"
default-storage-engine="InnoDB"
character_set_server="utf8mb4"
collation_server="utf8mb4_unicode_ci"
character-set-client-handshake=OFF
general-log-file="/var/log/mysql/mysql.log"
general-log=1
local-infile=0  # prevent reading files on the local filesystem even if the user has FILE privilege
skip-symbolic-links=1
symbolic-links=0
allow-suspicious-udfs=0
automatic-sp-privileges=0
skip-show-database
safe-user-create=1
secure-file-priv="/tmp"
secure-auth=1
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

### InSpec Checks
You can ignore the following InSpec tests:
1) /etc/mysql/my.cnf should not be readable by others --> If you take the permission from others, mysql daemon won't be able to read the config as well. Do not do it.
2) /var/log//mysql.log should be owned by "mysql" and File /var/log//mysql.log should be grouped into "adm" --> Log folder location in our setup is different and both the owner and the group belongs to `mysql` by mysql defaults.
