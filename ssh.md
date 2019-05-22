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
