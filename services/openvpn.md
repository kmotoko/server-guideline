## OpenVPN
### Disable IPv6
Not needed to access internal resources.
Add the following to `/etc/sysctl.d/99-sysctl.conf`:
```
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
```
Pay attention to already-configured rules. Safe way is to append towards the end of the file, before flushing the net rules.
Apply the rules: `sudo sysctl --system`
Comment out the following line in `/etc/hosts`:
```
#::1     localhost ip6-localhost ip6-loopback
```

### Install OpenVPN
+ Install via
```shell
sudo apt-get update
sudo apt-get install openvpn
```
+ Add a user for openvpn to isolate it:
```shell
sudo adduser --system --shell /usr/sbin/nologin --no-create-home ovpn
sudo groupadd ovpn
sudo usermod -g ovpn ovpn
```
+ Generate HMAC signature
Require a matching HMAC signature for all packets involved in the TLS handshake between the server and connecting clients. Packets without this signature are dropped.
```shell
sudo openvpn --genkey --secret /etc/openvpn/server/ta.key
```

+ Set up forward secrecy
Generate Diffie-Hellman parameter. This is a set of randomly generated data used when establishing Perfect Forward Secrecy during creation of a client’s session key. The default size is 2048 bits, but OpenVPN’s documentation recommends to use a prime size equivalent to your RSA key size.
```shell
sudo openssl genpkey -genparam -algorithm DH -out /etc/openvpn/server/dhp4096.pem -pkeyopt dh_paramgen_prime_len:4096
```

### VPN Certificate Authority
Create this in a secure local computer and store them offline as much as possible.
+ You can generate certificates and keys by using EasyRSA.
```shell
sudo apt-get install easy-rsa
# Create a CA dir
make-cadir ~/ca && cd ~/ca
# Replace X.X with the correct one
ln -s openssl-1.X.X.cnf openssl.cnf
```
+ The vars file created in /ca contains presets used by EasyRSA. Here you can specify a distinguished name for your certificate authority that will be passed to client certificates. Changing these fields is optional, but do it. Then, within `~/ca` dir: `source ./vars`. If it says something like `NOTE: If you run ./clean-all, I will be doing a rm -rf on /home/user/ca/keys`, run `./clean-all`.

+ Create server credentials
A root certificate, sometimes called a Certificate Authority, is the certificate and key pair that will be used to generate key pairs for clients and intermediate authorities (on this VPN server there are none). At each prompt, add or edit the information to be used in your certificate, or leave them blank. Use your VPN server’s hostname or some other identifier as the Common Name. **Important:** When using `build-ca`, also fill in the challenge password.
```shell
# Create CA
./build-ca
# Create server private key
# Confirm the signing of the certificate and the certificate requests by answering yes
./build-key-server server
# Upload the server credentials
scp ./keys/{ca.crt,server.crt,server.key} USERNAME@<SERVER_IP>:/etc/openvpn/server
# Upload the HMAC key
scp USERNAME@<SERVER_IP>:/etc/openvpn/server/ta.key ./keys
```

+ Create client credentials
Each client device connecting to the VPN should have its own unique key and identifier (client1, client2, etc.). All other certificate information can remain the same and be shared across all client devices. If you need to add users at any time later, just repeat this step using a different client name.
```
cd ~/ca && source ./vars && ./build-key-pass client1
```
**Important:** `./build-key-pass` and `./build-key` are different in that the former is encrypted with a passphrase.

### Server config file
Edit/create `/etc/openvpn/server.conf`:
```
dev tun
persist-key
persist-tun
topology subnet
port 1194
proto udp
keepalive 10 120

# Location of certificate authority's cert.
ca /etc/openvpn/server/ca.crt

# Location of VPN server's TLS cert.
cert /etc/openvpn/server/server.crt

# Location of server's TLS key
key /etc/openvpn/server/server.key

# Location of DH parameter file.
dh /etc/openvpn/server/dhp4096.pem

# The VPN's address block starts here.
server 10.89.0.0 255.255.255.0

explicit-exit-notify 1

# Drop root privileges and switch to the `ovpn` user after startup.
user ovpn

# OpenVPN process is exclusive member of ovpn group.
group ovpn

# Cryptography options. We force these onto clients by
# setting them here and not in client.ovpn. See
# `openvpn --show-tls`, `openvpn --show-ciphers` and
#`openvpn --show-digests` for all supported options.
tls-crypt /etc/openvpn/server/ta.key
auth SHA512    # This needs to be in client.ovpn too though.
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256
ncp-ciphers AES-256-GCM:AES-256-CBC

# Logging options.
ifconfig-pool-persist ipp.txt
status openvpn-status.log
log /var/log/openvpn.log
verb 3
```

### Client config file
OpenVPN’s client-side configuration file is client.ovpn. When you import an OpenVPN profile, the location of the directory where the credentials are stored doesn’t matter, but this .ovpn file needs to be in the same directory as the client certificate and all other credentials. OpenVPN does not refer to any of these files after importing and they do not need to remain on the client system.
Create `client.ovpn` file:

```
# No cryptography options are specified here because we want
# the VPN server to push those settings to clients rather than
# allow clients to dictate their crypto.

client
dev tun
persist-key
persist-tun
proto udp
nobind
user ovpn
group ovpn
remote-cert-tls server
auth SHA512
verb 3

# Remote server's IP address and port. IP is
# preferable over hostname so as not to rely
# on DNS lookups.
remote <your_linode's IP address> 1194

# To successfully import this profile, you
# want the client device's CA certificate copy,
# client certificate and key, and HMAC signature
# all in the same location as this .ovpn file.
ca ca.crt
cert client1.crt
key client1.key
tls-crypt ta.key
```

### Start OpenVPN daemon
**Important:** Below code will scan the /etc/openvpn directory on the server for files with a .conf extension. For every file that it finds, it will spawn a VPN daemon (server instance) so make sure you don’t have a client.conf or client.ovpn file in there.
```shell
sudo systemctl enable openvpn.* && sudo systemctl start openvpn.*
# Check it
sudo systemctl status openvpn*
```


### Overview of credentials
Each client device needs to contain the following files:

+ client1.key # Exclusive to this device.
+ client1.cert # Exclusive to this device.
+ CA.pem # Is shared among server and client devices.
+ ta.key # Is shared among server and client devices.
+ client.ovpn # Is shared among client devices.
