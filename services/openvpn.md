## OpenVPN
### Considerations before starting
Your VPN server might have all the following (at least two of them):
+ Public facing IP (public net)
+ Local network IP (private subnet)
+ VPN interface IP (tun interface)

Now the important thing is to avoid subnet conflicts, meaning that the local subnet IPs and VPN interface subnet IPs should not share the same address space. Secondly, the OpenVPN client also should not share the same space as the remote local network subnet and the vpn subnet. If you can connect to the VPN server but cannot access to the resources in the remote local network, check if there is any overlap in the address spaces.
Thus, here is the checklist before starting:
+ Check your public interface name
+ Check your private interface name and subnet
These will be used in the configurations below.

### Prerequisites: Packet forwarding, hosts config, and routing
+ IP forwarding and IPv6:
Ensure that IP forwarding is turned on in the kernel. IP forwarding allows the kernel to pass packets from one interface to another. Also, IPv6 is not needed to access internal resources.Since we are going to shut down ipv6, **remove the ipv6 related settings** from this guide's sysctl config. Then, **remove the lines about the ipv4 forwarding** as it will be enabled for the vpn server. Add the following to `/etc/sysctl.d/99-sysctl.conf` just before the part where you flush ipv4 and ipv6 config:

```
net.ipv4.ip_forward = 1

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```
Apply the rules: `sudo sysctl --system`.
**Important:** Again from Arch wiki:
> If the system uses systemd-networkd to control the network interfaces, a per-interface setting for IPv4 is not possible, i.e. systemd logic propagates any configured forwarding into a global (for all interfaces) setting for IPv4. The advised work-around is to use a firewall to forbid forwarding again on selective interfaces. See the systemd.network(5) manual page for more information. The IPForward=kernel semantics introduced in a previous systemd release 220/221 to honor kernel settings does not apply anymore.

Thus in iptables, allow forwarding only from/to a specific interface.

Comment out the following line in `/etc/hosts`:
```
#::1     localhost ip6-localhost ip6-loopback
```

+ Routing
From arch wiki:
> By default, all IP packets on a LAN addressed to a different subnet get sent to the default gateway. If the LAN/VPN gateway is also the default gateway, there is no problem and the packets get properly forwarded. If not, the gateway has no way of knowing where to send the packets. There are a couple of solutions to this problem.
    + Add a static route to the default gateway routing the VPN subnet to the LAN/VPN gateway's IP address.
    + Add a static route on each host on the LAN that needs to send IP packets back to the VPN.
    + Use iptables' NAT feature on the LAN/VPN gateway to masquerade the incoming VPN IP packets.

Therefore, the solution will involve NAT (Network Address Translation).
> NAT generally involves "re-writing the source and/or destination addresses of IP packets as they pass through a router or firewall"

### Iptables config
See the iptables rules. In addition, since you cannot restore table rules with `iptables-restore` from `rules.v4` and `rules.v6`, after restoring and saving the `INPUT`, `OUTPUT` and `FORWARD` rules, do:
```shell
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o <PRIVATE_INTERFACE> -j MASQUERADE
```
where `10.8.0.0/24` is the VPN subnet and `<PRIVATE_INTERFACE>` is the remote private LAN. Then, do: `sudo dpkg-reconfigure iptables-persistent`.

**Important:** Do not forget to only allow forwarding from/to specific interface.

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
+ The vars file created in /ca contains presets used by EasyRSA. Here you can specify a distinguished name for your certificate authority that will be passed to client certificates. Changing these fields is optional, but do it. Also change `export KEY_SIZE=2048` to `4096` since OpenVPN docs recommends the same size for the Diffie-Hellman parameter and the RSA key size. Then, within `~/ca` dir: `source ./vars`. If it says something like `NOTE: If you run ./clean-all, I will be doing a rm -rf on /home/user/ca/keys`, run `./clean-all`.

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
Change `PRIVATE_NET_SUBNET` with your actual one.
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
server 10.8.0.0 255.255.255.0

#  OpenVPN server can ‘push’ a route to the OpenVPN client
# to make it aware of the private network
push "route PRIVATE_NET_SUBNET 255.255.255.0"

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

**Important:** `push "route PRIVATE_NET_SUBNET 255.255.255.0"` is important to access the private net resources from the VPN client. It dictates the client that a private subnet exists on the remote network.

**Important:** It is generally recommended to use OpenVPN over UDP, because TCP over TCP is a bad idea, see: http://sites.inka.de/bigred/devel/tcp-tcp.html.
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
**Important:** Below code will scan the `/etc/openvpn` directory on the server for files with a .conf extension. For every file that it finds, it will spawn a VPN daemon (server instance) so make sure you don’t have a `client.conf` or `client.ovpn` file in there.
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
