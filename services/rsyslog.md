## Rsyslog for Centralized Log Collection
**Important:** Time must be in synchronized between server and client for remote logging to work.
So make sure you are using a time syncing tool like chronyd, ntpd etc.

We’re going to configure rsyslog server as central Log management system.
This follows the client-server model where rsyslog service will listen on either udp/tcp port.
The default port used by rsyslog is 514. On the client system,
rsyslog will collect and ship logs to a central rsyslog server over the network via UDP or TCP ports.

When working with syslog messages, there is a priority/severity level that characterizes a log file. Namely:
+ emerg, panic (Emergency ): Level 0 – This is the lowest log level. system is unusable
+ alert (Alerts):  Level 1 – action must be taken immediately
+ err (Errors): Level 3 – critical conditions
+ warn (Warnings): Level 4 – warning conditions
+ notice (Notification): Level 5 – normal but significant condition
+ info (Information): Level 6 – informational messages
+ debug (Debugging):  Level 7 – This is the highest level – debug-level messages

```shell
# IMPORTANT: gnutls-bin might be called gnutls-utils in some distros
# In debian 9, it is gnutls-bin
sudo apt-get install rsyslog gnutls-bin rsyslog-gnutls
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

### Certificates and TLS
"Certificate Authority" and "Generating the machine certificate" parts of this
section can be done entirely in your local computer where you act as CA, then you distribute
the appropriate files to target machines.
You only need remote target machine interaction when distributing.
#### Certificate Authority
It signs all of your other certificates.
The CA cert must be trusted by all clients and servers.
The private key must be well-protected and not given to any third parties.
The certificate itself can (and must) be distributed.
To generate it, do the following:
```shell
# generate the private key
sudo certtool --generate-privkey --outfile rsyslog-ca-key.pem
# now create the (self-signed) CA certificate itself
# set it to 10 years when asked
# the certificate is used to sign other certificates.
sudo certtool --generate-self-signed --load-privkey rsyslog-ca-key.pem --outfile rsyslog-ca.pem
sudo chmod 600 rsyslog-ca-key.pem
sudo chown root:root rsyslog-ca-key.pem
```
Answer the questions as follows: Use 3650 days, the certificates belongs to an authority,
the certificate be used to sign other certificates, the certificate be used to sign CRLs, enter dnsName.
You need to distribute this certificate to all peers and you need to point to it via the $DefaultNetstreamDriverCAFile config directive.
All other certificates will be issued by this CA.
**Important:** Do only distribute the ca.pem, NOT ca-key.pem (the private key).
Distributing the CA private key would totally breach security as everybody could issue new certificates on the behalf of this CA.

#### Generating the machine certificate
Each peer (be it client, server or both), needs a certificate that conveys its identity.
Access control is based on these certificates.
You can, for example, configure a server to accept connections only from configured clients.
The client ID is taken from the client instances certificate.
So as a general rule of thumb, you need to create a certificate for each instance of rsyslogd that you run.
That instance also needs the private key, so that it can properly decrypt the traffic.
Safeguard the peer’s private key file.

```shell
# generate a private key
sudo certtool --generate-privkey --outfile rsyslog-key.pem
# generate a certificate request
sudo certtool --generate-request --load-privkey rsyslog-key.pem --outfile rsyslog-request.pem
# Sign (validate, authorize) the certificate request and generate the instances certificate
# You need to have the CA’s certificate and private key for this
sudo certtool --generate-certificate --load-request rsyslog-request.pem --outfile rsyslog-cert.pem --load-ca-certificate rsyslog-ca.pem --load-ca-privkey rsyslog-ca-key.pem
sudo chmod 600 rsyslog-key.pem
sudo chown root:root rsyslog-key.pem
# verify (works for certificate pem files, not for priv keys)
certtool --certificate-info --infile rsyslog-cert.pem
sudo rm -f rsyslog-request.pem
```
Answer the `--generate-certificate` as follows: Common name: machine name (e.g. machine.example.net), it is a TLS web client certificate, it is a TLS web server certificate, not authority, if dnsName question exists it MUST be the name (or IP) of the peer in question (e.g. centralserver.example.net), see below for details.
Answer the `--generate-certificate` questions as follows: Cert does not belong to an authority;
it is a TLS web server and client certificate;
the dnsName MUST be the name of the peer in question (e.g. centralserver.example.net) -
this is the name used for authenticating the peers. Please note that you may use an IP address in dnsName.
This is a good idea if you would like to use default server authentication and you use selector lines with IP addresses (e.g. “*.* @@192.168.0.1”) -
in that case you need to select a dnsName of 192.168.0.1. But, of course, changing the server IP then requires generating a new certificate.

Do this for all target machines you need.

#### Distributing Files
Provide the target machines (rsyslog server and clients) with:
+ a copy of ca.pem (CA public key)
+ cert.pem (machine certificate)
+ key.pem (machine priv key, **not CA**)

In the target machine:
```
sudo mkdir /etc/ssl/certs-custom
sudo chmod 755 /etc/ssl/certs-custom
sudo chown root:root /etc/ssl/certs-custom
sudo mkdir /etc/ssl/private-custom
sudo chmod 700 /etc/ssl/private-custom
sudo chown root:root /etc/ssl/private-custom
```

Put ca.pem (CA public key) and cert.pem (machine certificate) into `/etc/ssl/certs-custom`,
key.pem (machine priv key, **not CA**) into `/etc/ssl/private-custom` by:
(in the local machine where you have certs and keys as the CA)
```
sudo scp file.txt username@target_machine:/remote/directory/
```

Then in the target machine:
```
sudo chmod 644 /etc/ssl/certs-custom/ca.pem
sudo chown root:root /etc/ssl/certs-custom/ca.pem
sudo chmod 644 /etc/ssl/certs-custom/cert.pem
sudo chown root:root /etc/ssl/certs-custom/cert.pem
sudo chmod 600 /etc/ssl/private-custom/key.pem
sudo chown root:root /etc/ssl/private-custom/key.pem
```

Do this for all target machines you need.

#### Cleanup
Do not forget to secure keys and certs in your local machine, where you act as a CA.
Check the file permissions, make them **owned by root, not readable by others, and
store in an encrypted container.**

### Rsyslog server config (log collector)
On the server that will collect logs:
Make a new config file: `sudo touch /etc/rsyslog.d/99-rsyslog.conf` and config to run in server mode:
```
$ModLoad imuxsock # local messages
$ModLoad imtcp # TCP listener

# make gtls driver the default
$DefaultNetstreamDriver gtls

# certificate files
$DefaultNetstreamDriverCAFile /path/to/contrib/gnutls/ca.pem
$DefaultNetstreamDriverCertFile /path/to/contrib/gnutls/cert.pem
$DefaultNetstreamDriverKeyFile /path/to/contrib/gnutls/key.pem

# $InputTCPServerStreamDriverPermittedPeer *.example.net
# $InputTCPServerStreamDriverPermittedPeer *.otherdepartment.example.net
# $InputTCPServerStreamDriverPermittedPeer *.example.com

$InputTCPServerStreamDriverMode 1 # run driver in TLS-only mode
$InputTCPServerStreamDriverAuthMode x509/name # client is authenticated
$InputTCPServerRun 10514 # start up listener at port 10514

$AllowedSender TCP, 127.0.0.1, MyPrivateIP_1, MyPrivateIP_2, MyDomain

$template remote-incoming-logs,"/var/log/%HOSTNAME%/%PROGRAMNAME%.log"
*.* ?remote-incoming-logs
& ~
```
As shown, you can also use domain name (e.g. \*.example.com). An example below:
```
$AllowedSender UDP, 192.168.43.0/24, [::1]/128, *.example.net, servera.example.com
$AllowedSender TCP, 192.168.43.0/24, [::1]/128, *.example.net, servera.example.com
```
The ``& ~`` instructs rsyslog daemon to store the log message only to a specified file.

Restart and check:
```shell
sudo rsyslogd -f /etc/rsyslog.conf -N1  # config validation
sudo systemctl restart rsyslog
sudo ss -tunelp | grep 10514
```

**Important: Allow incoming connections from client IPs on port 10514/TCP. Do not use UDP, as TLS is not possible.**

### Rsyslog client config (log forwarder)
Make a new config file: `sudo touch /etc/rsyslog.d/99-rsyslog.conf` and include:
```
$PreserveFQDN on

# Define Disk Queue Buffer in case the server goes down
$ActionQueueFileName queue # define a file name for disk assistance.
$ActionQueueMaxDiskSpace 1g  # The maximum size that all queue files together will use on disk.
$ActionQueueSaveOnShutdown on  # specifies that data should be saved at shutdown
$ActionQueueType LinkedList  # holds enqueued messages in memory which makes the process very fast.
$ActionResumeRetryCount -1  # prevents rsyslog from dropping messages when retrying to connect if server is not responding

# certificate files
$DefaultNetstreamDriverCAFile /rsyslog/protected/ca.pem
$DefaultNetstreamDriverCertFile /rsyslog/protected/machine-cert.pem
$DefaultNetstreamDriverKeyFile /rsyslog/protected/machine-key.pem

# set up the action
$DefaultNetstreamDriver gtls # use gtls netstream driver
$ActionSendStreamDriverMode 1 # require TLS for the connection
$ActionSendStreamDriverAuthMode x509/name # server is authenticated

# $ActionSendStreamDriverPermittedPeer central.example.net

# Which logs, over which protocol, to where, through which port
*.* @@(o)ip-or-domain-address-of-rsyslog-server:10514
```

Allows preservation of FQDN, handles when rsyslog server is down.
Not sure if it matters but put the line `*.* @@ip-address-of-rsysog-server:10514` at the end.
`@@` means TCP. You can replace it with a single `@` for UDP (not when using TLS). Also, you can `*.* @@fqdn-of-rsysog-server:10514`,
but don't. `*.*` at the beginning means all logs defined in rsyslog.

Restart and check:
```shell
sudo rsyslogd -f /etc/rsyslog.conf -N1  # config validation
sudo systemctl restart rsyslog
sudo ss -tunlp | grep 10514
```
**Important: Allow incoming connections from client IPs on port 10514/TCP. Do not use UDP, as TLS is not possible.**
