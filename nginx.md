## Nginx
```shell
sudo apt update
sudo apt install nginx
sudo systemctl enable nginx
```
By default, nginx serves files from `/var/www/html` dir. It is highly recommended to configure nginx with the *server blocks* (apache equivalent: *virtual host*), which allow a single web server to serve multiple websites if needed.
+ Credentials Storage Location/SSL certificate: `mkdir /root/certs/example.com/`, move your certificate(s) and key(s) into that folder.
Restrict permissions on the key file: `chmod 400 /root/certs/example.com/example.com.key`.
+ A Diffie-Hellman parameter is a set of randomly generated data used when establishing Perfect Forward Secrecy during initiation of an HTTPS connection. The default size is usually 1024 or 2048 bits, depending on the server’s OpenSSL version, but a 4096 bit key will provide greater security.
```
cd /root/certs/example.com
openssl genpkey -genparam -algorithm DH -out /root/certs/example.com/dhparam4096.pem -pkeyopt dh_paramgen_prime_len:4096
```

Generate configs like:
+ Create root directory at `/var/www/example.com/`
+ Create and config `/etc/nginx/conf.d/example.com.conf`
```
server {
    listen              <public_ipv4>:80;
    listen              [<public_ipv6>]:80;
    server_name         example.com www.example.com;
    return 301          https://example.com$request_uri;
    return 301          https://www.example.com$request_uri;
    }

server {
    listen              <public_ipv4>:443 ssl http2 default_server;
    listen              [<public_ipv6>]:443 ssl http2 default_server;
    server_name         example.com www.example.com;
    root                /var/www/example.com;
    index               index.html;

    location / {
         proxy_cache    one;
            proxy_pass  http://localhost:8000;
    }

    gzip             on;
    gzip_comp_level  3;
    gzip_types       text/plain text/css application/javascript image/*;
}
```
+ Changes we want nginx to apply universally are in the http block of `/etc/nginx/nginx.conf`:
Static content compression: Enable `gzip` compression only for certain content (images, HTML, and CSS). Do not do this for other file types as it might lead to exploits (CRIME and BREACH).
Disable server tokens to remove nginx version display to public. Unlike other directives, an add_header directive is not inherited from parent configuration blocks. If you have the directive in both, an add_header directive in a server block will override any in your http area. Replace ip-address and port with the URL and port of the upstream service whose files you wish to cache. For example, you would fill in 127.0.0.1:9000 if using WordPress. Directives you want NGINX to apply to all sites on your server should go into the http block of nginx.conf, including SSL/TLS directives. The directives below assume one website, or all sites on the server, using the same certificate and key. .pem format can also be used. SSL/TLS handshakes use a non-negligible amount of CPU power, so minimizing the amount of handshakes which connecting clients need to perform will reduce your system’s processor use. One way to do this is by increasing the duration of keepalive connections from 60 to 75 seconds. Maintain a connected client’s SSL/TLS session for 10 minutes before needing to re-negotiate the connection. OCSP Stapling, when enabled, NGINX will make OCSP requests on behalf of connecting browsers. The response received from the OCSP server is added to NGINX’s browser response, which eliminates the need for browsers to verify a certificate’s revocation status by connecting directly to an OCSP server.


```
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;

    server_tokens       off;
    keepalive_timeout   75;

    add_header          Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header          X-Content-Type-Options nosniff;
    add_header          X-Frame-Options SAMEORIGIN;
    add_header          X-XSS-Protection "1; mode=block";

    ssl_certificate     /root/certs/example.com/example.com.crt;
    ssl_certificate_key /root/certs/example.com/example.com.key;
    ssl_ciphers         ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_dhparam         /root/certs/example.com/dhparam4096.pem;
    ssl_prefer_server_ciphers on;
    ssl_protocols       TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /root/certs/example.com/cert.crt;

    proxy_cache_path /var/www/example.com/cache/ keys_zone=one:10m inactive=60m use_temp_path=off;
}
```
`sudo nginx -s reload`
`openssl s_client -connect example.org:443 -tls1 -tlsextdebug -status`
The return response should show a field of OCPS response data.
