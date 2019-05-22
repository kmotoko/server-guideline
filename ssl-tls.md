## SSL/TLS security
Regularly check [Mozilla Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS) for updates and compatibility across devices and browsers about TLS. As of 2019, It is not wise to use TLS <= v1.1 for high security sites.
Check [SSLlabs TLS deployment best practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices).
Mozilla has a nice tool to generate TLS config file for web servers: [Mozilla SSL/TLS config generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/). Tweak the file as needed. One important factor is the OpenSSL version used in the server, as it would be a limiting factor on the ciphers and TLS versions supported.
Use [Qualys SSL Server Test](https://www.ssllabs.com/ssltest/) to see if everything properly implemented.
