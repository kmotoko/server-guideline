## DNS Security
### DNSSEC
From ICANN:
> DNSSEC strengthens authentication in DNS using digital signatures based on public key cryptography. With DNSSEC, it's not DNS queries and responses themselves that are cryptographically signed, but rather DNS data itself is signed by the owner of the data. Every DNS zone has a public/private key pair. The zone owner uses the zone's private key to sign DNS data in the zone and generate digital signatures over that data. As the name "private key" implies, this key material is kept secret by the zone owner. The zone's public key, however, is published in the zone itself for anyone to retrieve. Any recursive resolver that looks up data in the zone also retrieves the zone's public key, which it uses to validate the authenticity of the DNS data. The resolver confirms that the digital signature over the DNS data it retrieved is valid. If so, the DNS data is legitimate and is returned to the user. If the signature does not validate, the resolver assumes an attack, discards the data, and returns an error to the user. DNSSEC adds two important features to the DNS protocol:
> 1) Data origin authentication allows a resolver to cryptographically verify that the data it received actually came from the zone where it believes the data originated.
> 2) Data integrity protection allows the resolver to know that the data hasn't been modified in transit since it was originally signed by the zone owner with the zone's private key.

From Google:
> Domain Name System Security Extensions (DNSSEC) help protect your domain from domain name server (DNS) threats, like cache poison attacks and DNS spoofing.

**Important:** Do not change your name servers while DNSSEC is enabled. If you do, your domain may not resolve.

Enable DNSSEC from your domain registrar.
Then, to verify, use the tools following: [Verisign DNSSEC Debugger](https://dnssec-debugger.verisignlabs.com/), [ViewDNS](https://viewdns.info/).

### DKIM, SPF and DMARC records
All three of them help to secure your mail exchange, also fighting spam. These can be set in the DNS settings of the registrar. Check the record keys with the external mail provider. [Yandex SPF](https://yandex.com/support/domain/set-mail/spf.html), [Yandex DKIM](https://yandex.com/support/domain/set-mail/dkim.html).
**Important:** Key length is important for the DKIM record. Regularly check if your mail external provider updates the key length so that you can set the new public key in the DNS records.
Tools to check if you properly implemented: [DKIM checker](https://www.dmarcanalyzer.com/dkim/dkim-check/), [SPF checker](https://www.dmarcanalyzer.com/spf/checker/), [DMARC checker](https://www.dmarcanalyzer.com/dmarc/dmarc-record-check/)
