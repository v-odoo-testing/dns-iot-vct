# DNS IoT VCT

## purpose

provide a domain for a local ip address so that we can requestt a certificate, allowing https comminication with errors and thus allowing us to print from odoo app to a local epos.

## check

if running local on 127.0.0.1:

```bash
$>nslookup 192-168-10-236.sss.iot.v-odoo.com 127.0.0.1
Server:		127.0.0.1
Address:	127.0.0.1#53

Name:	192-168-10-236.sss.iot.v-odoo.com
Address: 192.168.10.236
```


With a base domain `iot.v-odoo.com` as defined in the `dns-config.yaml` and subdomains as per subdomain array key:
```yaml
host: 127.0.0.1
port: 53
base_domain: iot.v-odoo.com
subdomains:
  - psa
  - sss
  - tato
```

## TXT records

test if present, see further under [Issuing Certificates](issuing_certificates) to add TXT records:

```bash
$> nslookup -q=txt _acmekey.sss.iot.v-odoo.com 127.0.0.1
Server:		127.0.0.1
Address:	127.0.0.1#53

_acmekey.sss.iot.v-odoo.com	text = "myacme" "text" "record" "data"
```

## Production setup

in order for this to work, we need to define a `NS record` on the domain server.

in our case: `v-odoo.com`is a cloud flare, so we add record:
```bash
ìot.v-odoo.com NS 600 remote.v-odoo.com
``` 
with `remote.v-odoo.com` pointing to our dns server.

From that moment in time, dns queries for domain `iot.v-odoo.com` will arive at our new dns server.


#### usage stand alone: 
```bash
python3 dns-iot.py [-c myconfig/file.yaml]
```

### production usage

config file in `/etc/dns-iot/dns-iot-config.yaml`

#### Install
```bash
cp dns-iot.py /usr/bin/
````

#### enable and start

```bash
systemctl enable --now dns-iot.service
```

check if service is running
```bash
systemctl enable --now dns-iot.service
```

check logs with:
```bash
journalctl -u dns-iot.service
```

## Issuing certificates

to issue a new certificate we need to add a specific TXT record to the server that letsencript can check to issue a certificate.
Our dns server already can add and remove TXT records by use of the dns query TXT.

### Add and remove TXT record

**Note**: *Adding and removing records with the following method can only be done from the local server*

Add a TXT record with the  **`:+:`** separator of key and value:
```bash
$>nslookup -q=txt "_acmekey.sss.iot.v-odoo.com:+:my_new_key" 127.0.0.1
Server:		127.0.0.1
Address:	127.0.0.1#53

_acmekey.sss.iot.v-odoo.com	text = "my_new_key"
```

Query -> simulate lets encript:
```bash
nslookup -q=txt "_acmekey.sss.iot.v-odoo.com"
Server:		127.0.0.1
Address:	127.0.0.1#53

_acmekey.sss.iot.v-odoo.com	text = "my_new_key"
```

Delete from the *local server* => use the **`:-:`** suffix on the txt query:
```bash
$>nslookup -q=txt "_acmekey.sss.iot.v-odoo.com:-:" 127.0.0.1
Server:		127.0.0.1
Address:	127.0.0.1#53

_acmekey.sss.iot.v-odoo.com	text = ""
```

## TODO:
 create a `certbot-dns-iot-vct` module that can update the dns server by using the **special** dns txt Query
