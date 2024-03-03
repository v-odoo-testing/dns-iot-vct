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

with `sss`being the customer defined in the `dns-iot-customer.yaml`
```yaml
- psa
- sss
- tato
```

and with a base domain `iot.v-odoo.com` as defined in the `dns-config.yaml`:
```yaml
host: 127.0.0.1
port: 53
base_domain: iot.v-odoo.com
```

## TXT records

TXT records are defned in `dns-iot-txt.yaml`
```yaml
_acmekey.sss: myacme text record data
```

test:
```bash
$> nslookup -q=txt _acmekey.sss.iot.v-odoo.com 127.0.0.1
Server:		127.0.0.1
Address:	127.0.0.1#53

_acmekey.sss.iot.v-odoo.com	text = "myacme" "text" "record" "data"
```

## Production setup

in order for this to work, we need to define a `NS record` on the domain server.

in our case: `v-odoo.com`is a cloud flare, so we add record:
```
ìot.v-odoo.com NS 600 remote.v-odoo.com
``` 
with `remote.v-odoo.com`pointing to our dns server.

from that moment in time, dns queries for domain `iot.v-odoo.com` will arive at our new dns server.

TODO:
- use logger for messages
- create systemd service
- add command line options for config file location.

## Issuing certificates

update the `dns-iot-txt.yaml` with the challenge and restart our dns server.

### TODO:
 create an `certbot-dns-iot-vct` module that can update and restart/reload the dns server 