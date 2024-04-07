---
status: PRODUCTION
---

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
odoo_url: https://www.v-consulting.biz
base_domain: iot.v-odoo.com
subdomains:
  - danny
```

`basedomain` and `subdomains` are daily updated through vct_iot subcription app, daily at `3:00:05 AM`, the entries in th config are just defaults in case the odoo server is not reachable on start up of the service.

`systemctl restart dns-iot.service` will reread the odoo IoT-subscriptions.


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
python3.8 dns-iot.py [-cmyconfig/file.yaml]
```

### production usage

config file in `/etc/dns-iot/dns-iot-config.yaml`

```bash
bin/build
scp dns_iot_vct-*-py3-none-any.whl vct_remote_root
```

#### Install
on server:

```bash
pip install dns_iot_vct-1.1.8-py3-none-any.whl
````

From `/usr//local/dns-iot-vct-post-install`copy config and service in place

```bash
cp /usr/local/dns-iot-vct-post-install/dns-iot.service /etc/systemd/system/dns-iot.service

mkdir -pv /etc/dns-iot
cp /usr/local/dns-iot-vct-post-install/dns-iot-config.yaml /etc/dns-iot/dns-iot-config.yaml
```

#### enable and start

```bash
systemctl enable --now dns-iot.service
```

#### check if service is running
```bash
systemctl status dns-iot.service
```

check logs with:
```bash
journalctl -u dns-iot.service
```

## Issuing certificates

to issue a new certificate we need to add a specific TXT record to the server that letsencript can check to issue a certificate.
Our dns server already can add and remove TXT records by use of the dns query TXT.

### Add and remove TXT record

**Note**: *Adding and removing records with the following method can only be done from the local server This needs ZMQ to connect to the local 127.0.0.1:5555 port for IPC, see example: (test_dns)[test_dns/dns_test.py]*

Add a TXT record with the  **`:+:`** separator of key and value, sample python code:

```python
def add_txt_record(record_name: str, record_content: str):
    context = zmq.Context()
    answer=''
    request=f'_TXT_:{record_name}:+:{record_content}'
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://127.0.0.1:5555")
    try:
        socket.send(request.encode())
    except Exception as e:
        logger.error('Encountered error adding TXT record: {0}'.format(e))
    try:
        answer = socket.recv()
    except Exception as e:
        logger.error('Encountered error adding TXT record, receive reply: {0}'.format(e))
    else:
        answer = answer.decode("utf-8")
        if answer == 'OK':
            logger.info('Successfully added TXT  %s %s', record_name,record_content)
        else:
            logger.error('Encountered error add TXT, bad reply: {0}'.format(answer)) 
    socket.close()
```

Query -> simulate lets encript:
```bash
nslookup -q=txt "_acmekey.sss.iot.v-odoo.com"
Server:		127.0.0.1
Address:	127.0.0.1#53

_acmekey.sss.iot.v-odoo.com	text = "my_new_key"
```

To Delete the TXT challence record from the *local server* , same as above add but use the **`:-:`** to delete.
Without Key, all keys are deleted for that subdomain, with key only that key is deleted.

see also [certbot-dns-vctdns](https://github.com/v-odoo-testing/certbot-dns-vctdns) for production application to get letsencrpt dns certificates.


