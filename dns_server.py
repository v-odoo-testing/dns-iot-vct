from dnslib import DNSRecord, DNSHeader, RR, QTYPE
from socketserver import UDPServer, BaseRequestHandler
import ipaddress
import yaml

global base_name
global config
global config_TXT
global config_A

config_TXT = {}
config_A = {}
config = {}

base_domain = "iot.v-odoo.com"

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

class DNSHandler(BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        request = DNSRecord.parse(data)

        #print (request)
        client,port=self.client_address

        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

        qname = request.q.qname
        qn = str(qname).lower()
        qtype = request.q.qtype
        qt = QTYPE[qtype]
        #print (f'qt={qt}')
        base_domain = "iot.v-odoo.com"

        if base_domain not in qn:
            print (f'ERROR: DNS {qt}:{qn} from {client}:{port} wrong domain: REFUSED')
            reply= DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=5), q=request.q)
        elif f".{base_domain}." not in qn:
            print (f'ERROR: DNS {qt}:{qn} from {client}:{port} wrong sub domain format NXDOMAIN')
            reply= DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=3), q=request.q)
        elif qt == "A" :
            ip_address = None
            found=False
            for key in config_A:
                if f".{key}.{base_domain}." in qn:
                    ip_address=qn.split(f".{key}.{base_domain}",1)[0].replace("-", ".")
                    try:
                        ip = ipaddress.ip_address(ip_address)
                    except ValueError:
                        pass
                    else:
                        found=True
                        print (f'INFO: DNS {qt}:{qn} from {client}:{port} -> {ip_address}')
                        reply.add_answer(*RR.fromZone(f"{qn} 5 A {ip_address}"))
            if not found:
                print (f'ERROR: DNS {qt}:{qn} from {client}:{port} wrong sub domain format NXDOMAIN')
                reply= DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=3), q=request.q)
        elif qt == "TXT":
            found=False
            for key,value in config_TXT.items():
                if qn == f"{key}.{base_domain}.":
                        found = True
                        print_value = (value[:15] + '..') if len(value) > 15 else value
                        print (f'INFO: DNS {qt}:{qn} from {client}:{port} -> {print_value}')
                        reply.add_answer(*RR.fromZone(f'{qn} 5 TXT {value}'))
            if not found:
                reply= DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=3), q=request.q)
                print (f'ERROR: DNS {qt}:{qn} from {client}:{port} wrong sub domain NXDOMAIN')
        else:
                print (f'ERROR: DNS {qt}:{qn} from {client}:{port} unsupported type')
                # NOERROR
        self.request[1].sendto(reply.pack(), self.client_address)


if __name__ == '__main__':
    
    try:
        with open('dns-config.yaml') as stream:
            config = yaml.safe_load(stream)
    except:
        pass
    try:
        HOST = config['host']
    except:
        HOST = "127.0.0.1"
    try:
        PORT = config['port']
    except:
        PORT = 53
    try:
        base_domain = config['base_domain']
    except:
        base_domain = "iot.v-odoo.com"
    print (f"->DNS server serving on {HOST}:{PORT}")
    print(f"-> dns Base Domain {base_domain}")
    with open('dns-iot-txt.yaml') as stream:
        config_TXT = yaml.safe_load(stream)
    for key in config_TXT:
        print(f"--> subdomains for TXT records {key}")

    with open('dns-iot-customer.yaml') as stream:
        config_A = yaml.safe_load(stream)
    for key in config_A:
        print(f"--> subdomains for  A  records {key}")

    with UDPServer((HOST, PORT), DNSHandler) as server:
        print(f"DNS server listening on {HOST}:{PORT}")
        server.serve_forever()