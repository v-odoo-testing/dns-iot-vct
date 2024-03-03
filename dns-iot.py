#!/usr/bin/python3
import logging
from optparse import OptionParser
import ipaddress
from socketserver import UDPServer, BaseRequestHandler
import yaml
from dnslib import DNSRecord, DNSHeader, RR, QTYPE

global base_name
global config
global config_TXT
global config_A

config_TXT = {}
config_A = {}
config = {}

base_domain = ""


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + "." + self)


class DNSHandler(BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        request = DNSRecord.parse(data)

        # print (request)
        client, port = self.client_address

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        qname = request.q.qname
        qn = str(qname).lower()
        qtype = request.q.qtype
        qt = QTYPE[qtype]
        # print (f'qt={qt}')
        base_domain = "iot.v-odoo.com"
        if (
            qt == "TXT"
            and (":-:" in qn or ":+:" in qn)
            and base_domain in qn
            and client == "127.0.0.1"
        ):
            # use TXT dns query to add or remove a TXT record from our dns server,
            # only possible from local 127.0.0.1 client
            if ":+:" in qn:
                split_qn = qn.split(":+:")
                qn_clean = split_qn[0]
                key = split_qn[0].split(f".{base_domain}")[0]
                value = split_qn[1][:-1]
                config_TXT[key] = value
                reply.add_answer(*RR.fromZone(f"{qn_clean} 5 TXT {value}"))
                print_value = (value[:15] + "..") if len(value) > 15 else value
                logging.info(f"TXT KEY  ADDED  ->{key}: '{print_value}'")
            else:
                split_qn = qn.split(":-:")
                key = split_qn[0].split(f".{base_domain}")[0]
                try:
                    del config_TXT[key]
                    reply.add_answer(*RR.fromZone(f"{split_qn[0]} 5 TXT ''"))
                    logging.info(f" DNS TXT KEY REMOVED ->{key}")
                except:
                    reply = DNSRecord(
                        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=5),
                        q=request.q,
                    )
                    logging.error(f" KEY '{key}' to remove not found in list")
        elif base_domain not in qn:
            logging.error(f" DNS {qt}:{qn} from {client}:{port} wrong domain: REFUSED")
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=5), q=request.q
            )
        elif f".{base_domain}." not in qn:
            logging.error(
                f"DNS {qt}:{qn} from {client}:{port} wrong sub domain format NXDOMAIN"
            )
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=3), q=request.q
            )
        elif qt == "A":
            ip_address = None
            found = False
            for key in config_A:
                if f".{key}.{base_domain}." in qn:
                    # here happens the magic
                    ip_address = qn.split(f".{key}.{base_domain}", 1)[0].replace(
                        "-", "."
                    )
                    try:
                        ip = ipaddress.ip_address(ip_address)
                    except ValueError:
                        pass
                    else:
                        found = True
                        logging.info(
                            f"DNS {qt}:{qn} from {client}:{port} -> {ip_address}"
                        )
                        reply.add_answer(*RR.fromZone(f"{qn} 5 A {ip_address}"))
            if not found:
                logging.error(
                    f"DNS {qt}:{qn} from {client}:{port} wrong sub domain format NXDOMAIN"
                )
                reply = DNSRecord(
                    DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=3),
                    q=request.q,
                )
        elif qt == "TXT":
            found = False
            for key, value in config_TXT.items():
                if qn == f"{key}.{base_domain}.":
                    found = True
                    print_value = (value[:15] + "..") if len(value) > 15 else value
                    logging.info(
                        f" DNS {qt}:{qn} from {client}:{port} -> {print_value}"
                    )
                    reply.add_answer(*RR.fromZone(f"{qn} 5 TXT {value}"))
            if not found:
                reply = DNSRecord(
                    DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=3),
                    q=request.q,
                )
                logging.error(
                    f"DNS {qt}:{qn} from {client}:{port} wrong sub domain NXDOMAIN"
                )
        else:
            logging.error(f" DNS {qt}:{qn} from {client}:{port} unsupported type")
            # NOERROR
        self.request[1].sendto(reply.pack(), self.client_address)


if __name__ == "__main__":
    config_file = ""
    parser = OptionParser()
    parser.add_option("-c")
    options, args = parser.parse_args()
    config_file = options.c
    if not config_file:
        config_file = "dns-iot-config.yaml"

    try:
        with open(config_file) as stream:
            config = yaml.safe_load(stream)
    except:
        pass
    try:
        HOST = config["host"]
    except:
        HOST = "127.0.0.1"
    try:
        PORT = config["port"]
    except:
        PORT = 53
    try:
        base_domain = config["base_domain"]
    except:
        base_domain = "iot.v-odoo.com"

    log_level = "info"
    try:
        log_level = config["log_level"]
    except:
        pass

    # if log_level in "DEBUG":
    #     logging.basicConfig(level=logging.DEBUG,format='%(module)s-%(funcName)s: %(message)s')
    #     logging.debug("Debug level logging started")
    # else:
    logging.basicConfig(
        level=logging.INFO
    )  # ,format='%(module)s-%(funcName)s: %(message)s')
    logging.info(f" -> DNS with config : {config_file}")
    logging.info(f" -> DNS server serving on {HOST}:{PORT}")
    logging.info(f" -> with DNS Base Domain: {base_domain}")

    try:
        config_A = config["subdomains"]
    except:
        pass

    for key in config_A:
        logging.info(f" --> DNS with subdomains for  A  records {key}")

    with UDPServer((HOST, PORT), DNSHandler) as server:
        logging.info(f"DNS server listening on {HOST}:{PORT}")
        server.serve_forever()
