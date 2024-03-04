#!/usr/bin/python3
"""
DNS server for iot to serve multiple subdomains from the base subdomain,
converting formated subdomain to an ip address.

f.i. 192-168-1-2.xxxx.iot.v-odoo.com will return a A record of 192.168.1.2

this is needed to create certificates to access local network resources by https.

to facilitate the issue of certificates, we can add txt recors by dns text query:

- add:
   nslookup -q=txt "_acmekey.sss.iot.v-odoo.com:+:my_new_key_value" 127.0.0.1
- query:
   nslookup -q=txt "_acmekey.sss.iot.v-odoo.com"
- delete:
   nslookup -q=txt "_acmekey.sss.iot.v-odoo.com:-:" 127.0.0.1

adding and deleting is only served on 127.0.0.1, not on public ip

To enable this server, add a NS record for a subdomain pointing to this server.

Don't forget to open firewall on port 53/udp
"""

# pylint: disable=deprecated-module, logging-fstring-interpolation
# pylint: disable+=broad-exception-caught

import logging
from optparse import OptionParser
import ipaddress
from socketserver import UDPServer, BaseRequestHandler
import yaml
from dnslib import DNSRecord, DNSHeader, RR, QTYPE

BASE_NAME = ""
config = {}
config_A = {}
config_TXT = {}

class DomainName(str):
    """Class representing doname name change"""

    def __getattr__(self, item):
        return DomainName(item + "." + self)


class DNSHandler(BaseRequestHandler):
    """Class handling the DNS"""

    def _refused(self, query_name, query_type, request):
        client, port = self.client_address
        logging.error(f" DNS {query_type}:{query_name} from HOST:{client}:{port} wrong domain: REFUSED")
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=5), q=request.q
        )
        return reply

    def _nxdomain(self, query_name, query_type, request):
        client, port = self.client_address
        logging.error(
            f"DNS {query_type}:{query_name} from HOST:{client}:{port} wrong sub domain format NXDOMAIN"
        )
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=3), q=request.q
        )
        return reply

    def _handle_a_record(self, query_name, query_type, request, reply):
        ip_address = None
        client, port = self.client_address
        found = False
        for key in config_A:
            if f".{key}.{BASE_NAME}." in query_name:
                # here happens the magic
                ip_address = query_name.split(f".{key}.{BASE_NAME}", 1)[0].replace("-", ".")
                try:
                    ip_check = ipaddress.ip_address(ip_address)
                except ValueError:
                    pass
                else:
                    found = True
                    logging.info(
                        f"DNS {query_type}:{query_name} from HOST:{client}:{port} -> {ip_check}"
                        )
                    reply.add_answer(*RR.fromZone(f"{query_name} 5 A {ip_address}"))
        if not found:
            reply = self._nxdomain(query_name, query_type, request)
        return reply

    def _handle_txt(self, query_name, query_type, request, reply):
        found = False
        client, port = self.client_address
        for key, value in config_TXT.items():
            if query_name == f"{key}.{BASE_NAME}.":
                found = True
                print_value = (value[:15] + "..") if len(value) > 15 else value
                logging.info(
                    f" DNS {query_type}:{query_name} from HOST:{client}:{port} -> {print_value}"
                    )
                reply.add_answer(*RR.fromZone(f"{query_name} 5 TXT {value}"))
        if not found:
            reply = self._nxdomain(query_name, query_type, request)
        return reply

    def _handle_txt_modif(self, query_name, request, reply):
        # use TXT dns query to add or remove a TXT record from our dns server,
        # only possible from local 127.0.0.1 client
        if ":+:" in query_name:
            split_query_name = query_name.split(":+:")
            query_name_clean = split_query_name[0]
            key = query_name_clean.split(f".{BASE_NAME}")[0]
            value = split_query_name[1][:-1]
            config_TXT[key] = value
            reply.add_answer(*RR.fromZone(f"{query_name_clean} 5 TXT {value}"))
            print_value = (value[:15] + "..") if len(value) > 15 else value
            logging.info(f"TXT KEY  ADDED  ->{key}: '{print_value}'")
        else:
            split_query_name = query_name.split(":-:")
            key = split_query_name[0].split(f".{BASE_NAME}")[0]
            try:
                del config_TXT[key]
                reply.add_answer(*RR.fromZone(f"{split_query_name[0]} 5 TXT ''"))
                logging.info(f" DNS TXT KEY REMOVED ->{key}")
            except Exception:
                reply = DNSRecord(
                    DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=5),
                    q=request.q,
                )
                logging.error(f" KEY '{key}' to remove not found in list")
        return reply

    def handle(self):
        data = self.request[0].strip()
        request = DNSRecord.parse(data)
        client, port = self.client_address

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        qname = request.q.qname
        query_name = str(qname).lower()
        qtype = request.q.qtype
        query_type = QTYPE[qtype]

        if BASE_NAME not in query_name:
            reply = self._refused(query_name, query_type, request)

        elif f".{BASE_NAME}" not in query_name:
            reply = self._nxdomain(query_name, query_type, request)

        elif query_type == "A":
            reply = self._handle_a_record(query_name, query_type, request, reply)

        elif query_type == "TXT":

            if (":-:" in query_name or ":+:" in query_name) and client == "127.0.0.1":
                reply = self._handle_txt_modif(query_name, request, reply)
            else:
                reply = self._handle_txt(query_name, query_type, request, reply)

        else:
            logging.error(f" DNS {query_type}:{query_name} from HOST:{client}:{port} unsupported type")
        self.request[1].sendto(reply.pack(), self.client_address)


if __name__ == "__main__":

    CONFIG_FILE = ""
    parser = OptionParser()
    parser.add_option("-c")
    options, args = parser.parse_args()
    CONFIG_FILE = options.c
    if not CONFIG_FILE:
        CONFIG_FILE = "dns-iot-config.yaml"

    try:
        with open(CONFIG_FILE,encoding="utf-8") as stream:
            config = yaml.safe_load(stream)
    except Exception:
        pass
    try:
        HOST = config["host"]
    except Exception:
        HOST = "127.0.0.1"
    try:
        PORT = config["port"]
    except Exception:
        PORT = 53
    try:
        BASE_NAME = config["base_domain"]
    except Exception:
        BASE_NAME = "iot.v-odoo.com"

    LOG_LEVEL = "info"
    try:
        LOG_LEVEL = config["log_level"]
    except Exception:
        pass

    # if LOG_LEVEL in "DEBUG":
    #     logging.basicConfig(level=logging.DEBUG,format='%(module)s-%(funcName)s: %(message)s')
    #     logging.debug("Debug level logging started")
    # else:
    logging.basicConfig(
        level=logging.INFO
    )  # ,format='%(module)s-%(funcName)s: %(message)s')
    logging.info(f" -> DNS with config : {CONFIG_FILE}")
    logging.info(f" -> DNS server serving on {HOST}:{PORT}")
    logging.info(f" -> with DNS Base Domain: {BASE_NAME}")

    try:
        config_A = config["subdomains"]
    except Exception:
        pass

    for a_key in config_A:
        logging.info(f" --> DNS with subdomains for  A  records {a_key}")

    with UDPServer((HOST, PORT), DNSHandler) as server:
        logging.info(f"DNS server listening on {HOST}:{PORT}")
        server.serve_forever()
