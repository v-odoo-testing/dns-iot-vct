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

# pylint: disable=logging-fstring-interpolation,broad-exception-caught


import _thread

# from optparse import OptionParser
import argparse
import binascii
import ipaddress
import json
import logging
import os
import time
from socketserver import BaseRequestHandler, UDPServer

import requests
import tzlocal
import yaml
import zmq
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from dnslib import QTYPE, RR, DNSHeader, DNSRecord

config = {}
ODOO_API = "/vct_iot_subscription/list"

ODOO_URL = "https://www.v-consulting.biz"
BASE_NAME = "iot.v-odoo.com"
BASE_DNS = None
BASE_EMAIL = None
BASE_AAC_URI = None
HOST = "127.0.0.1"
PORT = 53
LOG_LEVEL = "info"

SUB_DOMAINS = None

CONFIG_SUBDOMAINS = None
BASE_DOMAIN = None
CONFIG_TXT_RECORDS = []


class DomainName(str):
    """Class representing doname name change"""

    def __getattr__(self, item):
        return DomainName(item + "." + self)


class DNSHandler(BaseRequestHandler):
    """Class handling the DNS"""

    def _refused(self, query_name, query_type, request):
        client, port = self.client_address
        logging.error(f" DNS {query_type}:{query_name} from HOST:{client}:{port} wrong domain")
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=5), q=request.q)
        return reply

    def _nxdomain(self, query_name, query_type, request):
        client, port = self.client_address
        logging.error(f"DNS {query_type}:{query_name} from HOST:{client}:{port} wrong sub domain")
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=3), q=request.q)
        return reply

    def _formerr(self, data):
        client, port = self.client_address
        request_id = data[0] * 256 + data[1]
        logging.error(
            f"DNS {binascii.hexlify(bytearray(data))}from HOST:{client}:{port} \
                DNS Query Format Error"
        )
        reply = DNSRecord(DNSHeader(id=request_id, qr=1, aa=1, ra=1, rcode=1), q="")
        return reply

    def _handle_SOA_record(self, query_name, query_type, request, reply, passthrough=False):
        client, port = self.client_address
        if f"{BASE_DOMAIN}." == query_name and BASE_DNS and BASE_EMAIL:
            logging.info(f"DNS {query_type}:{query_name} from HOST:{client}:{port}")
            reply.add_answer(
                *RR.fromZone(
                    f"{query_name} IN SOA {BASE_DNS} {BASE_EMAIL} 1 7200 900 1209600 86400"
                )
            )
        elif not passthrough:
            reply = self._nxdomain(query_name, query_type, request)
        return reply

    def _handle_CAA_record(self, query_name, query_type, request, reply, passthrough=False):
        client, port = self.client_address
        if f"{BASE_DOMAIN}." == query_name:
            logging.info(f"DNS {query_type}:{query_name} from HOST:{client}:{port}")
            reply.add_answer(
                *RR.fromZone(
                    f'{query_name} IN CAA 0 issue "letsencrypt.org;validationmethods=dns-01"'
                )
            )
            reply.add_answer(*RR.fromZone(f'{query_name} IN CAA 0 issuewild "letsencrypt.org"'))
            if BASE_AAC_URI:
                reply.add_answer(
                    *RR.fromZone(
                        f'{query_name} IN CAA 128 issue "letsencrypt.org;accounturi={BASE_AAC_URI}"'
                    )
                )
        elif not passthrough:
            reply = self._nxdomain(query_name, query_type, request)
        return reply

    def _handle_subdomains(self, query_name, query_type, request, reply, passthrough=False):
        ip_address = None
        client, port = self.client_address
        # Find the key that matches the query_name using list comprehension
        matching_key = next(
            (key for key in CONFIG_SUBDOMAINS if f".{key}.{BASE_DOMAIN}." in query_name), None
        )

        # If matching_key is found, perform the magic
        if matching_key is not None:
            # here happens the magic
            ip_address = query_name.split(f".{matching_key}.{BASE_DOMAIN}", 1)[0].replace("-", ".")
            try:
                ip_check = ipaddress.ip_address(ip_address)
            except ValueError:
                pass
            else:
                logging.info(
                    f"DNS {query_type}:{query_name} from HOST:{client}:{port} -> {ip_check}"
                )
                if query_type == "A":
                    reply.add_answer(*RR.fromZone(f"{query_name} 86400 A {ip_address}"))
                else:
                    reply.add_answer(
                        *RR.fromZone(
                            f"{query_name} 1800 IN HTTPS 1 . alpn=http/1.0 ipv4hint={ip_address}"
                        )
                    )
        elif not passthrough:
            reply = self._nxdomain(query_name, query_type, request)
        return reply

    def _handle_TXT_record(self, query_name, query_type, request, reply, passthrough=False):
        found = False
        client, port = self.client_address
        prefix = None
        for short in CONFIG_SUBDOMAINS:
            if f".{short}.{BASE_DOMAIN}." in query_name:
                prefix = short
        if prefix:
            for key_value in CONFIG_TXT_RECORDS:
                key = query_name.split(f".{BASE_DOMAIN}", 1)[0]
                try:
                    value = key_value[key]
                except KeyError:
                    pass
                else:
                    found = True
                    # print_value = (value[:15] + "..") if len(value) > 15 else value
                    print_value = value
                    logging.info(
                        f" DNS {query_type}:{query_name} from HOST:{client}:{port} -> {print_value}"
                    )
                    reply.add_answer(*RR.fromZone(f"{query_name} 60 TXT {value}"))
        if not found and not passthrough:
            reply = self._nxdomain(query_name, query_type, request)
        return reply

    def handle(self):
        """
        DNS QUERY Handler
        """
        data = self.request[0]  # .strip()
        try:
            request = DNSRecord.parse(data)
        except Exception:
            reply = self._formerr(data)
            self.request[1].sendto(reply.pack(), self.client_address)
            return

        client, port = self.client_address

        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

        qname = request.q.qname
        query_name = str(qname).lower()
        qtype = request.q.qtype
        query_type = QTYPE[qtype]

        handlers = {
            "ANY": [
                (self._handle_SOA_record, "SOA"),
                (self._handle_CAA_record, "CAA"),
                (self._handle_subdomains, "A"),
                (self._handle_subdomains, "HTTPS"),
                (self._handle_TXT_record, "TXT"),
            ],
            "SOA": [(self._handle_SOA_record, "SOA")],
            "CAA": [(self._handle_CAA_record, "CAA")],
            "A": [(self._handle_subdomains, "A")],
            "HTTPS": [(self._handle_subdomains, "HTTPS")],
            "TXT": [(self._handle_TXT_record, "TXT")],
        }

        for query_type_key, handler_list in handlers.items():
            if query_type == query_type_key:
                for handler, handler_query_type in handler_list:
                    reply = handler(
                        query_name, handler_query_type, request, reply, query_type_key == "ANY"
                    )
                break
        else:
            logging.error(
                f"DNS {query_type}:{query_name} from HOST:{client}:{port} unsupported type"
            )

        self.request[1].sendto(reply.pack(), self.client_address)


class ZMQHandler:
    """
    Class handling the ZMQ communications
    """

    def __init__(self, url="tcp://127.0.0.1:5555"):
        self.socket = None
        self.url = url

    def __exit__(self, exc_type, exc_value, traceback):
        print("Danny __exit__")
        if self.socket:
            self.socket.close()

    def __enter__(self):
        print("Danny __enter__")
        context = zmq.Context()
        self.socket = context.socket(zmq.REP)
        self.socket.bind(self.url)
        logging.info("ipc server init")
        return self

    def serve(self):
        """
        Main IPC ZMQ serve loop
        """
        logging.info("ipc server listening")

        while True:
            #  Wait for next request from client
            message = self.socket.recv()
            message = message.decode("utf-8")
            logging.debug("Received request: %s", message)
            if "_TXT_:" in message:
                self.handle_ipc_message(message, "_TXT_:", self.handle_txt_modif)
            elif "__A__:" in message:
                self.handle_ipc_message(message, "__A__:", self.handle_a_modif)
            else:
                self.socket.send(b"???: request not understood")

    def handle_ipc_message(self, message, prefix, handler):
        """
        common Handler of the record modification from IPC handler
        """
        error_messages = {
            "wrong domain": lambda q: BASE_DOMAIN not in q,
            "wrong subdomain": lambda q: f".{BASE_DOMAIN}" not in q,
        }
        query = message.split(prefix)[1]
        error = next(
            (error_msg for error_msg, condition in error_messages.items() if condition(query)),
            None,
        )
        if error:
            self.socket.send(f"FAIL: {error}".encode())
        elif handler(query):
            self.socket.send(b"OK")
        else:
            self.socket.send(b"FAIL")

    def handle_txt_modif(self, query_name):
        """
        Handles the text record modification for the certbot dns
        """
        if ":+:" in query_name:
            split_query_name = query_name.split(":+:")
            query_name_clean = split_query_name[0]
            key = query_name_clean.split(f".{BASE_DOMAIN}")[0]
            value = split_query_name[1]
            key_value = {}
            key_value[key] = value
            CONFIG_TXT_RECORDS.append(key_value)
            # print_value = (value[:15] + "..") if len(value) > 15 else value
            print_value = value
            logging.info(f"TXT KEY  ADDED  ->{key}: '{print_value}'")
        elif ":-:" in query_name:
            key, value = self._remove_key_value(query_name)
            if key is not None:
                if value:
                    logging.info(" DNS TXT KEY/VALUE REMOVED -> '%s': '%s'", key, value)
                else:
                    logging.info(" DNS TXT KEY REMOVED -> '%s'", key)
            else:
                split_query_name = query_name.split(":-:")
                logging.error(
                    f" KEY '{split_query_name[0]}': '{value}' to remove not found in list"
                )
            return False
        else:
            return False
        return True

    def _remove_key_value(self, query_name):
        """
        remove a txt key or all txt records for specific subdomain from the CONFIG_TXT_RECORDS
        """
        # Extract key and value from query_name
        split_query_name = query_name.split(":-:")
        key = split_query_name[0].split(f".{BASE_DOMAIN}", 1)[0]
        value = split_query_name[1] if len(split_query_name) > 1 else None

        # Find prefix from CONFIG_SUBDOMAINS
        prefix = None
        for short in CONFIG_SUBDOMAINS:
            if f".{short}.{BASE_DOMAIN}" in query_name:
                prefix = short
                break

        # Remove key/value from CONFIG_TXT_RECORDS
        if prefix:
            for key_value in CONFIG_TXT_RECORDS[:]:
                if key_value[key] and ((value and key_value[key] == value) or not value):
                    CONFIG_TXT_RECORDS.remove(key_value)
                    return key, value
        return None, None

    def handle_a_modif(self, query_name):
        """
        Handles dynamical adding or removing authorized subdomains
        """
        if ":+:" in query_name:
            split_query_name = query_name.split(":+:")
            query_name_clean = split_query_name[0]
            key = query_name_clean.split(f".{BASE_DOMAIN}")[0]
            if key not in CONFIG_SUBDOMAINS:
                CONFIG_SUBDOMAINS.append(key)
                logging.info(f"SUBDOMAIN ADDED  ->{key}")
            else:
                logging.info(f"SUBDOMAIN ALREADY IN ->{key}")
        elif ":-:" in query_name:
            split_query_name = query_name.split(":-:")
            key = split_query_name[0].split(f".{BASE_DOMAIN}", 1)[0]
            if key != "*":
                if key in CONFIG_SUBDOMAINS:
                    CONFIG_SUBDOMAINS.remove(key)
                    logging.info(" DNS SUBDOMAIN REMOVED ->'%s'", key)
                else:
                    logging.error(" DNS  SUBDOMAIN NOT FOUND: '%s'", key)
                    return False
            else:
                for single_key in CONFIG_SUBDOMAINS[:]:
                    CONFIG_SUBDOMAINS.remove(single_key)
                logging.info("ALL DNS SUBDOMAINS REMOVED")
        else:
            return False
        return True


def get_subscription_list():
    """
    Thread / app scheduler to update allowed subdomains
    """

    url = f"{ODOO_URL}{ODOO_API}"
    try:
        response = requests.get(url, timeout=60)

    except requests.exceptions.ConnectionError as errc:
        logging.error("Error Connecting: %s", errc)
    except requests.exceptions.Timeout as errt:
        logging.error("Timeout Error: %s", errt)
    except requests.exceptions.RequestException as err:
        logging.error("Request error: %s", err)
    except Exception as msg:
        logging.error(" -> DNS Error retrieving subscriptions: %s", msg)
    else:
        if response.status_code == 200:
            response_data = json.loads(response.text)
            try:
                iot_domain = response_data["iot_domain"]
                globals()["BASE_DOMAIN"] = iot_domain
                logging.info(" --> DNS ODOO update Base Domain: %s", BASE_DOMAIN)
            except KeyError:
                pass
            try:
                sub_domains = response_data["sub_domains"]
                globals()["CONFIG_SUBDOMAINS"] = sub_domains
                logging.info(" --> DNS ODOO update Subdomains: %s", CONFIG_SUBDOMAINS)
            except KeyError:
                pass
        else:
            logging.error(
                " -> DNS Error retrieving subscriptions: %s %s",
                response.status_code,
                response.reason,
            )


def dns_thread():
    """
    Thread for dns handling
    """
    try:
        with UDPServer((HOST, PORT), DNSHandler) as server:
            logging.info("DNS server listening on %s:%s", HOST, PORT)
            server.serve_forever()
    except Exception as msg:
        logging.error("Socket binding error: %s\nExit...", str(msg))
        os._exit(1)


def ipc_thread():
    """
    Thread for IPC ZMQ comminication
    """
    try:
        with ZMQHandler() as server:
            server.serve()
    except Exception as msg:
        logging.error("Socket binding error: %s\nExit...", str(msg))
        os._exit(1)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config_file",
        "-c",
        default="/etc/dns-iot/dns-iot-config.yaml",
        help="config file for dns-iot",
    )
    args = parser.parse_args()

    config_file = args.config_file

    try:
        with open(config_file, encoding="utf-8") as stream:
            config = yaml.safe_load(stream)
    except OSError:
        pass

    configurations = {
        "host": HOST,
        "port": PORT,
        "odoo_url": ODOO_URL,
        "log_level": LOG_LEVEL,
        "base_domain": BASE_NAME,
        "base_dns": BASE_DNS,
        "base_email": BASE_EMAIL,
        "base_acc_uri": BASE_AAC_URI,
        "subdomains": SUB_DOMAINS,
    }

    for key, value in configurations.items():
        try:
            configurations[key] = config[key]
        except KeyError:
            pass

    HOST, PORT, ODOO_URL, LOG_LEVEL, BASE_NAME, BASE_DNS, BASE_EMAIL, BASE_AAC_URI, SUB_DOMAINS = (
        configurations.values()
    )

    # if LOG_LEVEL in "DEBUG":
    #     logging.basicConfig(level=logging.DEBUG,format='%(module)s-%(funcName)s: %(message)s')
    #     logging.debug("Debug level logging started")
    # else:
    logging.basicConfig(level=logging.INFO)
    logging.info(f" -> DNS with config : {config_file}")
    logging.info(f" -> DNS server serving on {HOST}:{PORT}")

    logging.info(f" -> Get Subscriptions from '{ODOO_URL}'")
    get_subscription_list()
    # if on start up this failed, get the defaults or the values form the CONFIG File
    if not BASE_DOMAIN:
        BASE_DOMAIN = BASE_NAME

    if not CONFIG_SUBDOMAINS:
        CONFIG_SUBDOMAINS = SUB_DOMAINS

    logging.info(f" -> with DNS Base Domain: {BASE_DOMAIN}")
    for a_key in CONFIG_SUBDOMAINS:
        logging.info(f" --> DNS with subdomains for  A  records {a_key}")

    _thread.start_new_thread(dns_thread, ())
    _thread.start_new_thread(ipc_thread, ())

    scheduler = BackgroundScheduler()

    # for daily Update

    scheduler.start()
    trigger = CronTrigger(
        year="*",
        month="*",
        day="*",
        hour="3",
        minute="0",
        second="5",
        timezone=str(tzlocal.get_localzone()),
    )

    scheduler.add_job(
        get_subscription_list,
        trigger=trigger,
        name="daily subscription update",
    )

    while True:
        time.sleep(100)
