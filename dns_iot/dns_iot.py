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

# TODO need to do some more linting fixes
# pylint: disable=logging-fstring-interpolation,broad-exception-caught


import os
import logging

# from optparse import OptionParser
import argparse
import ipaddress
from socketserver import UDPServer, BaseRequestHandler
import binascii
import _thread
import time
import json

import yaml
from dnslib import DNSRecord, DNSHeader, RR, QTYPE
import tzlocal
import zmq
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

ODOO_URL = "https://www.v-consulting.biz"
ODOO_API = "/vct_iot_subscription/list"
BASE_NAME = "iot.v-odoo.com"
HOST = "127.0.0.1"
PORT = 53
LOG_LEVEL = "info"

config = {}
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
        logging.error(
            f" DNS {query_type}:{query_name} from HOST:{client}:{port} wrong domain"
        )
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=5), q=request.q
        )
        return reply

    def _nxdomain(self, query_name, query_type, request):
        client, port = self.client_address
        logging.error(
            f"DNS {query_type}:{query_name} from HOST:{client}:{port} wrong sub domain"
        )
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=3), q=request.q
        )
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

    def _handle_a_record(self, query_name, query_type, request, reply):
        ip_address = None
        client, port = self.client_address
        found = False
        for key in CONFIG_SUBDOMAINS:
            if f".{key}.{BASE_DOMAIN}." in query_name:
                # here happens the magic
                ip_address = query_name.split(f".{key}.{BASE_DOMAIN}", 1)[0].replace(
                    "-", "."
                )
                try:
                    ip_check = ipaddress.ip_address(ip_address)
                except ValueError:
                    pass
                else:
                    found = True
                    logging.info(
                        f"DNS {query_type}:{query_name} from HOST:{client}:{port} -> {ip_check}"
                    )
                    reply.add_answer(*RR.fromZone(f"{query_name} 86400 A {ip_address}"))
        if not found:
            reply = self._nxdomain(query_name, query_type, request)
        return reply

    def _handle_txt(self, query_name, query_type, request, reply):
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
        if not found:
            reply = self._nxdomain(query_name, query_type, request)
        return reply

    def handle(self):
        data = self.request[0]  # .strip()
        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            print(e)
            reply = self._formerr(data)
            self.request[1].sendto(reply.pack(), self.client_address)
            return

        client, port = self.client_address

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        qname = request.q.qname
        query_name = str(qname).lower()
        qtype = request.q.qtype
        query_type = QTYPE[qtype]

        if BASE_DOMAIN not in query_name:
            reply = self._refused(query_name, query_type, request)

        elif f".{BASE_DOMAIN}" not in query_name:
            reply = self._nxdomain(query_name, query_type, request)

        elif query_type == "A":
            reply = self._handle_a_record(query_name, query_type, request, reply)

        elif query_type == "TXT":
            reply = self._handle_txt(query_name, query_type, request, reply)

        else:
            logging.error(
                f" DNS {query_type}:{query_name} from HOST:{client}:{port} unsupported type"
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
            (
                error_msg
                for error_msg, condition in error_messages.items()
                if condition(query)
            ),
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
                if key_value[key] and (
                    (value and key_value[key] == value) or not value
                ):
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

    CONFIG_FILE = ""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config_file",
        "-c",
        default="/etc/dns-iot/dns-iot-config.yaml",
        help="config file for dns-iot",
    )
    args = parser.parse_args()
    CONFIG_FILE = args.config_file

    try:
        with open(CONFIG_FILE, encoding="utf-8") as stream:
            config = yaml.safe_load(stream)
    except OSError:
        pass

    try:
        HOST = config["host"]
    except KeyError:
        pass

    try:
        PORT = config["port"]
    except KeyError:
        pass
    try:
        ODOO_URL = config["odoo_url"]
    except KeyError:
        pass

    try:
        LOG_LEVEL = config["log_level"]
    except KeyError:
        pass

    try:
        BASE_NAME = config["BASE_DOMAIN"]
    except KeyError:
        pass

    try:
        SUB_DOMAINS = config["subdomains"]
    except KeyError:
        pass

    # if LOG_LEVEL in "DEBUG":
    #     logging.basicConfig(level=logging.DEBUG,format='%(module)s-%(funcName)s: %(message)s')
    #     logging.debug("Debug level logging started")
    # else:
    logging.basicConfig(level=logging.INFO)
    logging.info(f" -> DNS with config : {CONFIG_FILE}")
    logging.info(f" -> DNS server serving on {HOST}:{PORT}")

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
