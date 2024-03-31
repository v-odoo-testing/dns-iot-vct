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

import os
import logging

# from optparse import OptionParser
import argparse
import ipaddress
from socketserver import UDPServer, BaseRequestHandler
import binascii
from time import sleep
import yaml
from dnslib import DNSRecord, DNSHeader, RR, QTYPE
import _thread
import time
import tzlocal
import zmq
import json
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

ODOO_URL= "https://www.v-consulting.biz"
ODOO_API= "/vct_iot_subscription/list"
BASE_NAME = "iot.v-odoo.com"
HOST = "127.0.0.1"
PORT = 53
LOG_LEVEL = "info"

config = {}
config_subdomains = None
base_domain = None 
config_TXT = []

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
        for key in config_subdomains:
            if f".{key}.{base_domain}." in query_name:
                # here happens the magic
                ip_address = query_name.split(f".{key}.{base_domain}", 1)[0].replace(
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
        for short in config_subdomains:
            if f".{short}.{base_domain}." in query_name:
                prefix = short5
        if prefix:
            for key_value in config_TXT:
                key = query_name.split(f".{base_domain}", 1)[0]
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

        if base_domain not in query_name:
            reply = self._refused(query_name, query_type, request)

        elif f".{base_domain}" not in query_name:
            reply = self._nxdomain(query_name, query_type, request)

        elif query_type == "A":
            reply = self._handle_a_record(query_name, query_type, request, reply)

        elif query_type == "TXT":

            if (":-:" in query_name or ":+:" in query_name) and client == "127.0.0.1":
                reply = self._handle_txt_modif(query_name, request, reply)
            else:
                reply = self._handle_txt(query_name, query_type, request, reply)

        else:
            logging.error(
                f" DNS {query_type}:{query_name} from HOST:{client}:{port} unsupported type"
            )
        self.request[1].sendto(reply.pack(), self.client_address)


def handle_txt_modif(query_name):
    if ":+:" in query_name:
        split_query_name = query_name.split(":+:")
        query_name_clean = split_query_name[0]
        key = query_name_clean.split(f".{base_domain}")[0]
        value = split_query_name[1]
        key_value = {}
        key_value[key] = value
        config_TXT.append(key_value)
        # print_value = (value[:15] + "..") if len(value) > 15 else value
        print_value = value
        logging.info(f"TXT KEY  ADDED  ->{key}: '{print_value}'")
    elif ":-:" in query_name:
        # remove key / value
        found = False
        find_value = None
        split_query_name = query_name.split(":-:")
        find_key = split_query_name[0].split(f".{base_domain}", 1)[0]
        if len(split_query_name) > 1:
            find_value = split_query_name[1]
        prefix = None
        for short in config_subdomains:
            if f".{short}.{base_domain}" in query_name:
                prefix = short
                break
        if prefix:
            for key_value in config_TXT[:]:
                if key_value[find_key] and (
                    (find_value and key_value[find_key] == find_value) or not find_value
                ):
                    found = True
                    config_TXT.remove(key_value)
        if found:
            if find_value:
                logging.info(
                    f" DNS TXT KEY/VALUE REMOVED ->'{find_key}':'{find_value}'"
                )
            else:
                logging.info(f" DNS TXT KEY REMOVED ->'{find_key}'")
        else:
            logging.error(
                f" KEY '{split_query_name[0]}': '{find_value}' to remove not found in list"
            )
            return False
    else:
        return False
    return True


def handle_a_modif(query_name):
    if ":+:" in query_name:
        split_query_name = query_name.split(":+:")
        query_name_clean = split_query_name[0]
        key = query_name_clean.split(f".{base_domain}")[0]
        if key not in config_subdomains:
            config_subdomains.append(key)
            logging.info(f"SUBDOMAIN ADDED  ->{key}")
            # need to save to config
        else:
            logging.info(f"SUBDOMAIN ALREADY IN ->{key}")
    elif ":-:" in query_name:
        split_query_name = query_name.split(":-:")
        key = split_query_name[0].split(f".{base_domain}", 1)[0]
        if key != "*":
            if key in config_subdomains:
                config_subdomains.remove(key)
                logging.info(f" DNS SUBDOMAIN REMOVED ->'{key}'")
            else:
                logging.error(f" DNS  SUBDOMAIN NOT FOUND: '{key}'")
                return False
        else:
            for skey in config_subdomains[:]:
                config_subdomains.remove(skey)
            logging.info(f"ALL DNS SUBDOMAINS REMOVED")
    else:
        return False
    return True


def dns_thread():
    try:
        with UDPServer((HOST, PORT), DNSHandler) as server:
            logging.info(f"DNS server listening on {HOST}:{PORT}")
            server.serve_forever()
    except Exception as msg:
        logging.error("Socket binding error: " + str(msg) + "\n" + "Exit...")
        os._exit(1)

def cnf_thread():
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    try:
        socket.bind("tcp://127.0.0.1:5555")
    except Exception as msg:
        logging.error("Socket binding error: " + str(msg) + "\n" + "Exit...")
        os._exit(1)
    logging.info(f"ipc server listening")
    while True:
        #  Wait for next request from client
        message = socket.recv()
        message = message.decode("utf-8")
        logging.info(f"Received request: {message}")
        if "_TXT_:" in message:
            query = message.split("_TXT_:")[1]
            if base_domain not in query:
                socket.send(b"FAIL: wrong domain")

            elif f".{base_domain}" not in query:
                socket.send(b"FAIL: wrong subdomain")

            elif handle_txt_modif(query):
                #  Send reply back to client
                socket.send(b"OK")
            else:
                socket.send(b"FAIL")
        elif "__A__:" in message:
            query = message.split("__A__:")[1]
            if base_domain not in query:
                socket.send(b"FAIL: wrong domain")

            elif f".{base_domain}" not in query:
                socket.send(b"FAIL: nxdomain")

            elif handle_a_modif(query):
                #  Send reply back to client
                socket.send(b"OK")
            else:
                socket.send(b"FAIL")
        else:
            socket.send(b"???: request not understood")

def get_subscription_list():
    global base_domain
    global config_subdomains
    url = f'{ODOO_URL}{ODOO_API}'
    try:
        response = requests.get(url )

    except requests.exceptions.ConnectionError as errc:
        logging.error("Error Connecting: {}".format(errc))
    except requests.exceptions.Timeout as errt:
        logging.error(f"Timeout Error: {errt}")   
    except requests.exceptions.RequestException as err:
        logging.error(f"Request error: {err}")
    except Exception as msg:
        logging.error(f" -> DNS Error retrieving subscriptions: {msg}")
        pass
    else:
        if response.status_code == 200:
            response_data = json.loads(response.text)
            try:
                iot_domain = response_data['iot_domain']
                base_domain = iot_domain
                logging.info(f" --> DNS ODOO update Base Domain: {base_domain}")
            except:
                pass
            try:
                sub_domains = response_data['sub_domains']
                config_subdomains = sub_domains
                logging.info(f" --> DNS ODOO update Subdomains: {config_subdomains}")
            except:
                pass
        else:
            logging.error(f" -> DNS Error retrieving subscriptions: {response.status_code} {response.reason}")


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
        BASE_NAME = config["base_domain"]
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
    if not base_domain:
        base_domain = BASE_NAME

    if not config_subdomains:
        config_subdomains = SUB_DOMAINS

    logging.info(f" -> with DNS Base Domain: {base_domain}")
    for a_key in config_subdomains:
        logging.info(f" --> DNS with subdomains for  A  records {a_key}")

    _thread.start_new_thread(dns_thread, ())
    _thread.start_new_thread(cnf_thread, ())
    
    scheduler = BackgroundScheduler()
    
    #for daily Update 

    scheduler.start()
    trigger = CronTrigger(
        year="*", month="*", day="*", hour="3", minute="0", second="5",timezone=str(tzlocal.get_localzone())
    )

    scheduler.add_job(
        get_subscription_list,
        trigger=trigger,
        name="daily subscription update",
    )

    # for testing
    #scheduler.add_job(get_subscription_list, 'interval', seconds=10)
    #scheduler.start()

    while True:
        time.sleep(100)
