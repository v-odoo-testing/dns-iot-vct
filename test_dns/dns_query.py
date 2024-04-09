#!/usr/bin/python3

import logging

import dns.resolver

logger = logging.getLogger(__name__)

# pylint: disable=logging-fstring-interpolation,broad-exception-caught


def query():
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ["127.0.0.1:5551"]
    answers = my_resolver.resolve("192-168-0-241.sss.iotdns.v-odoo.com", "A")
    for rdata in answers:
        print(rdata.address)
        # print('Host', rdata.exchange, 'has preference', rdata.preference)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    query()
