#!/usr/bin/python3

import logging

import zmq

logger = logging.getLogger(__name__)

# pylint: disable=logging-fstring-interpolation,broad-exception-caught


def add_txt_record(record_name: str, record_content: str):

    context = zmq.Context()
    context.RCVTIMEO = 1000
    context.SNDTIMEO = 1000
    answer = ""
    request = f"_TXT_:{record_name}:+:{record_content}"
    #  Socket to talk to server
    print("Connecting to hello world server…")
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://127.0.0.1:5555")
    try:
        socket.send(request.encode())
    except Exception as e:
        logger.error("Encountered error adding TXT record: {0}".format(e))

    try:
        answer = socket.recv()
    except Exception as e:
        logger.error("Encountered error adding TXT record, receive reply: {0}".format(e))
    else:
        answer = answer.decode("utf-8")
        if answer == "OK":
            logger.info("Successfully added TXT  %s %s", record_name, record_content)
        else:
            logger.error("Encountered error add TXT, bad reply: {0}".format(answer))
    socket.close()


def add_a_record(record_name: str):
    context = zmq.Context()
    context.RCVTIMEO = 1000
    context.SNDTIMEO = 1000
    answer = ""
    request = f"__A__:{record_name}:+:"
    #  Socket to talk to server
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://127.0.0.1:5555")
    try:
        socket.send(request.encode())
    except Exception as e:
        logger.error("Encountered error adding SUBDOMAIN record: {0}".format(e))
    try:
        answer = socket.recv()
    except Exception as e:
        logger.error("Encountered error adding TXT record, receive reply: {0}".format(e))
    else:
        answer = answer.decode("utf-8")
        if answer == "OK":
            logger.info("Successfully added SUBDOMAIN  %s", record_name)
        else:
            logger.error("Encountered error add DOMAIN %s, bad reply: {0}".format(answer))
    socket.close()


def del_txt_record(record_name: str, record_content: str):
    context = zmq.Context()
    answer = ""
    request = f"_TXT_:{record_name}:-:{ record_content}"
    context.RCVTIMEO = 1000
    context.SNDTIMEO = 1000
    socket = context.socket(zmq.REQ)
    try:
        socket.connect("tcp://127.0.0.1:5555")
    except socket.error as msg:
        print("Socket Error: %s" % msg)
    except TypeError as msg:
        print("Type Error: %s" % msg)

    try:
        socket.send(request.encode("utf-8"))
    except Exception as e:
        logger.error("Encountered error adding TXT record, send request: {0}".format(e))
    try:
        answer = socket.recv()
    except Exception as e:
        logger.error("Encountered error adding TXT record, receive reply: {0}".format(e))
    else:
        answer = answer.decode("utf-8")
        if "OK" == answer:
            logger.info("Successfully removed record %s TXT %s", record_name, answer)
        else:
            logger.error("Encountered error remove TXT record, bad reply: {0}".format(answer))
    socket.close()


def del_a_record(record_name: str):
    context = zmq.Context()
    answer = ""
    request = f"__A__:{record_name}:-:"
    context.RCVTIMEO = 1000
    context.SNDTIMEO = 1000
    socket = context.socket(zmq.REQ)

    socket.connect("tcp://127.0.0.1:5555")

    try:
        socket.send(request.encode("utf-8"))
    except Exception as e:
        logger.error("Encountered error remove subdomain, send request: {0}".format(e))
    try:
        answer = socket.recv()
    except Exception as e:
        logger.error("Encountered error remove subdomain, receive reply: {0}".format(e))
    else:
        answer = answer.decode("utf-8")
        if "OK" == answer:
            logger.info("Successfully removed domain(s) %s", record_name)
        else:
            logger.error("Encountered error remove subdomains, bad reply: {0}".format(answer))
    socket.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    add_txt_record(
        "_acmechallenge.psa.iotdns.v-odoo.com",
        "TRW4HC1Wtzhr6Z9DiEMpqVOMu87QUgYaCeEcFoIgLHQ",
    )
    # time.sleep(1)
    # del_txt_record('_acmechallenge.psa.iotdns.v-odoo.com','') #'TRW4HC1Wtzhr6Z9DiEMpqVOMu87QUgYaCeEcFoIgLHQ')
    # add_a_record('danny.iotdns.v-odoo.com')
    # add_a_record('sss.iotdns.v-odoo.com')
    # add_a_record('psa.iotdns.v-odoo.com')
    # add_a_record('gvs.iotdns.v-odoo.com')
    # add_a_record('gvs.iot.v-odoo.com')
    # del_a_record('psa.iotdns.v-odoo.com')
    # del_a_record('.iotdns.v-odoo.com')
    # del_a_record('*.dns.v-odoo.com')
    # del_a_record('*.iotdns.v-odoo.com')
