# coding: utf-8
import logging
import sys
import datetime
import certstream

certstream_url = 'wss://certstream.calidog.io'

def verif_confiance(url):
    return

def verif_https(url):
    return

def verif_whois(url):
    return

def verif_frequence(url):
    return

def verif_herbergeur_geoloc(url):
    return

def filtre():
    return

def print_callback(message, context):
    logging.debug("Message -> {}".format(message))

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = "NULL"
        else:
            domain = all_domains[0]

        sys.stdout.write(u"[{}] {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
        sys.stdout.flush()

logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

certstream.listen_for_events(print_callback, url=certstream_url)

