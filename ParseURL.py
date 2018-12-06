# coding: utf-8
import logging, sys, datetime, certstream
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

def traitementURL(domain):
    motcle =  ["banque", "credit", "agricole", "mutuel", "lcl.", "lyonnais", "bforbank", "hellobank", "bank", "caisse", "epargne", "hsbc", "fortuneo", "axa.", "groupama",
               "allianz", "barclays", "postale", "societegeneral", "boursorama", "paribas", "swisslife", "ubs.", "cetelem", "banq",
               "monabanq", "cic.", "banca", "creval","carige","banco","abnamro", "vanlanschot", "pekao", "pkobp","millenniumbcp","montepio",
               "standardchartered","santander", "nationwide","nordea","skandia", ]
    for mot in motcle:
        if mot in domain:
            sys.stdout.write(u"[{}] {} \n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), domain))
            sys.stdout.flush()
            return True
    return False

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
        traitementURL(domain)



logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
certstream.listen_for_events(print_callback, url=certstream_url)



#print_callback()
