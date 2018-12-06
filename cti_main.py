# coding: utf-8
import logging
import sys
import datetime
import certstream
import requests

certstream_url = 'wss://certstream.calidog.io'
score = 100

def trustedSite(url):
    global score
    with open("listeReduite.txt") as f:
        mylist = f.read().splitlines()
    if url in mylist:
        print("Score = 100/100")
        return "Site OK : " + url
    else:
        score = score - 50
        return checkHTTPS(url)

def checkHTTPS(url):
    global score
    try:
        requests.get("https://" + url, verify=True)
        #print("SSL GOOD CERTIFICATE DOMAIN")
        return analyseVisite(url)
    except Exception:
        #print("SSL ERROR BAD CERTIFICATE DOMAIN")
        score = score - 50
        print("Site non accepté. URL = " + url)
        print("Score = " + str(score))

def verif_whois(url):
    return

def analyseVisite(url):
    r = requests.get("https://www.alexa.com/siteinfo/" + url)
    page = str(r.text)
    if 'We don\'t have enough data to rank this website.' in page:
        print("Aucune donnée sur ce domaine.")
        return -1
    else:
        #page = str(r.text).split("demographics_div_country_table")[1].split("data-count")[1].split("&nbsp;")[1].split("</a>")[0]
        globalRank = page.split("<!-- Alexa web traffic metrics are available via our API at http://aws.amazon.com/awis -->\n")[1].split(' ')[0]
        country = page.split("countryRank")[2].split("title=\'")[1].split("\'")[0]
        countryRank = page.split("metrics-data align-vmiddle\">\n")[2].split(" ")[0]
        print("Rang mondial : " + globalRank)
        print("Pays : " + country)
        print("Rang dans le pays : " + countryRank)
        return 0

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
    return trustedSite(domain)


def print_callback(message, context):
    global score
    logging.debug("Message -> {}".format(message))
    if message['message_type'] == "heartbeat":
        return
    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
    if len(all_domains) == 0:
        domain = "NULL"
    else:
        domain = all_domains[0]
        print(domain)
        score = 100
        traitementURL(domain)

logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
certstream.listen_for_events(print_callback, url=certstream_url)

