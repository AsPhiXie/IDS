# coding: utf-8
import logging
import datetime
import certstream
import requests
from stix2 import Indicator
import whois
import datetime

certstream_url = 'wss://certstream.calidog.io'
score = 100
bl_dns = {
    "all.s5h.net",
    "b.barracudacentral.org",
    "bl.emailbasura.org",
    "bl.spamcannibal.org",
    "bl.spamcop.net",
    "blacklist.woody.ch",
    "bogons.cymru.com",
    "cbl.abuseat.org",
    "cdl.anti-spam.org.cn",
    "combined.abuse.ch",
    "db.wpbl.info",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dnsbl.anticaptcha.net",
    "dnsbl.dronebl.org",
    "dnsbl.inps.de",
    "dnsbl.sorbs.net",
    "dnsbl.spfbl.net",
    "drone.abuse.ch",
    "duinv.aupads.org",
    "dul.dnsbl.sorbs.net",
    "dyna.spamrats.com",
    "dynip.rothen.com",
    "http.dnsbl.sorbs.net",
    "ips.backscatterer.org",
    "ix.dnsbl.manitu.net",
    "korea.services.net",
    "misc.dnsbl.sorbs.net",
    "noptr.spamrats.com",
    "orvedb.aupads.org",
    "pbl.spamhaus.org",
    "proxy.bl.gweep.ca",
    "psbl.surriel.com",
    "relays.bl.gweep.ca",
    "relays.nether.net",
    "sbl.spamhaus.org",
    "short.rbl.jp",
    "singular.ttk.pte.hu",
    "smtp.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "spam.abuse.ch",
    "spam.dnsbl.anonmails.de",
    "spam.dnsbl.sorbs.net",
    "spam.spamrats.com",
    "spambot.bls.digibase.ca",
    "spamrbl.imp.ch",
    "spamsources.fabel.dk",
    "ubl.lashback.com",
    "ubl.unsubscore.com",
    "virus.rbl.jp",
    "web.dnsbl.sorbs.net",
    "wormrbl.imp.ch",
    "xbl.spamhaus.org",
    "z.mailspike.net",
    "zen.spamhaus.org",
    "zombie.dnsbl.sorbs.net"
}

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
        return verif_whois(url)
    except Exception:
        #print("SSL ERROR BAD CERTIFICATE DOMAIN")
        score = score - 50
        i = STIX2(url, score, "Site sans certificat SSL.")
        print(i)
        return

def verif_whois(url):
    global score
    domain = whois.whois(NAME)
    cd = domain.creation_date
    td = datetime.datetime.now()

    for server in domain.name_servers:
        if server in bl_dns:
            score -= -50
            return

    if (td - cd).days < 365:
        score -= 25

    return analyseVisite(url)

def analyseVisite(url):
    global score
    r = requests.get("https://www.alexa.com/siteinfo/" + url)
    page = str(r.text)
    if 'We don\'t have enough data to rank this website.' in page:
        score = score - 40

        i = STIX2(url, score, "Pas de donnee Alexa.")
        print(i)
        return
    else:
        globalRank = page.split("<!-- Alexa web traffic metrics are available via our API at http://aws.amazon.com/awis -->\n")[1].split(' ')[0]
        country = page.split("countryRank")[2].split("title=\'")[1].split("\'")[0]
        countryRank = page.split("metrics-data align-vmiddle\">\n")[2].split(" ")[0]

        intGLobal = int(globalRank)
        if (intGLobal > 4000000):
            score -= 40
        elif (intGLobal > 3000000):
            score -= 30
        elif (intGLobal > 2000000):
            score -= 20
        elif (intGLobal > 1000000):
            score -= 10
        i = STIX2(url, score, "Rang mondiale = " + globalRank)
        print(i)
        return

def traitementURL(domain):
    motcle = ["banque", "credit", "agricole", "mutuel", "lcl.", "lyonnais", "bforbank", "hellobank", "bank", "caisse",
              "epargne", "hsbc", "fortuneo", "axa.", "groupama",
              "allianz", "barclays", "postale", "societegeneral", "boursorama", "paribas", "swisslife", "ubs.",
              "cetelem", "banq",
              "monabanq", "cic.", "banca", "creval", "carige", "banco", "abnamro", "vanlanschot", "pekao", "pkobp",
              "millenniumbcp", "montepio",
              "standardchartered", "santander", "nationwide", "nordea", "skandia", "juliusbaer", "itau", "bradesco",
              "banrisul", "goldmansachs",
              "morganstanley", "citigroup", "jpmorganchase", "wellsfargo", "capitalone", "meriwest"]
    for mot in motcle:
        if mot in domain:
            return trustedSite(domain)

def STIX2(url, score, description):
    indik = Indicator(name="URL Suspecte", labels=["malicious-activity"], created=datetime.datetime.now(), description="Score = " + str(score) + " | " + description, pattern="[url:value = '" + url + "']")
    return indik

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
        score = 100
        traitementURL(domain)

logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
certstream.listen_for_events(print_callback, url=certstream_url)
