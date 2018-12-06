#!/usr/bin/python3

import socket
import ssl
import OpenSSL
from pprint import pprint
import sys
import requests

# https://23.253.135.79/

if len(sys.argv) < 2:
    print("Error, argument required")
    exit(-1)

NAME = sys.argv[1]
HOST = socket.gethostbyname(NAME.split("//")[1])
PORT = 443

# cert = ssl.get_server_certificate((HOST, PORT))
# x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
# pprint(x509.get_subject().get_components())
#
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect((HOST, PORT))
# s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)
# s.send("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(HOST).encode())
# print(s)
# s.close()

# catcher d'autres exceptions
try:
    r = requests.get(NAME, verify=True)
    print("SSL GOOD CERTIFICATE DOMAIN")
except requests.exceptions.SSLError:
    print("SSL ERROR BAD CERTIFICATE DOMAIN")


# L'api circl pour AS
