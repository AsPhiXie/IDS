#!/usr/bin/python3

import sys
import subprocess

if len(sys.argv) < 2:
    print("Error, argument required")
    exit(-1)

NAME = sys.argv[1]
PORT = 443

whois = subprocess.check_output("whois " + NAME, shell=True, universal_newlines=True)
print(whois)
