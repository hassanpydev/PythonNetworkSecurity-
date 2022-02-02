#!/usr/bin/python3.8

import subprocess
import re

mac_Address_pattren = r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w"
mac_address_output = subprocess.check_output(["ifconfig", "eno1"], shell=False)
extracted_mac_address = re.search(
    mac_Address_pattren, mac_address_output.decode()
).group(0)

print(extracted_mac_address)
