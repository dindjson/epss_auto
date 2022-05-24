import requests
import re
import sys
import json

cve = sys.argv[1]

cve_check = r'CVE-\d{4}-\d{4,7}'

if re.match(cve_check,cve):
    response = requests.get("https://api.first.org/data/v1/epss?cve=" + cve)
else:
    print("You suck at coding")

json_data = response.json()

print(json_data)
