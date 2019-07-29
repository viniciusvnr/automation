import requests
from qcs import qcsapi
from app_config import config
from pprint import pprint
import json

# Credential for Api
creds = config.get_config()
#  open connection
con = qcsapi.QualysImages(creds)
resp = con.GetByImageId("c8428f0b243c")

resp_json = resp.json()

# Define my object template
data = {
    "imageId": "",
    "repository": "",
    "tag": "",
    "vulnerabilityCount": "",
    "vulnerabilities": [],
    "hosts": [],
}

# build object
data["imageId"] = resp_json["imageId"]
data["repository"] = resp_json["repo"][0]["repository"]
data["tag"] = resp_json["repo"][0]["tag"]
data["vulnerabilityCount"] = resp_json["totalVulCount"]

for item in resp_json["vulnerabilities"]:
    data["vulnerabilities"].append(item)

for each in resp_json["host"]:
    data["hosts"].append(each)

cve_list = ["CVE-2019-1543", "CVE-2019-1982", "CVE-2019-1983"]
valuation = qcsapi.PolicyValuation(data)
# valuation.ValuationByQID("177008")
# valuation.ValuationBySeverity("2")
# valuation.ValuationByVulnCount("2")
valuation.ValuationByCVEId(cve_list)
