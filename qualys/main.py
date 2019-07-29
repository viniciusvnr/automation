import sys
import requests
import json
import re
from qcs import qcsapi
from app_config import config


# qid_toblock, severity_toblock, vulcount_toblock, cve_list
# image_id = sys.argv[1:]

# Check patterns
# # cve_list = ["CVE-2019-1543", "CVE-2019-1982", "CVE-2019-1983", "CVE-1999-0511"]
# *Sugestão:* Usar biblioteca `argparse` para parsing de argumentos

image_id = "476bb14bade6"
cve_list = []
cvepattern = re.compile(r"CVE-\d{4}-\d{4,7}")
imagepattern = re.compile(r"([0-9a-z]{12})")

for arg in sys.argv[1:]:
    if cvepattern.match(arg):
        cve_list = arg
    if imagepattern.match(arg):
        image_id = arg
# Creds for Api Access
creds = config.get_config()
# get url to build
url_builder = qcsapi.UrlBuilder()
# consume Api
con = qcsapi.QualysImages(creds, url_builder)
resp = con.GetByImageId(image_id)


print(json.dumps(resp, indent=2))

valuation = qcsapi.PolicyValuation(resp)
# valuation.ValuationByQID(qid_toblock)
valuation.ValuationBySeverity("2")
# valuation.ValuationByVulnCount(vulcount_toblock)
# valuation.ValuationByCVEId(cve_list)
# print(f"Valuation Succeed. \nData:\n{json.dumps(data, indent=2)}")


# class JSONObject:
#   def __init__( self, dict ):
#       vars(self).update( dict )

# #this is valid json string
# data='{"channel":{"lastBuild":"2013-11-12", "component":["test1", "test2"]}}'

# jsonobject = json.loads( data, object_hook=JSONObject)

# jsonobject.channel.component[0]

# print( jsonobject.channel.component[0]  )
# print( jsonobject.channel.lastBuild  )
