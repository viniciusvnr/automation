from qcs import qcsapi
from app_config import config
import sys, requests, json, re, argparse
from dotmap import DotMap


parser = argparse.ArgumentParser(description="Braspag qualys integration to evaluate images in CI pipeline")
parser.add_argument("--imageid", nargs="+", help="image Id to be evaluated")
parser.add_argument("--config", nargs=1, help="JSON file to be processed", type=argparse.FileType("r"))
arguments = parser.parse_args()

# Loading arguments
image_id = arguments.imageid[0]
config_arg = json.load(arguments.config[0])
cve_list = []

# Check Image Pattern
imagepattern = re.compile(r"([0-9a-z]{12})")
if imagepattern.match(image_id):
    pass
else:
    raise Exception("Provide a valid Image ID")

# check CVE Pattern
cvepattern = re.compile(r"CVE-\d{4}-\d{4,7}")
for each in config_arg["cves"]:
    if cvepattern.match(each):
        cve_list.append(each)
    else:
        raise Exception("Invalid cve pattern")

# Fill Qid_List
qid_list = []
for each in config_arg["qid"]:
    qid_list.append(each)

severity_toblock = config_arg["severity"]
vulncount = config_arg["vulncount"]

# Creds for Api Access
creds = config.get_config()

# get url to build
url_builder = qcsapi.UrlBuilder()

# Api Call
con = qcsapi.QualysImages(creds, url_builder)
resp = con.GetByImageId(image_id)

# Valuation by severity
valuation = qcsapi.PolicyValuation.ValuationBySeverity(resp, 1)


# valuation = qcsapi.PolicyValuation.ValuationByVulnCount(resp, 2)
# valuation = qcsapi.PolicyValuation.ValuationByQId(resp, 177008)
# valuation = qcsapi.PolicyValuation.ValuationByCVEId(resp, cve_list)
