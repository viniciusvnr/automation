import argparse
import json
import re

from app_config import config
from qcs import qcsapi

parser = argparse.ArgumentParser(description="Braspag qualys integration to evaluate images in CI pipeline")
parser.add_argument("--imageid", nargs="+", help="image Id to be evaluated")
parser.add_argument("--config", nargs=1, help="JSON file to be processed", type=argparse.FileType("r"))
arguments = parser.parse_args()

# Loading arguments
image_id = arguments.imageid[0]
config_arg = json.load(arguments.config[0])
qid_list = config_arg["qid"]
severity_toblock = config_arg["severity"]
vulncount = config_arg["vulncount"]

# Check Image Pattern
imagepattern = re.compile(r"([0-9a-z]{12})")
if imagepattern.match(image_id):
    pass
else:
    raise Exception("Provide a valid Image ID")

# check CVE Pattern
cve_list = []
cvepattern = re.compile(r"CVE-\d{4}-\d{4,7}")
for each in config_arg["cves"]:
    if cvepattern.match(each):
        cve_list.append(each)
    else:
        raise Exception("Invalid cve pattern")

# Creds for Api Access
creds = config.get_config()

# get url to build
url_builder = qcsapi.UrlBuilder()

# Api Call
con = qcsapi.QualysImages(creds, url_builder)
resp = con.GetByImageId(image_id)

# Valuation by severity
valuation = qcsapi.PolicyValuation.ValuationBySeverity(resp)

# Remove Sensor
# sensor_con = qcsapi.QualysSensor(creds, url_builder)
# Remove Sensor with Type CI/CD
# sensor_resp = sensor_con.RemoveSensorByType()


# sensor_uuid = ["fc9ff560-b3af-4f9d-8206-7cb5a6398a39"]
# sensor_resp = sensor_con.RemoveBySensoruuId(sensor_uuid)

