import requests
from dotmap import DotMap

from app_config import config


class UrlBuilder:
    def __init__(self, base_uri=config.get_apiuri()):
        self.uri = base_uri

    def build(self, path):
        self.path = path
        return self.uri + self.path


class QualysSensor:
    def __init__(self, auth, url_builder):
        self.auth = auth
        self.url_builder = url_builder

    def GetAll(self):
        result = requests.get(self.url_builder.build("/v1.1/sensors/"), auth=(self.auth))
        return DotMap(result.json())

    def GetBySensorId(self, sensorId):
        self.sensorId = sensorId
        result = requests.get(self.url_builder.build(f"/v1.1/sensors/{self.sensorId}"), auth=(self.auth))
        return DotMap(result.json())

    def RemoveBySensorId(self):
        result = requests.delete(self.url_builder.build(f"/v1.1/sensors/{self.sensorId}"), auth=(self.auth))
        return DotMap(result.json())


class QualysImages:
    def __init__(self, auth, url_builder):
        self.auth = auth
        self.url_builder = url_builder

    def GetAll(self):
        result = requests.get(self.url_builder.build("/v1.1/images/"), auth=(self.auth))
        return DotMap(result.json())

    def GetByImageId(self, imageId):
        self.imageId = imageId
        result = requests.get(self.url_builder.build(f"/v1.1/images/{self.imageId}"), auth=(self.auth))
        if result.status_code == 200:
            response = DotMap(result.json())
        else:
            raise Exception(f"Invalid Request.\n Httpcode: {result.status_code}")

        return response

    def GetImageVuln(self, imageId):
        self.imageId = imageId
        result = requests.get(self.url_builder.build(f"/v1.1/images/{self.imageId}/vuln"), auth=(self.auth))
        return DotMap(result.json())

    def GetImageVulnCount(self, imageId):
        self.imageId = imageId
        result = requests.get(self.url_builder.build(f"/v1.1/images/{self.imageId}/vuln/count"), auth=(self.auth))
        return DotMap(result.json())


class PolicyValuation:
    @classmethod
    def ValuationBySeverity(self, valuation_object, sev=5):
        self.sev = sev
        self.valuation_object = valuation_object
        for vul in self.valuation_object.vulnerabilities:
            if vul.severity >= self.sev:
                raise Exception(f"The severity found ({vul.severity}) is equal to or greater than the specified severity ({self.sev})\nVulnerability: {vul.title}\nTask stopped.")

    @classmethod
    def ValuationByQId(self, valuation_object, qid):
        self.valuation_object = valuation_object
        self.qid = qid
        for vul in self.valuation_object.vulnerabilities:
            if vul.qid == self.qid:
                raise Exception(f"QiD {self.qid} found.\nVulnerability: {vul.title}\nTask stopped.")

    @classmethod
    def ValuationByCVEId(self, valuation_object, cve: list):
        self.valuation_object = valuation_object.vulnerabilities
        self.cve = cve
        self.imageId = valuation_object.imageId
        for vul in self.valuation_object:
            result = any(elem in self.cve for elem in vul.cveids)
            if result:
                raise Exception(f"CVEId found on ImageId {self.imageId}.\nCVE List: {self.cve}.\nVulnerability: {vul.title}\nTask stopped.")

    @classmethod
    def ValuationByVulnCount(self, valuation_object, count):
        self.valuation_object = valuation_object
        self.count = count
        if self.valuation_object is list:
            for item in self.valuation_object:
                if self.count >= item.totalVulCount:
                    raise Exception(f"Number of vulnerabilities exceeded: ({self.count}).\nImage Id: {item.imageId}\nTask stopped.")
        if self.count == int(self.valuation_object.totalVulCount):
            raise Exception(f"Number of vulnerabilities exceeded: {self.count}.\nImage Id: {self.valuation_object.imageId}\nTask stopped.")


class Notifier:
    pass
