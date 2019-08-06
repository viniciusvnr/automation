import requests
import json
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
        result = requests.get(self.url_builder.build(
            "/v1.1/sensors/"), auth=(self.auth))
        return DotMap(result.json())

    def GetBySensorId(self, sensorId):
        self.sensorId = sensorId
        result = requests.get(self.url_builder.build("/v1.1/sensors/{}".format(self.sensorId)), auth=(self.auth))
        return DotMap(result.json())

    def RemoveBySensoruuId(self, sensor_uuid):
        self.sensor_uuid = sensor_uuid

        body = {"sensorIds": self.sensor_uuid}
        payload = json.dumps(body)
        headers = {'content-type': 'application/json'}
        result = requests.delete(self.url_builder.build("/v1.1/sensors"), data=payload, auth=(self.auth), headers=headers)
        if result.status_code == 200:
            return DotMap(result.json())
        else:
            raise Exception("Failed to delete sensor ID {}. Status Code {}".format(self.sensorId, result.status_code))

    def RemoveSensorByType(self):
        body = {"filter": "sensorType:CICD"}
        payload = json.dumps(body)
        headers = {'content-type': 'application/json'}
        result = requests.delete(self.url_builder.build("/v1.1/sensors"), data=payload, auth=(self.auth), headers=headers)
        if result.status_code == 200:
            return DotMap(result.json())
        else:
            raise Exception("Failed to delete sensor CI/CD. Status Code {}".format(result.status_code))


class QualysImages:
    def __init__(self, auth, url_builder):
        self.auth = auth
        self.url_builder = url_builder

    def GetAll(self):
        result = requests.get(self.url_builder.build("/v1.1/images/"), auth=(self.auth))
        return DotMap(result.json())

    def GetByImageId(self, imageId):
        self.imageId = imageId
        result = requests.get(self.url_builder.build("/v1.1/images/{}".format(self.imageId)), auth=(self.auth))
        if result.status_code == 200:
            response = DotMap(result.json())
        else:
            raise Exception("Invalid Request.\nhttp-code: {}".format(result.status_code))

        return response

    def GetImageVuln(self, imageId):
        self.imageId = imageId
        result = requests.get(self.url_builder.build("/v1.1/images/{}/vuln".format(self.imageId)), auth=(self.auth))
        return DotMap(result.json())

    def GetImageVulnCount(self, imageId):
        self.imageId = imageId
        result = requests.get(self.url_builder.build("/v1.1/images/{}/vuln/count".format(self.imageId)), auth=(self.auth))
        return DotMap(result.json())


class PolicyValuation:
    @classmethod
    def ValuationBySeverity(self, valuation_object, sev=5):
        self.sev = sev
        self.valuation_object = valuation_object
        for vul in self.valuation_object.vulnerabilities:
            if vul.severity >= self.sev:
                raise Exception("The severity found ({}) is equal to or greater than the specified severity ({})\nVulnerability: {}\nTask stopped.".format(vul.severity, self.sev, vul.title))
        print("Specified vulnerability not found.")

    @classmethod
    def ValuationByQId(self, valuation_object, qid):
        self.valuation_object = valuation_object
        self.qid = qid
        for vul in self.valuation_object.vulnerabilities:
            if vul.qid == self.qid:
                raise Exception("QiD {} found.\nVulnerability: {}\nTask stopped.".format(self.qid, vul.title))

    @classmethod
    def ValuationByCVEId(self, valuation_object, cve):
        self.valuation_object = valuation_object.vulnerabilities
        self.cve = cve
        self.imageId = valuation_object.imageId
        for vul in self.valuation_object:
            result = any(elem in self.cve for elem in vul.cveids)
            if result:
                raise Exception("CVEId found on ImageId {}.\nCVE List: {}.\nVulnerability: {}\nTask stopped.".format(self.imageId, self.cve, vul.title))

    @classmethod
    def ValuationByVulnCount(self, valuation_object, count):
        self.valuation_object = valuation_object
        self.count = count
        if self.valuation_object is list:
            for item in self.valuation_object:
                if self.count >= item.totalVulCount:
                    raise Exception("Number of vulnerabilities exceeded: ({}).\nImage Id: {}\nTask stopped.".format(self.count, item.imageId))
        if self.count == int(self.valuation_object.totalVulCount):
            raise Exception("Number of vulnerabilities exceeded: {}.\nImage Id: {}\nTask stopped.".format(self.count, self.valuation_object.imageId))


class Notifier:
    pass
