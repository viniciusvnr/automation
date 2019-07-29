import requests
from app_config import config
import json
import re


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
        return AnalysisResult.get_AnalysisResult(result)

    def GetBySensorId(self, sensorId):
        self.sensorId = sensorId
        result = requests.get(self.url_builder.build(f"/v1.1/sensors/{self.sensorId}"), auth=(self.auth))
        return AnalysisResult.get_AnalysisResult(result)

    def RemoveBySensorId(self):
        result = requests.delete(self.url_builder.build(f"/v1.1/sensors/{self.sensorId}"), auth=(self.auth))
        return AnalysisResult.get_AnalysisResult(result)


class QualysImages:
    def __init__(self, auth, url_builder):
        self.auth = auth
        self.url_builder = url_builder

    def GetAll(self):
        result = requests.get(self.url_builder.build("/v1.1/images/"), auth=(self.auth))
        return AnalysisResult.get_AnalysisResult(result)

    def GetByImageId(self, imageId):
        self.imageId = imageId
        result = requests.get(self.url_builder.build(f"/v1.1/images/{self.imageId}"), auth=(self.auth))
        return AnalysisResult.get_AnalysisResult(result)

    def GetImageVuln(self, imageId):

        result = requests.get(self.url_builder.build(f"/v1.1/images/{imageId}/vuln"), auth=(self.auth))
        return AnalysisResult.get_AnalysisResult(result)

    def GetImageVulnCount(self, imageId):
        self.imageId = imageId
        result = requests.get(self.url_builder.build(f"/v1.1/images/{self.imageId}/vuln/count"), auth=(self.auth))
        return AnalysisResult.get_AnalysisResult(result)


class AnalysisResult:
    def __init__(self):
        pass

    @classmethod
    def get_AnalysisResult(self, response):
        self.response = response.json()
        template = """{
                        "imageId": "",
                        "repository": "",
                        "tag": "",
                        "vulnerabilityCount": "",
                        "vulnerabilities": "[]"
                       }"""

        result = json.loads(template)

        result["imageId"] = self.response["imageId"]
        result["repository"] = self.response["repo"][0]["repository"]
        result["tag"] = self.response["repo"][0]["tag"]
        result["vulnerabilityCount"] = self.response["totalVulCount"]
        result["vulnerabilities"] = self.response["vulnerabilities"]

        return result


class PolicyValuation:
    def __init__(self, data):
        self.data = data
        self.vulobject = self.data["vulnerabilities"]

    def ValuationByQID(self, qid):
        self.qid = qid

        for item in self.vulobject:
            if int(self.qid) == item["qid"]:
                raise Exception("QID not permmited")

    def ValuationBySeverity(self, severity):
        self.severity = severity

        for item in self.vulobject:
            if int(self.severity) == item["severity"]:
                raise Exception("Severity not permmited")

    def ValuationByCVEId(self, cve: list):
        self.cve = cve

        for item in self.vulobject:
            result = all(elem in self.cve for elem in item["cveids"])
            if result:
                raise Exception("CVE Not Permmited")

    def ValuationByVulnCount(self, count):
        self.count = count

        if self.data["vulnerabilityCount"] >= self.count:
            raise Exception("vulnerability count exceed.")


class Notifier:
    pass
