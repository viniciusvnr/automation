import requests
from app_config import config
import re

# Utilizando arquivo config
# class QualysAuth:
#     def __init__(self):
#         pass

#     def _BasicAuth(self, user, pwd):
#         self.creds = (user, pwd)
#         return self.creds


class BaseUrl:
    def __init__(self):
        self.uri = config.get_apiuri()

    def _urn(self, path):
        self.path = path
        return self.uri + self.path


class QualysSensor(BaseUrl):
    def __init__(self, auth):
        self.auth = auth
        BaseUrl.__init__(self)

    def GetAll(self):
        return requests.get(self._urn("/v1.1/sensors/"), auth=(self.auth))

    def GetBySensorId(self, sensorId):
        self.sensorId = sensorId
        return requests.get(
            self._urn(f"/v1.1/sensors/{self.sensorId}"), auth=(self.auth)
        )

    def RemoveBySensorId(self):
        return requests.delete(
            self._urn(f"/v1.1/sensors/{self.sensorId}"), auth=(self.auth)
        )


class QualysImages(BaseUrl):
    def __init__(self, auth):
        self.auth = auth
        BaseUrl.__init__(self)

    def GetAll(self):
        return requests.get(self._urn("/v1.1/images/"), auth=(self.auth))

    def GetByImageId(self, imageId):
        self.imageId = imageId
        return requests.get(self._urn(f"/v1.1/images/{self.imageId}"), auth=(self.auth))

    def GetImageVuln(self, imageId):

        return requests.get(self._urn(f"/v1.1/images/{imageId}/vuln"), auth=(self.auth))

    def GetImageVulnCount(self, imageId):
        self.imageId = imageId
        return requests.get(
            self._urn(f"/v1.1/images/{self.imageId}/vuln/count"), auth=(self.auth)
        )


class PolicyValuation:

    """ 
    Data object must be:
    {
    "imageId": "",
    "repository": "",
    "tag": "",
    "vulnerabilityCount": "",
    "vulnerabilities": [],
    "hosts": [],
    }

    """

    def __init__(self, data: dict):
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
        # pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

        # if pattern.match():
        #     pass

        for item in self.vulobject:
            result = all(elem in self.cve for elem in item["cveids"])
            if result:
                raise Exception("CVE Not Permmited")
        else:
            raise Exception("Invalid CVE")

    def ValuationByVulnCount(self, count):
        self.count = count

        if self.data["vulnerabilityCount"] >= self.count:
            raise Exception("vulnerability count exceed.")


class Notifier:
    pass


# class QualysRegistry:
#     def __init__(self, registryId, scheduleId):
#         self.registryId = registryId
#         self.scheduleId = scheduleId
