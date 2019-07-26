import requests
import re


class QualysAuth:
    def __init__(self):
        pass

    def _BasicAuth(self, user, pwd):
        self.creds = (user, pwd)
        return self.creds


class BaseUrl:
    def __init__(self):
        self.uri = "https://qualysapi.qg3.apps.qualys.com/csapi"

    def _urn(self, path):
        self.path = path
        return self.uri + self.path


class QualysSensor(BaseUrl):
    def __init__(self, auth, sensorId=""):
        self.sensorId = sensorId
        self.auth = auth
        BaseUrl.__init__(self)

    def GetAll(self):
        return requests.get(self._urn("/v1.1/sensors/"), auth=(self.auth))

    def GetBySensorId(self):
        return requests.get(
            self._urn("/v1.1/sensors/" + self.sensorId), auth=(self.auth)
        )

    def RemoveBySensorId(self):
        return requests.delete(
            self._urn("/v1.1/sensors" + self.sensorId), auth=(self.auth)
        )


class QualysImages(BaseUrl):
    def __init__(self, auth):
        self.auth = auth
        BaseUrl.__init__(self)

    def GetAll(self):
        return requests.get(self._urn("/v1.1/images/"), auth=(self.auth))

    def GetByImageId(self, imageId):
        self.imageId = imageId
        return requests.get(self._urn("/v1.1/images/" + self.imageId), auth=(self.auth))

    def GetImageVuln(self, imageId):

        return requests.get(
            self._urn("/v1.1/images/" + imageId + "/vuln"), auth=(self.auth)
        )

    def GetImageVulnCount(self, imageId):
        self.imageId = imageId
        return requests.get(
            self._urn("/v1.1/images/" + self.imageId + "/vuln/count"), auth=(self.auth)
        )


class PolicyValuation:
    def __init__(self, imageId, vuln):
        self.vuln = vuln
        self.imageId = imageId

    def ValuationByVulnerability(self):
        pass

    def ValuationBySeverity(self, severity):
        self.severity = severity
        pass

    def ValuationByCVEId(self, cveid):
        self.cveid = cveid
        pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

        if pattern.match(self.cveid):
            pass
        else:
            raise ApiError("Invalid CVE")

    def ValuationByVulnCount(self):
        pass


class Notifier:
    pass


# class QualysRegistry:
#     def __init__(self, registryId, scheduleId):
#         self.registryId = registryId
#         self.scheduleId = scheduleId
