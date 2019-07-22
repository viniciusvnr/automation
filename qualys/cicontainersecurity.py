import qualysapi

class QualysServerCreds:

    def __init__(self, serverUrl, username, password):

        serverUrl = serverUrl.replace("/$", "")
        self.serverUrl = serverUrl
        self.username = username
        self.password = password


class GetImageVul:
    pass

class GetBuildInfo:
    pass


