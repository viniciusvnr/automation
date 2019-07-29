import os

# Api Config
def get_config():

    # user = os.getenv("API_USER")
    user = "user"
    # password = os.getenv("API_PASSWORD")
    password = r"pass"
    api_credential = (user, password)
    return api_credential


# Api Url
def get_apiuri():
    # apiurl = os.getenv("API_URL")
    uri = "https://qualysapi.qg3.apps.qualys.com/csapi"
    return uri


# Slack Logging
def get_slack_config():
    slack_token = os.getenv("SLACK_TOKEN")
    slack_channel = os.getenv("SLACK_CHANNEL")
    slack_config = (slack_token, slack_channel)
    return slack_config
