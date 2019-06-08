import json
import urllib3
import certifi
from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication
from pprint import  pprint

http = urllib3.PoolManager()

def post_to_slack(slackurl, message='Hello World'):
    slack_url = slackurl
    
    encoded_data = json.dumps({'text': message}).encode('utf-8')
    response = http.request("POST", slack_url, body=encoded_data, headers={'Content-Type': 'application/json'})
    print(str(response.status) + str(response.data))

slackuri = "{SlackWebhook_url}"

#Azure DevOps
personal_access_token = '{PAT_TOKEN}'
organization_url = 'https://dev.azure.com/{organization}'

credentials = BasicAuthentication('', personal_access_token)
tpprovider = 'git'
connection = Connection(base_url=organization_url, creds=credentials)
core_client = connection.clients_v5_1.get_core_client()
git_client = connection.clients_v5_1.get_git_client()
policy = connection.clients_v5_0.get_policy_client()
projects = core_client.get_projects()

for project in projects:
    projectid = project.id
    repos = git_client.get_repositories(projectid)
    project_policies = policy.get_policy_configurations(projectid)

    for repo in repos:
        repid = repo.id
        defaultbranch = repo.default_branch

        filetered_policies = (x for x in project_policies
                                if x.type.display_name == "Minimum number of reviewers" and
                                    x.settings.get("scope")[0].get("refName") == defaultbranch and 
                                    x.settings.get("scope")[0].get("repositoryId") == repid)
        bpol = next(filetered_policies, None)
        if bpol != None:
            # compliant = bpol.settings
            poltype = bpol.type.display_name
            scope = bpol.settings.get("scope")
            minapprovecount = bpol.settings.get("minimumApproverCount")
                    
            if minapprovecount != None:
                if minapprovecount < 2:
                    mslack = "Project: ", project.name, ' | repo: ', repo.name," | Branch: ", defaultbranch, " | Conformidade: Não"
                    msg = ''.join(mslack)
                    post_to_slack(slackuri, msg)
                elif minapprovecount >= 2:
                    mslack = "Project: ", project.name, ' | repo: ', repo.name, " | Branch: ", defaultbranch, " | Conformidade: Sim"
                    msg = ''.join(mslack)
                    post_to_slack(slackuri, msg)
        else:
            mslack = "Project: ", project.name, ' | repo: ', repo.name, " | Conformidade: Sem Politica"
            msg = ''.join(mslack)
            post_to_slack(slackuri, msg)
