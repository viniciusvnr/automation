# Intro

The objective here is to provide useful scripts for DevOps tasks.

## Scripts

### Azure Devops

- [Check Branch Policy](azuredevops/check-branchpol.py)

>Script to check if the repository in a given team project has a policy and if the minimum reviewers is >= 2.

### Qualys

- [Qualys Api Integration](qualys/qualysvulscan.py)

> Valuation Config Template

```json
{
    "severity": 3,
    "cves": [
        "CVE-2019-1543",
        "CVE-2019-1982",
        "CVE-2019-1983",
        "CVE-1999-0511"
    ],
    "qid": [
        177008,
        177009,
        177010
    ],
    "vulncount": "10"
}
```

> Run script in console

```sh
python .\main.py --imageid 9fec0723a1ef --config .\valuation_config.json
```
