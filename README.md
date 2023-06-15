# Introduction
AWS Securityhub best practice by chalice include service management and finding handler.

# Quickstart
## Prepare Venv 
```
# python3 -m venv securityhub
# cd securityhub
# source bin/activate
```

## Install Chalice
```
# pip install chalice
# chalice --help
```

## Credentials
Before you can deploy an application, be sure you have AWS credentials configured.

# Deploy
## Local
```
# git clone https://git.daimler.com/ITT-China/aws-sechub.git
# cd aws-sechub
# pip install -r requirements.txt
# chalice deploy --profile SharedP  (profile name need to be replaced by your settings)
```

## Automatically
```
# git clone https://git.daimler.com/ITT-China/aws-sechub.git
# cd aws-sechub
# git add .
# git commit -m "sth to do"   (Deploy pipeline will be triggered automatically on DevCenter)
# git push
```

# Reference
Documents https://aws.github.io/chalice/index

AWS Chalice Repo https://github.com/aws/chalice

AWS Chalice Workshop https://chalice-workshop.readthedocs.io/en/latest/index.html


# Issues
- Can't add more decorator on same lambda. Such as more cw event on one lambda.
- Can't get lambda_context in blueprint for event decorator 
    -  https://github.com/aws/chalice/issues/1566
- Only create customize folder or files under chalicelib folder?
- When chalice support Step Function?
    - Create Step Function resource
    - Authorization
    - Reference 

- Any other known issue?