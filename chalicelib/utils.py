import json
import time
from datetime import datetime, date
from chalice import CustomAuthorizer

import boto3
import requests


authorizer = CustomAuthorizer(
    'Oap2ImsJwtAuthorizer',
    header='Authorization',
    authorizer_uri=('arn:aws-cn:apigateway:cn-north-1:lambda:path/2015-03-31'
                    '/functions/arn:aws-cn:lambda:cn-north-1:843403612003:'
                    'function:oap2-ims-jwt-authorizer/invocations'),
    invoke_role_arn='arn:aws-cn:iam::843403612003:role/ims-api-authorizer-role'
)


class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        else:
            return json.JSONEncoder.default(self, obj)


def respond(code=200, data=[], messages=[]):
    return {
        'statusCode': code,
        'body': json.dumps({
            "data": data,
            "messages": messages
        }, cls=ComplexEncoder)
    }


def get_ts():
    ts = time.time()
    st = datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M%S')
    return st


def switch_role(**kwargs):
    _session = boto3.session.Session(region_name='cn-north-1')
    sts_client = _session.client('sts')
    sts_response = sts_client.assume_role(
        RoleArn=kwargs["RoleArn"],
        RoleSessionName='role-session-' + get_ts(),
    )
    sts_session = boto3.Session(
        aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
        aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
        aws_session_token=sts_response['Credentials']['SessionToken']
    )
    return sts_session


def get_wechat_group(**kwargs):
    groupName = kwargs['groupName']
    url = "https://5bf2ses997.execute-api.cn-north-1.amazonaws.com.cn/dev/v1/aws/wechat/groups"
    params = {'name': groupName}
    headers = {}
    response = requests.request("GET", url, headers=headers, params=params)
    print(response.text)
    return response.json()


def send_wechat_message(**kwargs):
    groupId = kwargs['groupId']
    title = kwargs['title']
    description = kwargs['description']
    url = "https://bafask91w9.execute-api.cn-north-1.amazonaws.com.cn/dev/messages"
    payload = json.dumps({
        "msgType": "textcard",
        "msgContent": {
            "title": f"[{title}]",
            "description": description,
            "btntxt": "More",
            "url": "https://console.amazonaws.cn/securityhub/home?region=cn-north-1#/summary",
        },
        "groupId": groupId
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def send_mail(**kwargs):
    receivers = kwargs['Receivers']
    subject = kwargs['Subject']
    body = kwargs['Body']

    url = "http://10.200.21.108:8000/utils/account/send/mail/"
    payload = {'Receivers': receivers,
               'Subject': subject,
               'Body': body
               }
    headers = {
        'Authorization': 'Token f071d8feda5e42148d42142fbea2de3f4eccfde1'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)