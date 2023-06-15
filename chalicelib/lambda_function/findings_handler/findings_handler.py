import json
import os
import sys
from datetime import datetime, timezone
from chalice import Blueprint

from chalicelib.utils import ComplexEncoder, send_mail
from chalicelib.utils import switch_role, get_wechat_group, send_wechat_message


findings_handler = Blueprint(__name__)


##################
# Fix ELB Finding
##################

def ELB4(**kwargs):
    """ Application load balancer should be configured to drop http headers

    fix control: [ELB.4] This control evaluates AWS Application Load Balancers (ALB)
                 to ensure they are configured to drop http headers. By default, ALBs
                 are not configured to drop invalid http header values. This control evaluates
                 all ALBs fails if the attribute value of routing.http.drop_invalid_header_fields.enabled is set to false.
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    lb_arn = resource['Id']
    lb_drop_invalid_header = {
        'Key': 'routing.http.drop_invalid_header_fields.enabled',
        'Value': 'true'
    }

    res = client.describe_load_balancer_attributes(
        LoadBalancerArn=lb_arn
    )

    if lb_drop_invalid_header not in res['Attributes']:
        res = client.modify_load_balancer_attributes(
            LoadBalancerArn=lb_arn,
            Attributes=[
                lb_drop_invalid_header,
            ]
        )

    if lb_drop_invalid_header in res['Attributes']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def ELB5(**kwargs):
    """ Application and Classic Load Balancers logging should be enabled

    fix control: [ELB.5] This control checks whether the Application Load Balancer and the Classic Load Balancer have logging enabled.
                 The control fails if the access_logs.s3.enabled is false.
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    lb_arn = resource['Id']
    lb_access_logs = {
        'Key': 'access_logs.s3.enabled',
        'Value': 'true'
    }
    lb_aaccess_logs_bucket = {
        'Key': 'access_logs.s3.bucket',
        'Value': 'p0000ps3alb0000'
    }
    lb_aaccess_logs_prefix = {
        'Key': 'access_logs.s3.prefix',
        'Value': lb_arn.split('/')[-2]
    }

    res = client.describe_load_balancer_attributes(
        LoadBalancerArn=lb_arn
    )

    if lb_access_logs not in res['Attributes']:
        res = client.modify_load_balancer_attributes(
            LoadBalancerArn=lb_arn,
            Attributes=[
                lb_access_logs,
                lb_aaccess_logs_bucket,
                lb_aaccess_logs_prefix
            ]
        )

    if lb_access_logs in res['Attributes']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def ELB6(**kwargs):
    """ Application Load Balancer deletion protection should be enabled

    fix control: [ELB.6] This control checks whether an Application
                 Load Balancer has deletion protection enabled. The control fails if deletion protection is not configured.
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    lb_arn = resource['Id']
    lb_deletion_protection = {
        'Key': 'deletion_protection.enabled',
        'Value': 'true',
    }

    res = client.describe_load_balancer_attributes(
        LoadBalancerArn=lb_arn
    )

    if lb_deletion_protection not in res['Attributes']:
        res = client.modify_load_balancer_attributes(
            LoadBalancerArn=lb_arn,
            Attributes=[
                lb_deletion_protection,
            ]
        )

    if lb_deletion_protection in res['Attributes']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response

def ELB9(**kwargs):
    """ Classic Load Balancers should have cross-zone load balancing enabled

    fix control: [ELB.9] This control checks whether cross-zone load balancing is enabled for Classic Load Balancers. This control fails if cross-zone load balancing is not enabled for a Classic Load Balancer
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    lb_name = resource['Id'].split("/")[-1]

    res = client.modify_load_balancer_attributes(
        LoadBalancerName=lb_name,
        LoadBalancerAttributes={
            'CrossZoneLoadBalancing': {
                'Enabled': True
            }
        }
    )
    if res['LoadBalancerAttributes']['CrossZoneLoadBalancing']["Enabled"] == True:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    print(response)
    return response
    '''
    if lb_deletion_protection not in res['Attributes']:
        res = client.modify_load_balancer_attributes(
            LoadBalancerArn=lb_arn,
            Attributes=[
                lb_deletion_protection,
            ]
        )

    if lb_deletion_protection in res['Attributes']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    '''
    print(res)
    return res

##################
# Fix EC2 Finding
##################

def EC22(**kwargs):
    """ The VPC default security group should not allow inbound and outbound traffic

    fix control: [EC2.2] This AWS control checks that the default security group of a VPC does not allow inbound or outbound traffic.
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']
    sg_id = resource['Id'].split('/')[1]

    res = client.describe_security_groups(
        GroupIds=[
            sg_id,
        ],
    )

    if res['SecurityGroups'][0]['IpPermissionsEgress'] != []:
        client.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=res['SecurityGroups'][0]['IpPermissionsEgress']
        )

    if res['SecurityGroups'][0]['IpPermissions'] != []:
        client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=res['SecurityGroups'][0]['IpPermissions']
        )

    res = client.describe_security_groups(
        GroupIds=[
            sg_id,
        ],
    )

    if res['SecurityGroups'][0]['IpPermissionsEgress'] == [] and res['SecurityGroups'][0]['IpPermissions'] == []:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


##################
# Fix RDS Finding
##################

def RDS8(**kwargs):
    """ RDS DB instances should have deletion protection enabled

    fix control: [RDS.8] This control checks whether RDS DB instances have deletion protection enabled.
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    rds_identifier = resource['Details']['AwsRdsDbInstance']['DBInstanceIdentifier']
    res = client.modify_db_instance(
        DBInstanceIdentifier=rds_identifier,
        DeletionProtection=True
    )
    if res['DBInstance']['DeletionProtection'] is True:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def RDS9(**kwargs):
    """Database logging should be enabled

    fix control: [RDS.9] This control checks whether the following Amazon RDS logs are enabled and sent to CloudWatch Logs:
                    Oracle: (Alert, Audit, Trace, Listener),
                    PostgreSQL: (Postgresql, Upgrade),
                    MySQL: (Audit, Error, General, SlowQuery),
                    MariaDB: (Audit, Error, General, SlowQuery),
                    SQL Server: (Error, Agent),
                    Aurora: (Audit, Error, General, SlowQuery),
                    Aurora-MySQL: (Audit, Error, General, SlowQuery),
                    Aurora-PostgreSQL: (Postgresql).
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']
    rds_cwlogexpconf_type = {
        "postgres": ["postgresql", "upgrade"],
        "oracle": ["alert", "audit", "listener", "trace"],
        "mysql": ["audit", "error", "general", "slowquery"],
        "sqlserver": ["error"]
    }

    rds_identifier = resource['Details']['AwsRdsDbInstance']['DBInstanceIdentifier']
    rds_engine = resource['Details']['AwsRdsDbInstance']['Engine']
    rds_engine_version = resource['Details']['AwsRdsDbInstance']['EngineVersion']
    rds_cwlogexpconf = {}
    if rds_engine == 'postgres':
        rds_cwlogexpconf['EnableLogTypes'] = rds_cwlogexpconf_type['postgres']
    if rds_engine in 'oracle-se2|oracle-ee|oracle-se1|oracle-se':
        rds_cwlogexpconf['EnableLogTypes'] = rds_cwlogexpconf_type['oracle']
    if rds_engine in 'mysql|mariadb':
        rds_cwlogexpconf['EnableLogTypes'] = rds_cwlogexpconf_type['mysql']
    if rds_engine in 'sqlserver-ex':
        rds_cwlogexpconf['EnableLogTypes'] = rds_cwlogexpconf_type['sqlserver']

    res = client.describe_db_instances(
        DBInstanceIdentifier=rds_identifier,
    )

    logTypesToEnable = []
    if 'EnabledCloudwatchLogsExports' in res['DBInstances'][0]:
        logTypesToEnable = res['DBInstances'][0]['EnabledCloudwatchLogsExports']

    if 'PendingCloudwatchLogsExports' in res['DBInstances'][0]['PendingModifiedValues']:
        logTypesToEnable = res['DBInstances'][0]['PendingModifiedValues']['PendingCloudwatchLogsExports']['LogTypesToEnable']

    if logTypesToEnable == rds_cwlogexpconf['EnableLogTypes']:
        response['Fixed'] = True
    else:
        if rds_engine == 'postgres' and rds_engine_version == '9.6.5':
            response['Fixed'] = 'Not Support postgres 9.6.5'
        else:
            res = client.modify_db_instance(
                DBInstanceIdentifier=rds_identifier,
                CloudwatchLogsExportConfiguration=rds_cwlogexpconf
            )
            logTypesToEnable = res['DBInstance']['PendingModifiedValues']['PendingCloudwatchLogsExports']['LogTypesToEnable']
            if logTypesToEnable == rds_cwlogexpconf['EnableLogTypes']:
                response['Fixed'] = True
            else:
                response['Fixed'] = False
    return response


def RDS20(**kwargs):
    """ An RDS event notifications subscription should be configured for critical database instance events

    fix control: [RDS.20] This control checks whether an Amazon RDS Event subscription for RDS instances is
                 configured to notify on event categories of both "maintenance", "configuration change", and "failure".
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    subscription_name = resource['Id'].split(':')[-1]
    account_id = resource['Id'].split(':')[4]
    sns_topic_arn = 'arn:aws-cn:sns:cn-north-1:' + account_id + ':oap2-ims-notification'
    event_categories = [
        "configuration change",
        "maintenance",
        "failure"
    ]

    res = None
    try:
        res = client.describe_event_subscriptions(
            SubscriptionName=subscription_name
        )['EventSubscriptionsList'][0]
    except Exception as e:
        print("Exception:", e.args)

    if res is None:
        res = client.create_event_subscription(
            SubscriptionName=subscription_name,
            SnsTopicArn=sns_topic_arn,
            SourceType='db-instance',
            EventCategories=event_categories,
            SourceIds=[subscription_name],
            Enabled=True
        )['EventSubscription']
    else:
        event_categories_current = res['EventCategoriesList']
        for event in event_categories_current:
            if event not in event_categories:
                event_categories.append(event)

        res = client.modify_event_subscription(
            SubscriptionName=subscription_name,
            SnsTopicArn=sns_topic_arn,
            SourceType='db-instance',
            EventCategories=event_categories,
            Enabled=True
        )['EventSubscription']

    if res['CustSubscriptionId'] == subscription_name:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


##################
# Fix S3 Finding
##################

def S32(**kwargs):
    """ S3 buckets should prohibit public read access

    fix control: [S3.2] This AWS control checks whether your S3 buckets allow public read access by evaluating
                 the Block Public Access settings, the bucket policy, and the bucket access control list (ACL).
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    bucket = resource['Id'].split(':')[-1]

    res = client.get_bucket_policy(Bucket=bucket)
    policy = json.loads(res['Policy'])

    for pl in policy['Statement']:
        if pl['Action'] == 's3:GetObject' and pl['Principal'] == '*' and pl['Effect'] == 'Allow':
            pl_pra = pl
            policy['Statement'].remove(pl)

    client.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(policy)
    )
    res = client.get_bucket_policy(Bucket=bucket)
    if pl_pra not in json.loads(res['Policy'])['Statement']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def S33(**kwargs):
    """ S3 buckets should prohibit public write access

    fix control: [S3.3] This AWS control checks whether your S3 buckets allow public write access
                 by evaluating the Block Public Access settings, the bucket policy, and the bucket access control list (ACL).
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    bucket = resource['Id'].split(':')[-1]

    res = client.get_bucket_policy(Bucket=bucket)
    policy = json.loads(res['Policy'])

    for sm in policy['Statement']:
        if sm['Effect'] == 'Allow' and sm['Principal'] == '*' and sm['Action'] in 's3:PutObject|s3:*':
            sm['Action'] = [
                "s3:ListBucket",
                "s3:GetObject"
            ]

    if policy != json.loads(res['Policy']):
        client.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps(policy)
        )
        res = client.get_bucket_policy(Bucket=bucket)

    if '"Action": "s3:*"' not in res['Policy'] and '"Action": "s3:PutObject"' not in res['Policy']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def S34(**kwargs):
    """ S3 buckets should have server-side encryption enabled

    fix control: [S3.4] This AWS control checks that your Amazon S3 bucket either has Amazon S3 default encryption enabled
                 or that the S3 bucket policy explicitly denies put-object requests without server side encryption.
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    bucket = resource['Id'].split(':')[-1]
    res = {}
    try:
        res = client.get_bucket_encryption(Bucket=bucket)
    except Exception as e:
        print("Exception:", e.args)

    if 'ServerSideEncryptionConfiguration' not in res:
        client.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        },
                        'BucketKeyEnabled': False
                    },
                ]
            }
        )
        res = client.get_bucket_encryption(
            Bucket=bucket
        )

    if 'Rules' in res['ServerSideEncryptionConfiguration']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def S35(**kwargs):
    """ S3 buckets should require requests to use Secure Socket Layer

    fix control: [S3.5] This AWS control checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL).
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    bucket = resource['Id'].split(':')[-1]
    deny_http = {
        "Sid": "DenyAccessOfHTTP",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": resource['Id'] + "/*",
        "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    }
    policy = {}

    try:
        res = client.get_bucket_policy(Bucket=bucket)
        policy = json.loads(res['Policy'])
    except Exception as e:
        print("Exception:", e.args)

    if policy == {}:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                deny_http
            ]
        }
    elif deny_http not in policy['Statement']:
        policy['Statement'].append(deny_http)

    client.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(policy)
    )
    res = client.get_bucket_policy(Bucket=bucket)
    if deny_http in json.loads(res['Policy'])['Statement']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def S36(**kwargs):
    """ S3 permissions granted to other AWS accounts in bucket policies should be restricted

    fix control: [S3.6] This control checks whether the S3 bucket policy allows sensitive bucket-level
                 or object-level actions from a principal in another AWS account. The control fails if
                 any of the following actions are allowed in the S3 bucket policy for a principal in another AWS account:
                 s3:DeleteBucketPolicy, s3:PutBucketAcl, s3:PutBucketPolicy, s3:PutObjectAcl, and s3:PutEncryptionConfiguration.
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    bucket = resource['Id'].split(':')[-1]

    res = client.get_bucket_policy(Bucket=bucket)
    policy = json.loads(res['Policy'])

    if "DenyDeletePutObj" in res['Policy']:
        deny_policy_index = [ policy['Statement'].index(i) for i in policy['Statement'] if 'Sid' in i and i['Sid'] == 'DenyDeletePutObj' ][0]
        deny_policy = policy['Statement'][deny_policy_index]
        policy['Statement'].remove(deny_policy)
        if type(deny_policy['Principal']['AWS']) != list:
            deny_policy['Principal']['AWS'] = [deny_policy['Principal']['AWS']]
        if type(deny_policy['Resource']) != list:
            deny_policy['Resource'] = [deny_policy['Resource']]
    else:
        deny_policy = {
            "Sid": "DenyDeletePutObj",
            "Effect": "Deny",
            "Principal": {
                'AWS': []
            },
            "Action": [
                "s3:DeleteBucketPolicy",
                "s3:PutBucketAcl",
                "s3:PutBucketPolicy",
                "s3:PutEncryptionConfiguration",
                "s3:PutObjectAcl"
            ],
            "Resource": []
        }

    for pl in policy['Statement']:
        if 's3:ListBucketByTags' in pl['Action']:
            pl['Action'].remove('s3:ListBucketByTags')
        if 'arn:aws-cn:iam:' in json.dumps(pl['Principal']) and pl['Ef2fect'] == 'Allow' and pl['Resource'] == (resource['Id'] + "/*"):
            if type(pl['Principal']['AWS']) == list:
                for p in pl['Principal']['AWS']:
                    if p not in deny_policy['Principal']['AWS']:
                        deny_policy['Principal']['AWS'].append(p)
            else:
                if pl['Principal']['AWS'] not in deny_policy['Principal']['AWS']:
                    deny_policy['Principal']['AWS'].append(pl['Principal']['AWS'])

            if type(pl['Resource']) == list:
                for s in pl['Resource']:
                    if s not in deny_policy['Resource']:
                        deny_policy['Resource'].append(s)
            else:
                if pl['Resource'] not in deny_policy['Resource']:
                    deny_policy['Resource'].append(pl['Resource'].split('/')[0])
                    deny_policy['Resource'].append(pl['Resource'])

    policy['Statement'].append(deny_policy)
    client.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(policy)
    )
    res = client.get_bucket_policy(Bucket=bucket)
    if deny_policy in json.loads(res['Policy'])['Statement']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response

def S39(**kwargs):
    """ S3 bucket server access logging should be enabled

    fix control: [S3.9] This control checks if an Amazon S3 Bucket has server access logging enabled to a chosen target bucket.
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    bucket = resource['Id'].split(':')[-1]
    client.put_bucket_logging(
        Bucket=bucket,
        BucketLoggingStatus={
            'LoggingEnabled': {
                'TargetBucket': bucket,
                'TargetPrefix': 'selfserverlog/'
            }
        }
    )
    res = client.get_bucket_logging(Bucket=bucket)
    if 'LoggingEnabled' in res:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


##################
# Fix SNS Finding
##################

def SNS1(**kwargs):
    """ SNS topics should be encrypted at-rest using AWS KMS

    fix control: [SNS.1] This control checks whether an Amazon SNS topic is encrypted at rest using AWS KMS.
    fix by CFN: False
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']
    topic_name = resource['Id'].split(':')[-1]

    if topic_name == 'oap2-ims-notification':
        client.set_topic_attributes(
            TopicArn=resource['Id'],
            AttributeName='KmsMasterKeyId',
            AttributeValue='arn:aws-cn:kms:cn-north-1:843403612003:key/9cd7c588-846d-46c6-b81c-3b932f5bd70d'
        )
    else:
        client.set_topic_attributes(
            TopicArn=resource['Id'],
            AttributeName='KmsMasterKeyId',
            AttributeValue='alias/aws/sns'
        )

    res = client.get_topic_attributes(
        TopicArn=resource['Id']
    )
    if 'KmsMasterKeyId' in res['Attributes']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


##################
# Fix SQS Finding
##################

def SQS1(**kwargs):
    """ Amazon SQS queues should be encrypted at rest

    fix control: [SQS.1] This control checks whether Amazon SQS queues are encrypted at rest.
    fix by CFN: False
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']
    account_id = resource['Id'].split(':')[-2]
    role_arn = 'arn:aws-cn:iam::' + account_id + ':role/oap2-ims/ims-service-role'
    queue_name = resource['Id'].split(':')[-1]
    queue_url = '/'.join(['https://sqs.cn-north-1.amazonaws.com.cn', account_id, queue_name])

    customer_kms_sqs_policy = {
        "Version": "2012-10-17",
        "Id": "key-consolepolicy-3",
        "Statement": [
            {
                "Sid": "Allow use of the key for AWS services",
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "s3.amazonaws.com",
                        "sns.amazonaws.com",
                        "events.amazonaws.com"
                    ]
                },
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:CreateGrant",
                    "kms:DescribeKey"
                ],
                "Resource": "*"
            },
            {
                "Sid": "Allow access through Simple Queue Service (SQS) for all principals in the account that are authorized to use SQS",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "*"
                },
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:CreateGrant",
                    "kms:DescribeKey"
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "kms:CallerAccount": account_id,
                        "kms:ViaService": "sqs.cn-north-1.amazonaws.com"
                    }
                }
            },
            {
                "Sid": "Allow direct access to key metadata to the account",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws-cn:iam::" + account_id + ":root"
                },
                "Action": [
                    "kms:Describe*",
                    "kms:Get*",
                    "kms:List*",
                    "kms:RevokeGrant"
                ],
                "Resource": "*"
            },
            {
                "Sid": "Allow access for Key Administrators",
                "Effect": "Allow",
                "Principal": {
                    "AWS": role_arn
                },
                "Action": [
                    "kms:Create*",
                    "kms:Describe*",
                    "kms:Enable*",
                    "kms:List*",
                    "kms:Put*",
                    "kms:Update*",
                    "kms:Revoke*",
                    "kms:Disable*",
                    "kms:Get*",
                    "kms:Delete*",
                    "kms:TagResource",
                    "kms:UntagResource",
                    "kms:ScheduleKeyDeletion",
                    "kms:CancelKeyDeletion"
                ],
                "Resource": "*"
            }
        ]
    }
    alias_name = 'alias/customer-kms-sqs'
    key_description = 'CMK of SQS'
    alias_name = create_kmskey(
        RoleArn=role_arn,
        AliasName=alias_name,
        KeyPolicy=customer_kms_sqs_policy,
        KeyDescription=key_description
    )
    client.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={'KmsMasterKeyId': alias_name}
    )

    res = client.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=['All']
    )
    if 'KmsMasterKeyId' in res['Attributes']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


##########################
# Fix API Gateway Finding
##########################

def APIGateway1(**kwargs):
    """ API Gateway REST and WebSocket API execution logging should be enabled

    fix control: [APIGateway.1] This control checks whether all stages of Amazon API Gateway REST
                 and WebSocket APIs have logging enabled. The control fails if logging is not enabled
                 for all methods of a stage or if loggingLevel is neither ERROR nor INFO.
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    res = client.update_stage(
        restApiId=resource['Id'].split('/')[2],
        stageName=resource['Id'].split('/')[4],
        patchOperations=[
            {
                'op': 'replace',
                'path': '/*/*/logging/loglevel',
                'value': 'ERROR'
            }
        ]
    )
    if res['methodSettings']['*/*']['loggingLevel'] == 'ERROR':
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


##########################
# Fix DynamoDB Finding
##########################

def DynamoDB1(**kwargs):
    """ DynamoDB tables should automatically scale capacity with demand

    fix control: [DynamoDB.1] This control checks whether a DynamoDB table can scale its read or write capacity as needed.
                 This control passes if the table uses an on-demand capacity mode or if the table uses provisioned mode with automatic scaling configured
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    res = client.update_table(
        TableName=resource['Id'].split('/')[1],
        BillingMode='PAY_PER_REQUEST'
    )
    if res['TableDescription']['BillingModeSummary'] == 'PAY_PER_REQUEST':
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def DynamoDB2(**kwargs):
    """ DynamoDB tables should have point-in-time recovery enabled

    fix control: [DynamoDB.2] This control checks whether point-in-time recovery (PITR) is enabled for a DynamoDB table.
    fix by CFN: True
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    res = client.update_continuous_backups(
        TableName=resource['Id'].split('/')[1],
        PointInTimeRecoverySpecification={
            'PointInTimeRecoveryEnabled': True
        }
    )
    if res['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'] == 'ENABLED':
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


##########################
# Fix CloudTrail Finding
##########################

def CloudTrail1(**kwargs):
    """ CloudTrail should be enabled and configured with at least one multi-region trail

    fix control: [CloudTrail.1] This AWS control checks that there is at least one multi-region AWS CloudTrail trail.
    fix by CFN: False
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    resources = client.describe_trails()
    res_update = []
    for resource in resources['trailList']:
        if resource['IncludeGlobalServiceEvents'] is False:
            resource = client.update_trail(
                Name=resource['TrailARN'],
                IncludeGlobalServiceEvents=True,
            )
        if resource['IsMultiRegionTrail'] is False and resource['IncludeGlobalServiceEvents'] is True:
            res = client.update_trail(
                Name=resource['TrailARN'],
                IsMultiRegionTrail=True,
            )
            if res['IsMultiRegionTrail'] is True:
                res_update.append(True)
            else:
                res_update.append(False)
    if False not in res_update:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def CloudTrail2(**kwargs):
    """ CloudTrail should have encryption at-rest enabled

    fix control: [CloudTrail.2] This AWS control checks whether AWS CloudTrail is configured to
                 use the server side encryption (SSE) AWS Key Management Service (AWS KMS) customer
                 master key (CMK) encryption. The check will pass if the KmsKeyId is defined
    fix by CFN: False
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']
    oap2_ims_kms_cloudtrail = 'arn:aws-cn:kms:cn-north-1:605492383956:key/aefc7a10-5302-4806-a423-4c1971ff9360'

    res = client.get_trail(
        Name=resource['Id']
    )

    if 'KmsKeyId' not in res['Trail']:
        update_kmskey_policy(account_id=resource['Id'].split(':')[4])
        res['Trail'] = client.update_trail(
            Name=resource['Id'],
            KmsKeyId=oap2_ims_kms_cloudtrail,
        )

    if 'KmsKeyId' in res['Trail']:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def CloudTrail4(**kwargs):
    """ CloudTrail log file validation should be enabled

    fix control: [CloudTrail.4] This AWS control checks whether CloudTrail log file validation is enabled.
    fix by CFN: False
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    res = client.get_trail(
        Name=resource['Id']
    )

    if res['Trail']['LogFileValidationEnabled'] is False:
        update_kmskey_policy(account_id=resource['Id'].split(':')[4])
        res['Trail'] = client.update_trail(
            Name=resource['Id'],
            EnableLogFileValidation=True
        )

    if res['Trail']['LogFileValidationEnabled'] is True:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


##########################
# Fix IAM Finding
##########################

def IAM2(**kwargs):
    """IAM users should not have IAM policies attached

    fix control: [IAM.2] This Amazon Web Services control checks that none of your
                 IAM users have policies attached. Instead, IAM users must inherit permissions
                 from IAM groups or roles.
    fix by CFN: False
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    username = resource['Details']['AwsIamUser']['UserName']
    policy_list = client.list_attached_user_policies(UserName=username)
    groupname = username.replace("usr", "grp")

    existed_group = client.list_groups()['Groups'];
    groupslist = list()
    for group in existed_group:
        groupslist.append(group['GroupName'])

    print(policy_list)
    if groupname not in groupslist:
        client.create_group(GroupName=groupname)

    policy_arns = policy_list['AttachedPolicies'][0]['PolicyArn']
    client.attach_group_policy(GroupName=groupname,PolicyArn=policy_arns)
    client.detach_user_policy(UserName=username,PolicyArn=policy_arns)
    print(username,policy_arns)
    client.add_user_to_group(GroupName=groupname,UserName=username)

    new_policy_list = client.list_attached_user_policies(UserName=username)

    if len(new_policy_list['AttachedPolicies']) == 0:
        response['Fixed'] = 'True'

    else:
        response['Fixed'] = 'False'

    return response


def IAM3(**kwargs):
    """IAM users' access keys should be rotated every 90 days or less

    fix control: [IAM.3] This Amazon Web Services control checks whether the active access keys are rotated within 90 days.
    fix by CFN: false

    """
    response = {}
    client = kwargs['client']
    resource = kwargs['resource']
    finding = kwargs['finding']
    sechub_client = kwargs['sechub_client']
    username = resource['Details']['AwsIamUser']['UserName']
    account_id = resource['Id'].split(':')[4]

    today = datetime.now()
    today_utc = today.replace(tzinfo=timezone.utc)
    access_keys = client.list_access_keys(UserName=username)

    if len(access_keys['AccessKeyMetadata']) > 0:
        user = client.get_user(UserName=username)
        user_tags = user['User']['Tags'] if 'Tags' in user['User'] else None
        for ak in access_keys['AccessKeyMetadata']:
            if ak['Status'] == 'Active':
                access_key_id = ak['AccessKeyId']
                create_date = ak['CreateDate']
                create_date_utc = create_date.replace(tzinfo=timezone.utc)
                ak_lu = client.get_access_key_last_used(AccessKeyId=access_key_id)
                access_key_last_used = ak_lu['AccessKeyLastUsed'].get('LastUsedDate', create_date)
                access_key_last_used_utc = access_key_last_used.replace(tzinfo=timezone.utc)
                access_key_interval_last_used = (today_utc - access_key_last_used_utc).days
                access_key_interval_create = (today_utc - create_date_utc).days

                if finding['Workflow']['Status'] == 'SUPPRESSED':
                    if access_key_interval_last_used < 90 and access_key_interval_create > 365:
                        response = UnSuppressed(
                            client=sechub_client,
                            finding=finding
                        )
                    if access_key_interval_last_used < 90 and 90 < access_key_interval_create < 365:
                        response['Fixed'] = 'Suppressed Done Already'

                if finding['Workflow']['Status'] == 'NEW' and access_key_interval_last_used < 90 and access_key_interval_create > 90:
                    if user_tags is not None:
                        for tag in user_tags:
                            if tag['Key'] == 'Email':
                                receivers = tag['Value'].replace(' ', ';')+ ';dw_133_aws-ops@daimler.com;jian.j.xu@daimler.com'
                            if tag['Key'] == 'Owner':
                                owner = tag['Value']
                            if tag['Key'] == 'Project':
                                project = tag['Value']
                        subject = '[Alarm] AWS AKSK Rotation Every 90 days of your owned IAM user [{}]'.format(username)
                        body = open(os.path.join(os.path.dirname(__file__), 'mail.html')).read().format(
                            Owner=owner,
                            UserName=username,
                            AccountID=account_id,
                            Project=project,
                            AccessKeyId=access_key_id,
                            AccessKeyAge=access_key_interval_create
                        )

                        send_mail(
                            Receivers=receivers,
                            Subject=subject,
                            Body=body
                        )
                        response['Fixed'] = 'Email sent'
                    else:
                        response['Fixed'] = 'Email not sent, please add tags'
    return response


def IAM5(**kwargs):
    """MFA should be enabled for all IAM users that have a console password

    fix control: [IAM.5] This Amazon Web Services control checks whether Amazon Web Services Multi-Factor
                 Authentication (MFA) is enabled for all Amazon Web Services Identity and Access Management
                 (IAM) users that use a console password.
    fix by CFN：False
    """

    response = {}
    client = kwargs['client']
    resource = kwargs['resource']
    username = resource['Details']['AwsIamUser']['UserName']
    mfa_device_list = client.list_mfa_devices(UserName=username)
    mfa_devices = mfa_device_list['MFADevices']
    print(username, mfa_devices)

    if len(mfa_devices)==0:
        client.delete_login_profile(UserName=username)
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def IAM7(**kwargs):
    """ Password policies for IAM users should have strong configurations

    fix control: [IAM.7] This AWS control checks whether the account password policy
                 for IAM users uses the following recommended configurations:
                 RequireUppercaseCharacters: true,
                 RequireLowercaseCharacters: true,
                 RequireSymbols: true,
                 RequireNumbers: true,
                 MinimumPasswordLength: 14.
    fix by CFN: False
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    res = client.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        MaxPasswordAge=90,
        PasswordReusePrevention=24
    )

    if res['ResponseMetadata']['HTTPStatusCode'] == 200:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def IAM8(**kwargs):
    """Unused IAM user credentials should be removed

    fix control:[IAM.8] This control checks whether your IAM users have passwords
                        or active access keys that were not used within the previous 90 days.
    fix by CFN: False

    """

    response = {}
    result = []

    client = kwargs['client']
    resource = kwargs['resource']
    username = resource['Details']['AwsIamUser']['UserName']

    today = datetime.now()
    today_utc = today.replace(tzinfo=timezone.utc)

    lp = None
    try:
        lp = client.get_login_profile(
            UserName=username,
        )
    except Exception as e:
        print("Exception:", e.args)

    if lp is not None:
        user = client.get_user(UserName=username)
        console_last_used = user['User']['PasswordLastUsed']
        console_last_used_utc = console_last_used.replace(tzinfo=timezone.utc)
        console_interval = (today_utc - console_last_used_utc).days

        if console_interval > 90:
            res = client.delete_login_profile(UserName=username)
            if res['ResponseMetadata']['HTTPStatusCode'] == 200:
                result.append('right')
            else:
                result.append('wrong')

    access_keys = client.list_access_keys(UserName=username)
    if len(access_keys['AccessKeyMetadata']) > 0:
        for ak in access_keys['AccessKeyMetadata']:
            if ak['Status'] == 'Active':
                access_key_id = ak['AccessKeyId']
                create_date = ak['CreateDate']
                ak_lu = client.get_access_key_last_used(AccessKeyId=access_key_id)
                access_key_last_used = ak_lu['AccessKeyLastUsed'].get('LastUsedDate', create_date)
                access_key_last_used_utc = access_key_last_used.replace(tzinfo=timezone.utc)
                access_key_interval = (today_utc - access_key_last_used_utc).days

                if access_key_interval > 90:
                    res = client.update_access_key(
                        UserName=username,
                        AccessKeyId=access_key_id,
                        Status='Inactive'
                    )
                    if res['ResponseMetadata']['HTTPStatusCode'] == 200:
                        result.append('right')
                    else:
                        result.append('wrong')

    if 'wrong' not in result:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


def CIS13(**kwargs):
    """ Ensure credentials unused for 90 days or greater are disabled

    fix control: [CIS.1.3] Amazon IAM users can access Amazon Web Services
                 resources using different types of credentials, such as
                passwords or access keys. It is recommended that all credentials
                that have been unused in 90 or greater days be removed or
                deactivated.
    fix by CFN: False
    """

    response = {}
    response['Fixed'] = 'Handled by IAM8 handler'
    return response


def CIS14(**kwargs):
    """ Ensure access keys are rotated every 90 days or less

    fix control: [CIS.1.4] Access keys consist of an access key ID and secret
                 access key, which are used to sign programmatic requests that
                 you make to Amazon Web Services. It is recommended that all
                 access keys be regularly rotated.
    fix by CFN: False
    """

    response = {}
    response['Fixed'] = 'Handled by IAM3 handler'
    return response


def CIS110(**kwargs):
    """ Ensure IAM password policy prevents password reuse

    fix control: [CIS.1.10] IAM password policies can prevent the reuse of a given password by the same user.
                 It is recommended that the password policy prevent the reuse of passwords.
    fix by CFN: False
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    policy = client.get_account_password_policy()

    if policy['PasswordPolicy']['PasswordReusePrevention'] != 24:
        client.update_account_password_policy(
            PasswordReusePrevention=24
        )
        policy = client.get_account_password_policy()

    if policy['PasswordPolicy']['PasswordReusePrevention'] == 24:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


##########################
# Fix KMS Finding
##########################

def CIS28(**kwargs):
    """ Ensure rotation for customer created CMKs is enabled

    fix control: [CIS.2.8] AWS Key Management Service (KMS) allows customers to rotate the
                 backing key which is key material stored within the KMS which is tied to
                 the key ID of the Customer Created customer master key (CMK). It is the backing
                 key that is used to perform cryptographic operations such as encryption and decryption.
                 It is recommended that CMK key rotation be enabled
    fix by CFN: False
    """

    response = {}

    client = kwargs['client']
    resource = kwargs['resource']

    res = client.get_key_rotation_status(
        KeyId=resource['Id']
    )

    if res['KeyRotationEnabled'] is False:
        client.enable_key_rotation(
            KeyId=resource['Id']
        )
        res = client.get_key_rotation_status(
            KeyId=resource['Id']
        )

    if res['KeyRotationEnabled'] is True:
        response['Fixed'] = True
    else:
        response['Fixed'] = False
    return response


##########################
# KMS Tools
##########################

def update_kmskey_policy(**kwargs):
    role_arn = 'arn:aws-cn:iam::605492383956:role/aws-role-006-0000-u-cldtrl'
    keyId = 'aefc7a10-5302-4806-a423-4c1971ff9360'
    sts_session = switch_role(RoleArn=role_arn)
    client = sts_session.client('kms')

    res = client.get_key_policy(
        KeyId=keyId,
        PolicyName='default'
    )
    policies = json.loads(res['Policy'])

    account_id = kwargs['account_id']
    root_arn = 'arn:aws-cn:iam::' + account_id + ':root'
    cloudtrail_arn = 'arn:aws-cn:cloudtrail:*:' + account_id + ':trail/*'

    for policy in policies['Statement']:
        if policy['Sid'] == 'Allow use of the key' and root_arn not in policy['Principal']['AWS']:
            policy['Principal']['AWS'].append(root_arn)
        if policy['Sid'] == 'Enable CloudTrail Encrypt Permissions' and cloudtrail_arn not in policy['Condition']['StringLike']['kms:EncryptionContext:aws:cloudtrail:arn']:
            policy['Condition']['StringLike']['kms:EncryptionContext:aws:cloudtrail:arn'].append(cloudtrail_arn)

    print(policies)

    res = client.put_key_policy(
        KeyId=keyId,
        PolicyName='default',
        Policy=json.dumps(policies)
    )

    print(res)


def create_kmskey(**kwargs):
    role_arn = kwargs['RoleArn']
    sts_session = switch_role(RoleArn=role_arn)
    client = sts_session.client('kms')

    key_policy = kwargs['KeyPolicy']
    alias_name = kwargs['AliasName']
    res = client.list_aliases()
    if alias_name not in json.dumps(res['Aliases'], cls=ComplexEncoder):
        res = client.create_key(
            Policy=json.dumps(key_policy),
            Description=kwargs['KeyDescription']
        )
        key_id = res['KeyMetadata']['KeyId']
        client.enable_key_rotation(KeyId=key_id)
        client.create_alias(AliasName=alias_name, TargetKeyId=key_id)

    return alias_name


##########################
# Finding Suppressed
##########################

def Suppressed(**kwargs):
    ''' Finding Suppressed for special exception'''

    response = {}

    client = kwargs['client']
    finding = kwargs['finding']
    findingIdentifiers = [
        {
            'Id': finding['Id'],
            'ProductArn': finding['ProductArn']
        }
    ]
    note = {
        'Text': 'As business need, suppressed',
        'UpdatedBy': 'Daimler AWS Security Hub Admin'
    }
    workflow = {'Status': 'SUPPRESSED'}
    res = client.batch_update_findings(FindingIdentifiers=findingIdentifiers,
                                       Note=note,
                                       Workflow=workflow)

    if res['ResponseMetadata']['HTTPStatusCode'] == 200:
        response['Fixed'] = 'Suppressed Done'
    else:
        response['Fixed'] = 'Suppressed Wrong'
    return response


def UnSuppressed(**kwargs):
    ''' Finding UnSuppressed for special exception'''

    response = {}

    client = kwargs['client']
    finding = kwargs['finding']
    findingIdentifiers = [
        {
            'Id': finding['Id'],
            'ProductArn': finding['ProductArn']
        }
    ]
    note = {
        'Text': 'As business fixed, dont not suppressed',
        'UpdatedBy': 'Daimler AWS Security Hub Admin'
    }
    workflow = {'Status': 'NEW'}
    res = client.batch_update_findings(FindingIdentifiers=findingIdentifiers,
                                       Note=note,
                                       Workflow=workflow)

    if res['ResponseMetadata']['HTTPStatusCode'] == 200:
        response['Fixed'] = 'UnSuppressed Done'
    else:
        response['Fixed'] = 'UnSuppressed Wrong'
    return response


##########################
# GuardDuty Handler
##########################

def GuardDuty(**kwargs):
    response = {}
    response['Fixed'] = 'in coding'
    return response


##########################
# Access Analyzer Handler
##########################

def IAMAccessAnalyzer(**kwargs):
    response = {}
    response['Fixed'] = 'in coding'
    return response


##########################
# Finding Handler Gateway
##########################

@findings_handler.lambda_function(name='findings-handler')
def lambda_handler(event, context):
    role_arn = event['role_arn']
    finding = event['finding']
    handler = event['handler']
    trigger = event['trigger']
    resources = finding['Resources']

    responses = {}
    responses['ID'] = finding['Id']
    responses['Title'] = finding['Title']
    responses['AwsAccountId'] = finding['AwsAccountId']
    responses['Handler'] = handler
    responses['Trigger'] = trigger
    responses['ProductName'] = finding['ProductFields']['aws/securityhub/ProductName']
    responses['Resources'] = []

    deny_handler_trigger_automatically = ['S32', 'S36','ELB9']

    if trigger == 'Automatically' and handler in deny_handler_trigger_automatically:
        response = {}
        response['Resource'] = resources[0]['Id']
        response['Fixed'] = 'Deny to trigger automatically'
    else:
        sts_session = switch_role(RoleArn=role_arn)
        for resource in resources:
            response = {}
            response['Resource'] = resource['Id']
            resource_type = resource['Id'].split(':')[2]
            if resource_type == '' and 'CloudTrail' in finding['Title']:
                resource_type = 'cloudtrail'
            if resource_type == '' and 'IAM' in finding['Title']:
                resource_type = 'iam'
            if resource_type == 'elasticloadbalancing' and resource['Type'] == 'AwsElbv2LoadBalancer':
                resource_type = 'elbv2'
            if resource_type == 'elasticloadbalancing' and resource['Type'] == "AwsElbLoadBalancer":
                resource_type = 'elb'
            if handler in 'Suppressed|UnSuppressed':
                resource_type = 'securityhub'
            client = sts_session.client(resource_type.lower())

            this_mod = sys.modules[__name__]
            print('Finding Handler: ', '{}(client={}, resource="{}")'.format(handler, client, resource))
            print({'Trigger ' + handler: trigger})
            try:
                finding_handler = getattr(this_mod, handler)
                if handler in 'Suppressed|UnSuppressed':
                    response_handler = finding_handler(client=client, finding=finding)
                else:
                    sechub_client = sts_session.client('securityhub')
                    response_handler = finding_handler(client=client, resource=resource, finding=finding, sechub_client=sechub_client)
                response.update(response_handler)
            except AttributeError as e:
                print(e.args)
                response['Fixed'] = 'Handler not found or sth wrong'
    responses['Resources'].append(response)
    groupId = get_wechat_group(groupName='AWS SecurityHub Support')['data'][0]['groupId']
    title = f"{responses['ProductName']} Finding"
    description = (f"<div class=\"highlight\">{responses['Title']}</div>"
                   f"<div class=\"normal\">Resource: {responses['Resources'][0]['Resource']}</div>"
                   f"<div class=\"gray\">Handler: {responses['Handler']}</div>"
                   f"<div class=\"highlight\">Trigger: {responses['Trigger']}</div>"
                   f"<div class=\"gray\">Fixed: {responses['Resources'][0]['Fixed']}</div>")
    send_wechat_message(
        groupId=groupId,
        title=title,
        description=description
    )
    print(responses)
    return responses
