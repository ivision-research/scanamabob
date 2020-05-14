import boto3
import botocore
import json
from scanamabob.services.sts import get_accountid

PUBLIC_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'
ENC_NOT_FOUND = 'ServerSideEncryptionConfigurationNotFoundError'
__cache_buckets = {}


def client(context, profile, **kwargs):
    ''' Return an S3 client handle for the given context and profile '''
    access_key, secret = context.get_credentials(profile)
    return boto3.client('s3',
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret,
                        **kwargs)


def resources(context, profile=None, **kwargs):
    ''' Return an S3 resource handle for the given context and profile '''
    access_key, secret = context.get_credentials(profile)
    return boto3.resource('s3',
                          aws_access_key_id=access_key,
                          aws_secret_access_key=secret,
                          **kwargs)


def control(context, profile, **kwargs):
    ''' Return an S3 resource handle for the given context and profile '''
    access_key, secret = context.get_credentials(profile)
    return boto3.client('s3control',
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret,
                        **kwargs)


def get_all_buckets(context, profile):
    ''' Lists all buckets for an account. Caches results '''
    if profile in __cache_buckets:
        return __cache_buckets[profile]

    bucketrequest = client(context, profile).list_buckets()
    buckets = [x['Name'] for x in bucketrequest['Buckets']]

    __cache_buckets[profile] = buckets
    return buckets


def get_account_public_access(context, profile):
    account = get_accountid(context, profile)
    ctrl = control(context, profile)
    try:
        pub_block = ctrl.get_public_access_block(AccountId=account)
    except ctrl.exceptions.NoSuchPublicAccessBlockConfiguration:
        return {'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False}

    return pub_block['PublicAccessBlockConfiguration']


def get_bucket_public_access(context, profile, bucket):
    s3 = client(context, profile)
    try:
        pub_block = s3.get_public_access_block(Bucket=bucket)
    except:
        return {'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False}
    return pub_block['PublicAccessBlockConfiguration']


def get_bucket_acl(context, profile, bucket):
    s3 = client(context, profile)
    return s3.get_bucket_acl(Bucket=bucket)


def get_bucket_policy(context, profile, bucket):
    s3 = client(context, profile)
    try:
        return json.loads(s3.get_bucket_policy(Bucket=bucket)['Policy'])
    except botocore.exceptions.ClientError as err:
        if 'NoSuchBucketPolicy' not in err.args[0]:
            raise err
        return None


def get_bucket_settings(context, profile, bucket):
    s3 = client(context, profile)
    settings = {}

    versioning = s3.get_bucket_versioning(Bucket=bucket)
    if 'Status' in versioning:
        settings['versioning'] = versioning['Status']
    else:
        settings['versioning'] = 'Suspended'
    if 'MFADelete' in versioning:
        settings['mfa_delete'] = versioning['MFADelete']
    else:
        settings['mfa_delete'] = 'Disabled'

    logging = s3.get_bucket_logging(Bucket=bucket)
    if 'LoggingEnabled' in logging:
        settings['logging'] = logging['LoggingEnabled']['TargetBucket']
    else:
        settings['logging'] = 'Disabled'

    try:
        settings['hosting'] = s3.get_bucket_website(Bucket=bucket)
    except botocore.exceptions.ClientError as err:
        if 'NoSuchWebsiteConfiguration' not in err.args[0]:
            raise err
        settings['hosting'] = 'Disabled'

    try:
        enc = s3.get_bucket_encryption(Bucket=bucket)
        settings['encryption'] = enc['ServerSideEncryptionConfiguration']
    except botocore.exceptions.ClientError as err:
        if err.response['Error']['Code'] != ENC_NOT_FOUND:
            raise err
        settings['encryption'] = 'Disabled'

    return settings


def iter_bucket_objects(context, profile, bucket):
    paginator = client(context, profile).get_paginator('list_objects_v2')
    for objects_page in paginator.paginate(Bucket=bucket):
        if 'Contents' in objects_page:
            for s3_object in objects_page['Contents']:
                yield s3_object


def get_object_acl(context, profile, bucket, key):
    return resources(context, profile).ObjectAcl(bucket, key)


def get_owner_id(context, profile):
    return client(context, profile).list_buckets()['Owner']['ID']
