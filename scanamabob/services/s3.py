import boto3
import botocore
import json
from scanamabob.services.sts import get_accountid

PUBLIC_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'
ENC_NOT_FOUND = 'ServerSideEncryptionConfigurationNotFoundError'
__cache_buckets = {}


def client(context, **kwargs):
    ''' Return an S3 client handle for the given context and profile '''
    return context.session.client('s3', **kwargs)


def resources(context, **kwargs):
    ''' Return an S3 resource handle for the given context '''
    return context.session.resource('s3', **kwargs)


def control(context, **kwargs):
    ''' Return an S3 control handle for the given context '''
    return context.session.client('s3control', **kwargs)


def get_all_buckets(context):
    ''' Lists all buckets for an account. Caches results '''
    if context.current_profile in __cache_buckets:
        return __cache_buckets[context.current_profile]

    bucketrequest = client(context).list_buckets()
    buckets = [x['Name'] for x in bucketrequest['Buckets']]

    __cache_buckets[context.current_profile] = buckets
    return buckets


def get_account_public_access(context):
    account = get_accountid(context)
    ctrl = control(context)
    try:
        pub_block = ctrl.get_public_access_block(AccountId=account)
    except ctrl.exceptions.NoSuchPublicAccessBlockConfiguration:
        return {'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False}

    return pub_block['PublicAccessBlockConfiguration']


def get_bucket_public_access(context, bucket):
    s3 = client(context)
    try:
        pub_block = s3.get_public_access_block(Bucket=bucket)
    except:
        return {'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False}
    return pub_block['PublicAccessBlockConfiguration']


def get_bucket_acl(context, bucket):
    s3 = client(context)
    return s3.get_bucket_acl(Bucket=bucket)


def get_bucket_policy(context, bucket):
    s3 = client(context)
    try:
        return json.loads(s3.get_bucket_policy(Bucket=bucket)['Policy'])
    except botocore.exceptions.ClientError as err:
        if 'NoSuchBucketPolicy' not in err.args[0]:
            raise err
        return None


def get_bucket_settings(context, bucket):
    s3 = client(context)
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


def iter_bucket_objects(context, bucket):
    paginator = client(context).get_paginator('list_objects_v2')
    for objects_page in paginator.paginate(Bucket=bucket):
        if 'Contents' in objects_page:
            for s3_object in objects_page['Contents']:
                yield s3_object


def get_object_acl(context, bucket, key):
    return resources(context).ObjectAcl(bucket, key)


def get_owner_id(context):
    return client(context).list_buckets()['Owner']['ID']
