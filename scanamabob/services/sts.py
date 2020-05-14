import boto3
from botocore.exceptions import ClientError
from scanamabob.scans import Finding, Scan, ScanSuite


def client(context, profile, **kwargs):
    ''' Return a STS client handle for the given context and profile '''
    access_key, secret = context.get_credentials(profile)
    return boto3.client('sts',
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret,
                        **kwargs)


def get_accountid(context, profile):
    return client(context, profile).get_caller_identity().get('Account')
