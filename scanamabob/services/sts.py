import boto3
from botocore.exceptions import ClientError
from scanamabob.scans import Finding, Scan, ScanSuite


def client(context, **kwargs):
    ''' Return a STS client handle for the given context '''
    return context.session.client('sts', **kwargs)


def get_accountid(context):
    return client(context).get_caller_identity().get('Account')
