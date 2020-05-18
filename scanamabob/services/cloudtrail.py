import boto3


def client(context, **kwargs):
    ''' Return an IAM client handle for the given context and profile '''
    return context.session.client('cloudtrail', **kwargs)
