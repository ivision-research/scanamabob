import boto3


def client(context, profile=None, **kwargs):
    ''' Return an IAM client handle for the given context and profile '''
    access_key, secret = context.get_credentials(profile)
    return boto3.client('cloudtrail',
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret,
                        **kwargs)
