import boto3


def client(context, profile=None):
    access_key, secret = context.get_credentials(profile)
    return boto3.client('iam',
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret)


def resources(context, profile=None):
    access_key, secret = context.get_credentials(profile)
    return boto3.resource('iam',
                          aws_access_key_id=access_key,
                          aws_secret_access_key=secret)


def all_users(context, profile=None):
    ''' Gets a list of all users '''
    iam = client(context, profile)
    usernames = []
    for page in iam.get_paginator('list_users').paginate(MaxItems=1000):
        for user in page['Users']:
            usernames.append(user['UserName'])
    return usernames
