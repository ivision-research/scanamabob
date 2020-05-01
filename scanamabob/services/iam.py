import boto3

__cache_all_users = {}


def client(context, profile=None):
    ''' Return an IAM client handle for the given context and profile '''
    access_key, secret = context.get_credentials(profile)
    return boto3.client('iam',
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret)


def resources(context, profile=None):
    ''' Return an IAM resource handle for the given context and profile '''
    access_key, secret = context.get_credentials(profile)
    return boto3.resource('iam',
                          aws_access_key_id=access_key,
                          aws_secret_access_key=secret)


def all_users(context, profile=None):
    ''' Gets a list of all users '''
    # Use cached result if available
    if profile in __cache_all_users:
        return __cache_all_users[profile]

    iam = client(context, profile)
    usernames = []
    for page in iam.get_paginator('list_users').paginate(MaxItems=1000):
        for user in page['Users']:
            usernames.append(user['UserName'])

    # Cache result for future requests
    __cache_all_users[profile] = usernames
    return usernames
