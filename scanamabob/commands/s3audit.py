import sys
import json
from argparse import ArgumentParser
from scanamabob.context import Context, add_context_to_argparse
import scanamabob.services.s3 as s3
from scanamabob.services.sts import get_accountid

DESCRIPTION = 'Generate report on S3 access controls'
USAGE = f'''{sys.argv[0]} s3audit [-h]'''

parser = ArgumentParser(description=DESCRIPTION,
                        usage=USAGE)
add_context_to_argparse(parser)


def audit_account(context):
    accountid = s3.get_accountid(context)
    print(f'# {context.current_profile} ({accountid})')

    print('\n## Account Level Public Access\n')
    access = s3.get_account_public_access(context)

    print(f'Block grants via new ACLs: {access["BlockPublicAcls"]}')
    print(f'Block grants via any ACLs: {access["IgnorePublicAcls"]}')
    print(f'Block grants via new Policies: {access["BlockPublicPolicy"]}')
    print(f'Block grants via any Policies: {access["RestrictPublicBuckets"]}')

    print('\n## Buckets\n')

    for bucket in s3.get_all_buckets(context):
        audit_bucket(context, bucket)


def audit_bucket(context, bucket):
    print(f'### Bucket: {bucket}\n')
    access = s3.get_bucket_public_access(context, bucket)

    print('#### Public Access Blocks\n')
    print(f'Block grants via new ACLs: {access["BlockPublicAcls"]}')
    print(f'Block grants via any ACLs: {access["IgnorePublicAcls"]}')
    print(f'Block grants via new Policies: {access["BlockPublicPolicy"]}')
    print(f'Block grants via any Policies: {access["RestrictPublicBuckets"]}')

    print('\n#### Bucket Settings\n')
    settings = s3.get_bucket_settings(context, bucket)
    ownerid = s3.get_owner_id(context)

    print(f'Versioning: {settings["versioning"]}')
    print(f'MFA Delete: {settings["mfa_delete"]}')
    print(f'Service Access Logging: {settings["logging"]}')
    print(f'Static Website Hosting: {settings["hosting"]}')
    print(f'Default Encryption: {settings["encryption"]}')

    print('\n#### Bucket ACL\n')
    for grant in s3.get_bucket_acl(context, bucket)['Grants']:
        grantee = grant['Grantee']
        permission = grant['Permission']
        if grantee['Type'] == 'CanonicalUser':
            if 'DisplayName' in grantee:
                print(f"- User \"{grantee['DisplayName']}\": {permission}")
            elif grantee['ID'] == ownerid:
                print(f"- Account Owner: {permission}")
            else:
                print(f"- User \"{grantee['ID']}\": {permission}")
        elif grant['Grantee']['Type'] == 'Group':
            print(f"- Group \"{grantee['URI']}\": {permission}")

    policy = s3.get_bucket_policy(context, bucket)
    if policy:
        print('\n#### Bucket Policy\n')
        print('```.json\n' + json.dumps(policy, indent=2) + "\n```\n")

    print('\n#### Bucket Content By Access\n')
    count = 0
    grants = {}
    for s3_object in s3.iter_bucket_objects(context, bucket):
        count += 1
        key = s3_object['Key']
        # print('Getting ACL for ' + s3_object['Key'], file=sys.stderr)
        obj_acl = s3.get_object_acl(context, bucket, key)
        for grant in obj_acl.grants:
            grantee = json.dumps(grant['Grantee'])
            permission = grant['Permission']
            if grantee not in grants:
                grants[grantee] = {permission: [key]}
            elif permission not in grants[grantee]:
                grants[grantee][permission] = [key]
            else:
                grants[grantee][permission].append(key)

    for grantee_json in grants:
        grantee = json.loads(grantee_json)
        if grantee == {'Type': 'Group', 'URI': s3.PUBLIC_URI}:
            print(f'- Public:')
        elif grantee['Type'] == 'CanonicalUser':
            if 'DisplayName' in grantee:
                print(f'- User "{grantee["DisplayName"]}":')
            elif grantee['ID'] == ownerid:
                print("- Account Owner:")
            else:
                print(f'- User "{grantee["ID"]}":')
        else:
            print(f'- {grantee}:')
        for permission in grants[grantee_json].keys():
            print(f'  - {permission}:')
            for key in grants[grantee_json][permission]:
                print(f'    - {key}')

    print(f'\n{count} total object(s) in bucket\n')


def command(args):
    ''' Main handler of the s3audit subcommand '''
    arguments = parser.parse_args(args)
    context = Context(arguments.profiles, arguments.regions)
    buckets = {}
    for profile in context.profiles:
        context.current_profile = profile
        audit_account(context)

COMMAND = {'description': DESCRIPTION,
           'function': command}
