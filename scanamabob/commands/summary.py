from argparse import ArgumentParser
from scanamabob.context import Context, add_context_to_argparse
from scanamabob.services.sts import get_accountid


DESCRIPTION = 'Scan AWS environment for common security misconfigurations'
USAGE = f'''scanamabob summary [-h] [-r regions] [-p profiles]'''
parser = ArgumentParser(description=DESCRIPTION,
                        usage=USAGE)
add_context_to_argparse(parser)


def iam_summary(context):
    print('## IAM')


def ec2_summary(context):
    print('## EC2')


def command(args):
    ''' Main handler of the summary subcommand '''
    arguments = parser.parse_args(args)
    context = Context(arguments.profiles, arguments.regions)

    if not context.regions_valid():
        print('Invalid regions provided, scan cancelled')
        sys.exit(1)

    for profile in context.profiles:
        context.set_profile(profile)
        accountid = get_accountid(context)
        print(f'# {profile} ({accountid})')
        iam_summary(context)
        ec2_summary(context)


COMMAND = {'description': DESCRIPTION,
           'function': command}
