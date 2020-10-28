from argparse import ArgumentParser

from scanamabob.context import Context, add_context_to_argparse
from scanamabob.services.sts import get_accountid


DESCRIPTION = "Scan AWS environment for common security misconfigurations"
USAGE = f"""scanamabob summary [-h] [-r regions] [-p profiles]"""


def add_parser(main_parser):
    parser = main_parser.add_parser(
        name="summary", description=DESCRIPTION, usage=USAGE
    )
    add_context_to_argparse(parser)
    parser.set_defaults(func=command)


def iam_summary(context):
    print("## IAM")


def ec2_summary(context):
    print("## EC2")


def command(arguments):
    """ Main handler of the summary subcommand """
    context = Context(arguments.profiles, arguments.regions)

    if not context.regions_valid():
        print("Invalid regions provided, scan cancelled")
        sys.exit(1)

    for profile in context.profiles:
        context.set_profile(profile)
        accountid = get_accountid(context)
        print(f"# {profile} ({accountid})")
        iam_summary(context)
        ec2_summary(context)
