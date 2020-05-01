import sys
import time
import os
import json
from argparse import ArgumentParser
import scanamabob.scans.iam as iam
import scanamabob.scans.ec2 as ec2
import scanamabob.scans.s3 as s3
import scanamabob.scans.cloudtrail as cloudtrail
import scanamabob.scans.elb as elb
import scanamabob.scans.rds as rds
from scanamabob.context import Context, add_context_to_argparse

DESCRIPTION = 'Scan AWS environment for common security misconfigurations'
USAGE = f'''scanamabob scan [-h] [-p] [-l] [scantypes] [...]'''
parser = ArgumentParser(description=DESCRIPTION,
                        usage=USAGE)
# parser.add_argument('-o', '--output', choices=['stdout', 'json'],
#                     default='stdout',
#                     help="Output format for scan (default: stdout)")
parser.add_argument('scantypes', nargs='*',
                    help="Specific scan suite or individual scan to run (eg. iam.mfa)")
parser.add_argument('-p', '--permissions', action='store_true',
                    help="Return IAM Policy JSON needed to complete scan")
parser.add_argument('-l', '--list-scans', action='store_true',
                    help="List the scans available to run")
add_context_to_argparse(parser)


scan_suites = {
    'iam': iam.scans,
    'ec2': ec2.scans,
    's3': s3.scans,
    'cloudtrail': cloudtrail.scans,
    'elb': elb.scans,
    'rds': rds.scans
}


def scan_targets_valid(scanlist):
    valid = True
    for i in scanlist:
        if '.' in i:
            suite, scan = i.split('.')
            if suite not in scan_suites or scan not in scan_suites[suite].scans:
                print(f'{target} is not a valid scan')
                valid = False
        else:
            if i not in scan_suites:
                print(f'{i} is not a valid scan suite')
                valid = False
    return valid


def run_scans(scantypes, context):
    ''' Run the given scantypes with using the provided context '''
    findings = {}

    for profile in context.profiles:
        findings[profile] = []
        if scantypes:
            # Run user specified scans
            for scantype in scantypes:
                if '.' in scantype:
                    suite, target = scantype.split('.')
                    scan = scan_suites[suite].scans[target]
                    print(' - Running Scan "{}"'.format(scan.title))
                    scan_findings = scan.run(context, profile)
                    findings[profile].extend()
                else:
                    suite_findings = scan_suites[scantype].run(context,
                                                               profile)
                    findings[profile].extend(suite_findings)
        else:
            # Run all scans
            for suite in scan_suites:
                suite_findings = scan_suites[suite].run(context, profile)
                findings[profile].extend(suite_findings)

    print('\n{} total finding(s) from scan:'.format(len(findings)))

    for profile in findings:
        print(f'Findings from {profile} profile:')
        for finding in findings[profile]:
            print(finding.__dict__)


def get_permissions(scantypes):
    permissions = []

    if scantypes:
        # Get permissions for user specified scans
        for scantype in scantypes:
            if '.' in scantype:
                suite, target = scantype.split('.')
                scan = scan_suites[suite].scans[target]
                for permission in scan.permissions:
                    if permission not in permissions:
                        permissions.append(permission)
            else:
                suite = scan_suites[scantype]
                for permission in suite.get_permissions():
                    if permission not in permissions:
                        permissions.append(permission)
    else:
        # Get permissions for all scans
        for suite in scan_suites:
            for permission in scan_suites[suite].get_permissions():
                if permission not in permissions:
                    permissions.append(permission)

    # Format and print IAM Policy JSON
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
                "Effect": "Allow",
                "Action": sorted(permissions),
                "Resource": "*"
            }
        ]
    }
    print(json.dumps(policy, sort_keys=True, indent=4))


def list_scans():
    for suite in scan_suites:
        print(f'Suite "{suite}" - {scan_suites[suite].title}:')
        for scan in scan_suites[suite].scans:
            title = scan_suites[suite].scans[scan].title
            print(f'  "{suite}.{scan}" - {title}')
        print('')


def command(args):
    ''' Main handler of the 'scan' subcommand '''
    arguments = parser.parse_args(args)

    if not scan_targets_valid(arguments.scantypes):
        print('Invalid scan types provided, scan cancelled')
        sys.exit(1)

    context = Context(arguments.profiles, arguments.regions)

    if arguments.permissions:
        get_permissions(arguments.scantypes)
    elif arguments.list_scans:
        list_scans()
    else:
        run_scans(arguments.scantypes, context)


COMMAND = {'description': DESCRIPTION,
           'function': command}
