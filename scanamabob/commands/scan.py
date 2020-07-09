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
import scanamabob.scans.redshift as redshift
from scanamabob.context import Context, add_context_to_argparse


DESCRIPTION = 'Scan AWS environment for common security misconfigurations'
USAGE = f'''scanamabob scan [-h] [-l] [-P] [-r regions] [-p profiles] \
[scantypes] [...]'''
parser = ArgumentParser(description=DESCRIPTION,
                        usage=USAGE)
parser.add_argument('-o', '--output', choices=['stdout', 'json'],
                    default='stdout',
                    help="Output format for scan (default: stdout)")
parser.add_argument('-l', '--list-scans', action='store_true',
                    help="List the scans available to run")
parser.add_argument('-P', '--permissions', action='store_true',
                    help="Return IAM Policy JSON needed to complete scan")
add_context_to_argparse(parser)
parser.add_argument('scantypes', nargs='*',
                    help="Specific scan suites or individual scans to run")


scan_suites = {
    'iam': iam.scans,
    'ec2': ec2.scans,
    's3': s3.scans,
    'cloudtrail': cloudtrail.scans,
    'elb': elb.scans,
    'rds': rds.scans,
    'redshift': redshift.scans
}


def scan_targets_valid(scanlist):
    valid = True
    for i in scanlist:
        if '.' in i:
            suite, scan = i.split('.')
            if suite not in scan_suites:
                print(f'{suite} is not a valid scan suite')
                valid = False
            elif scan not in scan_suites[suite].scans:
                print(f'{scan} not a valid scan in {suite} suite')
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
        if context.output == 'stdout':
            print(f'- Scanning {profile} profile')
        context.set_profile(profile)
        findings[profile] = []
        if scantypes:
            # Run user specified scans
            for scantype in scantypes:
                context.state = scantype
                if '.' in scantype:
                    suite, target = scantype.split('.')
                    scan = scan_suites[suite].scans[target]
                    if context.output == 'stdout':
                        print(' - Running Scan "{}"'.format(scan.title))
                    scan_findings = scan.run(context)
                    findings[profile].extend(scan_findings)
                else:
                    suite_findings = scan_suites[scantype].run(context)
                    findings[profile].extend(suite_findings)
        else:
            # Run all scans
            for suite in scan_suites:
                context.state = suite
                suite_findings = scan_suites[suite].run(context)
                findings[profile].extend(suite_findings)

    if context.output == 'stdout':
        print('\n{} total finding(s) from scan:'.format(len(findings)))

        for profile in findings:
            print(f'Findings from "{profile}" profile:')
            for finding in findings[profile]:
                print(finding.as_stdout())
    else:
        findings_json = {}
        for profile in findings:
            findings_json[profile] = []
            for finding in findings[profile]:
                findings_json[profile].append(finding.as_dict())
        print(json.dumps(findings_json, indent=4))


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
    ''' Main handler of the scan subcommand '''
    arguments = parser.parse_args(args)

    if not scan_targets_valid(arguments.scantypes):
        print('Invalid scan types provided, scan cancelled')
        sys.exit(1)

    context = Context(arguments.profiles, arguments.regions, arguments.output)

    # This is validated after building context because the context is used to
    # enumerate regions
    if not context.regions_valid():
        print('Invalid regions provided, scan cancelled')
        sys.exit(1)

    if arguments.list_scans:
        list_scans()
    elif arguments.permissions:
        get_permissions(arguments.scantypes)
    else:
        run_scans(arguments.scantypes, context)


COMMAND = {'description': DESCRIPTION,
           'function': command}
