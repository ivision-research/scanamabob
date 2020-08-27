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


scan_suites = {
    'iam': iam.scans,
    'ec2': ec2.scans,
    's3': s3.scans,
    'cloudtrail': cloudtrail.scans,
    'elb': elb.scans,
    'rds': rds.scans,
    'redshift': redshift.scans
}


DESCRIPTION = 'Scan AWS environment for common security misconfigurations'
USAGE = f'''scanamabob scan [-h] [-l] [-P] [-r regions] [-p profiles] \
[scantypes] [...]'''
parser = ArgumentParser(description=DESCRIPTION,
                        usage=USAGE)
parser.add_argument('--exclude', action='append', default=[],
                    help="Exclude the given scan type from running")
parser.add_argument('--include', action='append', default=[],
                    help="Include the given scan type when running")
parser.add_argument('-o', '--output', choices=['stdout', 'json'],
                    default='stdout',
                    help="Output format for scan (default: stdout)")
parser.add_argument('-l', '--list-scans', action='store_true',
                    help="List the scans available to run")
parser.add_argument('-P', '--permissions', action='store_true',
                    help="Return IAM Policy JSON needed to complete scan")
add_context_to_argparse(parser)
parser.add_argument('scantypes', nargs='*', default=scan_suites.keys(),
                    help="Specific scan suites or individual scans to run")


def valid_specifier(spec):
    suite, scan = None, None
    parts = spec.split('.')

    if parts[0] not in scan_suites:
        return False
    if len(parts) > 1 and parts[1] not in scan_suites[parts[0]].scans:
        return False

    return True


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


def scans(scan_set, output=False):
    ''' Yield the given scan set '''

    for suite_name in scan_suites:
        suite = scan_suites[suite_name]
        if output:
            print('Running Scan Suite "{}"'.format(suite.title))

        for scan_name in suite.scans:
            scan = suite.scans[scan_name]
            if f'{suite_name}.{scan_name}' in scan_set:
                if output:
                    print(' - Running Scan "{}"'.format(scan.title))
                yield scan


def run_scans(scan_set, context):
    ''' Run the given scan set using the provided context '''
    findings = {}

    for profile in context.profiles:
        if context.output == 'stdout':
            print(f'- Scanning {profile} profile')
        context.set_profile(profile)
        findings[profile] = []

        # Run user specified scans
        for scan in scans(scan_set, context.output == 'stdout'):
            scan_findings = scan.run(context)
            findings[profile].extend(scan_findings)

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


def get_permissions(scan_set):
    permissions = []

    # Get permissions for user specified scans
    for scan in scans(scan_set):
        for permission in scan.permissions:
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


def expand_arguments(args):
    ''' Does a pre-pass over the command line arguments to expand `+/-foo` into `--include/exclude=foo` '''

    prefix_map = {
        '-': 'exclude',
        '+': 'include'
    }

    new_args = []
    for arg in args:
        if arg[0] in prefix_map and valid_specifier(arg[1:]):
            new_args.append(f'--{prefix_map[arg[0]]}={arg[1:]}')
        else:
            new_args.append(arg)
    return new_args


def compute_scan_set(include, exclude):
    # Expand all the suites into a set of scans excluding unwanted suites.
    scan_specs = set()
    for spec in (include - exclude):
        if spec in scan_suites:
            scan_names = scan_suites[spec].scans.keys()
            scan_specs |= set(map(lambda s: f'{spec}.{s}', scan_names))
        else:
            scan_specs.add(spec)

    # Remove any unwanted scans that may not have appeared before expansion.
    scan_specs -= exclude

    return scan_specs


def command(args):
    ''' Main handler of the scan subcommand '''
    args = expand_arguments(args)
    arguments = parser.parse_args(args)
    include = set(arguments.include)
    if not len(include):
        include = set(arguments.scantypes)
    exclude = set(arguments.exclude)
    scan_set = compute_scan_set(include, exclude)

    if not scan_targets_valid(scan_set):
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
        get_permissions(scan_set)
    else:
        run_scans(scan_set, context)


COMMAND = {'description': DESCRIPTION,
           'function': command}
