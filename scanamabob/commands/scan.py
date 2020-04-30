import sys
import time
import os
from argparse import ArgumentParser
import scanamabob.scans.iam as iam
import scanamabob.scans.ec2 as ec2
import scanamabob.scans.s3 as s3
import scanamabob.scans.cloudtrail as cloudtrail
import scanamabob.scans.elb as elb
import scanamabob.scans.rds as rds

DESCRIPTION = 'Scan AWS environment for common security misconfigurations'
USAGE = f'''{sys.argv[0]} scan [-h] [-o FORMAT] [scantypes] [...]'''
parser = ArgumentParser(description=DESCRIPTION,
                        usage=USAGE)
parser.add_argument('-o', '--output', choices=['stdout', 'json'],
                    default='stdout',
                    help="Output format for scan (default: stdout)")
parser.add_argument('scantypes', nargs='*',
                    help="Specific scan suite or individual scan to run (eg. iam.mfa)")

scan_suites = {
    'iam': iam.scans,
    'ec2': ec2.scans,
    's3': s3.scans,
    'cloudtrail': cloudtrail.scans,
    'elb': elb.scans,
    'rds': rds.scans
}

def command(args):
    arguments = parser.parse_args(args)
    finding_path = time.strftime('aws-scan/%b-%d-%Y-%H-%M/findings')
    # Run all the scans!
    findings = []

    for suitename in scan_suites:
        findings.extend(scan_suites[suitename].run())

    print('\n{} finding(s) from scan:'.format(len(findings)))

    for finding in findings:
        print(finding.__dict__)


COMMAND = {'description': DESCRIPTION,
           'function': command}
