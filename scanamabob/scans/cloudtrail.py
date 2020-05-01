import boto3
import os
from scanamabob.scans import Finding, Scan, ScanSuite
from .ec2 import get_regions

cloudtrail = boto3.client('cloudtrail')


class LogFileValidation(Scan):
    title = 'Verifying log file validation on all CloudTrails'
    permissions = ['']

    def run(self, context, profile=None):
        findings = []
        trails = []
        log_validation_disabled = []
        trailcount = 0
        for region in get_regions():
            region_client = boto3.client('cloudtrail', region_name=region)
            for trail in region_client.describe_trails()['trailList']:
                if trail['TrailARN'] in trails:
                    continue
                trails.append(trail['TrailARN'])
                friendly_name = f'{trail["HomeRegion"]}:trail/{trail["Name"]}'
                if not trail['LogFileValidationEnabled']:
                    log_validation_disabled.append(friendly_name)

        if len(log_validation_disabled):
            finding = Finding('cloudtrail_integrity',
                              'CloudTrail log validation disabled',
                              'LOW', trails=log_validation_disabled)
            findings.append(finding)
        return findings


scans = ScanSuite('CloudTrail Scans',
                  {'log_validation': LogFileValidation()})
