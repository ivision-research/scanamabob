import boto3
import sys
from scanamabob.scans import Finding, Scan, ScanSuite
from scanamabob.services.ec2 import get_regions
from scanamabob.services.cloudtrail import client


class LogFileValidation(Scan):
    title = 'Verifying log file validation on all CloudTrails'
    permissions = ['']

    def run(self, context, profile=None):
        cloudtrail = client(context, profile)
        trails = []
        log_validation_disabled = []
        trailcount = 0

        if '*' in context.regions:
            regions = get_regions(context, profile)
        else:
            regions = context.regions

        for region in regions:
            region_client = client(context, profile, region_name=region)
            for trail in region_client.describe_trails()['trailList']:
                if trail['TrailARN'] in trails:
                    continue
                trails.append(trail['TrailARN'])
                friendly_name = f'{trail["HomeRegion"]}:trail/{trail["Name"]}'
                if not trail['LogFileValidationEnabled']:
                    log_validation_disabled.append(friendly_name)

        if len(log_validation_disabled):
            return [Finding(context.state,
                            'CloudTrail log validation disabled',
                            'LOW', trails=log_validation_disabled)]
        return []


scans = ScanSuite('CloudTrail Scans',
                  {'log_validation': LogFileValidation()})
