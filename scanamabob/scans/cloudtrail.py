import boto3
import sys
from scanamabob.scans import Finding, Scan, ScanSuite
from scanamabob.services.ec2 import get_regions
from scanamabob.services.cloudtrail import client


class CloudTrailInUse(Scan):
    title = 'Verifying that CloudTrail is being used'
    permissions = ['']

    def run(self, context):
        regions_without_trails = []
        
        for region in context.regions:
            region_client = client(context, region_name=region)
            if not len(region_client.describe_trails()['trailList']):
                regions_without_trails.append(region)

        if len(regions_without_trails):
            return [Finding(context.state,
                            'CloudTrail not in use',
                            'MEDIUM', regions=regions_without_trails)]
        return []


class LogFileValidation(Scan):
    title = 'Verifying log file validation on all CloudTrails'
    permissions = ['']

    def run(self, context):
        trails = []
        log_validation_disabled = []
        trailcount = 0

        for region in context.regions:
            region_client = client(context, region_name=region)
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
                  {'in_use': CloudTrailInUse(),
                   'log_validation': LogFileValidation()})
