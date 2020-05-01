import boto3
from .ec2 import get_regions
from scanamabob.scans import Finding, Scan, ScanSuite


class AccessLogScan(Scan):
    title = 'Verifying ELB instances have access logs enabled'
    permissions = ['']

    def run(self, context, profile=None):
        findings = []
        accesslogs_disabled = {}
        elb_count = 0
        disabled_count = 0

        for region in get_regions():
            elb = boto3.client('elb', region_name=region)
            for page in elb.get_paginator('describe_load_balancers').paginate():
                for lb in page['LoadBalancerDescriptions']:
                    elb_count += 1
                    name = lb['LoadBalancerName']
                    # Verbose much?
                    attribs = elb.describe_load_balancer_attributes(LoadBalancerName=name)['LoadBalancerAttributes']
                    if not attribs['AccessLog']['Enabled']:
                        disabled_count += 1
                        if region not in accesslogs_disabled:
                            accesslogs_disabled[region] = []
                        accesslogs_disabled[region].append(name)
            elbv2 = boto3.client('elbv2', region_name=region)
            # Same thing, for v2 ELBs
            for page in elbv2.get_paginator('describe_load_balancers').paginate():
                for lb in page['LoadBalancers']:
                    elb_count += 1
                    name = lb['LoadBalancerName']
                    arn = lb['LoadBalancerArn']
                    attribs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=arn)
                    for attrib in attribs['Attributes']:
                        key = attrib['Key']
                        value = attrib['Value']
                        if key == 'access_logs.s3.enabled' and value == 'false':
                            disabled_count += 1
                            if region not in accesslogs_disabled:
                                accesslogs_disabled[region] = []
                            accesslogs_disabled[region].append(name)

        if disabled_count:
            findings.append(Finding('elb_accesslogs',
                                    'ELB Instances with Access Logs disabled',
                                    'LOW',
                                    elb_count=elb_count,
                                    disabled_count=disabled_count,
                                    elbs=accesslogs_disabled))

        return findings


class DeleteProtectScan(Scan):
    title = 'Verifying ELBv2 instances have delete protection enabled'
    permissions = ['']

    def run(self, context, profile=None):
        findings = []
        dltpt_disabled = {}
        elb_count = 0
        disabled_count = 0

        for region in get_regions():
            elbv2 = boto3.client('elbv2', region_name=region)
            for page in elbv2.get_paginator('describe_load_balancers').paginate():
                for lb in page['LoadBalancers']:
                    elb_count += 1
                    name = lb['LoadBalancerName']
                    arn = lb['LoadBalancerArn']
                    attribs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=arn)
                    for attrib in attribs['Attributes']:
                        key = attrib['Key']
                        value = attrib['Value']
                        if key == 'deletion_protection.enabled' and value == 'false':
                            disabled_count += 1
                            if region not in dltpt_disabled:
                                dltpt_disabled[region] = []
                            dltpt_disabled[region].append(name)

        if disabled_count:
            findings.append(Finding('elb_deleteprotect',
                                    'ELBv2 Instances with Delete Protection disabled',
                                    'LOW',
                                    elb_count=elb_count,
                                    disabled_count=disabled_count,
                                    elbs=dltpt_disabled))

        return findings


scans = ScanSuite('ELB Scans',
                  {'access_log': AccessLogScan(),
                   'delete_protect': DeleteProtectScan()})
