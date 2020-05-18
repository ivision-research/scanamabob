import os
from scanamabob.scans import Finding, Scan, ScanSuite
from scanamabob.services.ec2 import client, get_regions, get_region_instances


class EncryptionScan(Scan):
    title = 'Scanning EC2 instances for EBS volume encryption'
    permissions = ['']

    def run(self, context):
        findings = []
        total_volumes = 0
        unencrypted_volumes = 0
        # { 'region': [instances, affected] }
        unencrypted = {}

        for region in get_regions(context):
            region_client = client(context, region_name=region)
            paginator = region_client.get_paginator('describe_volumes')
            for page in paginator.paginate():
                for volume in page['Volumes']:
                    total_volumes += 1
                    if not volume['Encrypted']:
                        unencrypted_volumes += 1
                        if region not in unencrypted:
                            unencrypted[region] = []
                        unencrypted[region].append(volume['VolumeId'])

        if unencrypted_volumes:
            finding = Finding(context.state,
                              'EBS block storage volumes without encryption',
                              'MEDIUM',
                              count_total=total_volumes,
                              count_unenc=unencrypted_volumes,
                              unenc_volumes=unencrypted)
            findings.append(finding)

        return findings


scans = ScanSuite('EC2 Scans',
                  {'encryption': EncryptionScan()})
