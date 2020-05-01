import boto3
from .ec2 import get_regions
from scanamabob.scans import Finding, Scan, ScanSuite

rds = boto3.client('rds')


class EncryptionScan(Scan):
    title = 'Verifying RDS instances have encryption enabled'
    permissions = ['']

    def run(self, context, profile=None):
        findings = []
        rds_count = 0
        unenc_count = 0
        unenc = {}

        for region in get_regions():
            rds = boto3.client('rds', region_name=region)
            for page in rds.get_paginator('describe_db_instances').paginate():
                for db in page['DBInstances']:
                    rds_count += 1
                    if not db['StorageEncrypted']:
                        unenc_count += 1
                        if region not in unenc:
                            unenc[region] = []
                        unenc[region].append(db['DBInstanceIdentifier'])

        if unenc_count:
            findings.append(Finding('rds_unencrypted',
                                    'RDS instances without encryption',
                                    'LOW',
                                    rds_count=rds_count,
                                    unenc_count=unenc_count,
                                    instances=unenc))
        return findings


scans = ScanSuite('RDS Scans',
                  {'encryption': EncryptionScan()})
