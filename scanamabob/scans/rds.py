from scanamabob.services.rds import client
from scanamabob.scans import Finding, Scan, ScanSuite


class EncryptionScan(Scan):
    title = 'Verifying RDS instances have encryption enabled'
    permissions = ['']

    def run(self, context):
        findings = []
        rds_count = 0
        unenc_count = 0
        unenc = {}

        for region in context.regions:
            rds = client(context, region_name=region)
            for page in rds.get_paginator('describe_db_instances').paginate():
                for db in page['DBInstances']:
                    rds_count += 1
                    if not db['StorageEncrypted']:
                        unenc_count += 1
                        if region not in unenc:
                            unenc[region] = []
                        unenc[region].append(db['DBInstanceIdentifier'])

        if unenc_count:
            findings.append(Finding(context.state,
                                    'RDS instances without encryption',
                                    'LOW',
                                    rds_count=rds_count,
                                    unenc_count=unenc_count,
                                    instances=unenc))
        return findings


scans = ScanSuite('RDS Scans',
                  {'encryption': EncryptionScan()})
