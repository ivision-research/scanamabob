from scanamabob.services.rds import client
from scanamabob.scans import Finding, Scan, ScanSuite


class PropertyScan(Scan):
    title = ''
    permissions = ['']

    def __init__(self, name, value, title):
        self.name = name
        self.value = value
        self.title = title

    def run(self, context):
        findings = []
        rds_count = 0
        flagged_rds_count = 0
        flagged = {}

        for region in context.regions:
            rds = client(context, region_name=region)
            for page in rds.get_paginator('describe_db_instances').paginate():
                for db in page['DBInstances']:
                    rds_count += 1
                    if db[self.name] == self.value:
                        flagged_rds_count += 1
                        if region not in flagged:
                            flagged[region] = []
                        flagged[region].append(db['DBInstanceIdentifier'])

        if flagged_rds_count:
            findings.append(Finding(context.state,
                                    self.title,
                                    'LOW',
                                    rds_count=rds_count,
                                    flagged_rds_count=flagged_rds_count,
                                    instances=flagged))
        return findings


class EncryptionScan(PropertyScan):
    title = 'Verifying RDS instances have encryption enabled'
    permissions = ['']

    def __init__(self):
        super().__init__('StorageEncrypted',
                         False,
                         'RDS instances without encryption')


class MultiAZScan(PropertyScan):
    title = 'Verifying RDS instances are in multiple availability zones'
    permissions = ['']

    def __init__(self):
        super().__init__('MultiAZ',
                         False,
                         'RDS instances without multiple availability zones')


scans = ScanSuite('RDS Scans',
                  {'encryption': EncryptionScan(),
                   'multiaz': MultiAZScan()})
