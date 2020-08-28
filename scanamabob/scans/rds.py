from scanamabob.services.rds import client, describe_db_instances, describe_db_cluster
from scanamabob.scans import Finding, Scan, ScanSuite


class PropertyScan(Scan):
    title = ""
    permissions = [""]

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
            for db in describe_db_instances(context, region):
                rds_count += 1
                target_value = db[self.name]

                # Cluster properties take precedence.
                if "DBClusterIdentifier" in db:
                    cluster = describe_db_cluster(
                        context, region, db["DBClusterIdentifier"]
                    )
                    if self.name in cluster:
                        target_value = cluster[self.name]

                if db[self.name] == target_value:
                    flagged_rds_count += 1
                    if region not in flagged:
                        flagged[region] = []
                    flagged[region].append(db["DBInstanceIdentifier"])

        if flagged_rds_count:
            findings.append(
                Finding(
                    context.state,
                    self.title,
                    "LOW",
                    rds_count=rds_count,
                    flagged_rds_count=flagged_rds_count,
                    instances=flagged,
                )
            )
        return findings


class EncryptionScan(PropertyScan):
    title = "Verifying RDS instances have encryption enabled"
    permissions = [""]

    def __init__(self):
        super().__init__("StorageEncrypted", False, "RDS instances without encryption")


class BackupsScan(PropertyScan):
    title = "Verifying RDS instances have backups enabled"
    permissions = [""]

    def __init__(self):
        super().__init__("BackupRetentionPeriod", 0, "RDS instances without backups")


class MultiAZScan(PropertyScan):
    title = "Verifying RDS instances are in multiple availability zones"
    permissions = [""]

    def __init__(self):
        super().__init__(
            "MultiAZ", False, "RDS instances without multiple availability zones"
        )


scans = ScanSuite(
    "RDS Scans",
    {
        "encryption": EncryptionScan(),
        "backups": BackupsScan(),
        "multiaz": MultiAZScan(),
    },
)
