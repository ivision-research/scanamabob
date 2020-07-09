from scanamabob.services.ec2 import get_region_secgroups
from scanamabob.services.redshift import client
from scanamabob.scans import Finding, Scan, ScanSuite


class PubliclyAccessibleScan(Scan):
    title = 'Verifying Redshift clusters are not publicly accessible'
    permissions = ['']

    def run(self, context):
        findings = []
        cluster_count = 0
        public_count = 0
        public = {}

        # First find any cluster that is `PubliclyAccessibble`.
        for region in context.regions:
            redshift = client(context, region_name=region)
            for page in redshift.get_paginator('describe_clusters').paginate():
                for cluster in page['Clusters']:
                    cluster_count += 1
                    if cluster['PubliclyAccessible']:
                        public_count += 1
                        if region not in public:
                            public[region] = []
                        cluster_id = cluster['ClusterIdentifier']
                        port = cluster['Endpoint']['Port']
                        security_groups = {group['VpcSecurityGroupId']: [] for group in cluster['VpcSecurityGroups']}
                        public[region].append({'id': cluster_id, 'port': port, 'security_groups': security_groups})

        # Next see if there are security groups in place for the found clusters.
        severity = 'LOW'
        for region in public:
            for cluster in public[region]:
                for group in get_region_secgroups(context, region):
                    group_id = group['GroupId']
                    if group_id not in cluster['security_groups']:
                        continue
                    for permission in group['IpPermissions']:
                        if permission['IpRanges'] == []:
                            continue
                        if permission['FromPort'] != cluster['port']:
                            continue
                        for ip in permission['IpRanges']:
                            cidr_ip = ip['CidrIp']
                            if cidr_ip == "0.0.0.0/0":
                                severity = 'HIGH'
                                cluster['security_groups'][group_id].append({'source': cidr_ip, 'class': 'Internet'})
                            elif context.is_aws_cidr(cidr_ip):
                                severity = 'MEDIUM'
                                cluster['security_groups'][group_id].append({'source': cidr_ip, 'class': 'AWS'})

        if public_count:
            findings.append(Finding(context.state,
                                    'Redshift clusters are publicly accessible',
                                    severity,
                                    cluster_count=cluster_count,
                                    public_count=public_count,
                                    instances=public))
        return findings


scans = ScanSuite('Redshift Scans',
                  {'public': PubliclyAccessibleScan()})
