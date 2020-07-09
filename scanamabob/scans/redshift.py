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


class SSLEnabledScan(Scan):
    title = 'Verifying Redshift clusters are using SSL'
    permissions = ['']

    def run(self, context):
        findings = []
        parameter_group_count = 0
        no_ssl_count = 0
        groups_without_ssl = {}
        instances = {}

        # Search for parameter groups wit SSL disabled.
        for region in context.regions:
            redshift = client(context, region_name=region)
            for page in redshift.get_paginator('describe_cluster_parameter_groups').paginate():
                for parameter_group in page['ParameterGroups']:
                    parameter_group_count += 1
                    group_name = parameter_group['ParameterGroupName']
                    for parameter in redshift.describe_cluster_parameters(ParameterGroupName=group_name)['Parameters']:
                        if parameter['ParameterName'] == 'require_ssl' and parameter['ParameterValue'] == 'false':
                            no_ssl_count += 1
                            if region not in groups_without_ssl:
                                groups_without_ssl[region] = []
                            groups_without_ssl[region].append({'group_name': group_name, 'in_use': False})

        # Next see if those parameter groups are actually used.
        severity = 'INFO'
        instances = {}
        for region in context.regions:
            redshift = client(context, region_name=region)
            for page in redshift.get_paginator('describe_clusters').paginate():
                for cluster in page['Clusters']:
                    for parameter_group in cluster['ClusterParameterGroups']:
                        group_name = parameter_group['ParameterGroupName']
                        for other_group in groups_without_ssl[region]:
                            if other_group['group_name'] == group_name:
                                other_group['in_use'] = True
                                severity = 'MEDIUM'

        if no_ssl_count:
            findings.append(Finding(context.state,
                                    'Redshift cluster parameter groups with SSL disabled',
                                    severity,
                                    parameter_group_count=parameter_group_count,
                                    no_ssl_count=no_ssl_count,
                                    instances=groups_without_ssl))
        return findings


scans = ScanSuite('Redshift Scans',
                  {'public': PubliclyAccessibleScan(),
                   'ssl': SSLEnabledScan()})
