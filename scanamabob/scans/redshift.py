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


class ParameterGroupScan(Scan):
    def __init__(self, name, value, title):
        self.name = name
        self.value = value
        self.title = title

    def run(self, context):
        findings = []
        parameter_group_count = 0
        flagged_parameter_group_count = 0
        flagged = {}
        instances = {}

        # Search for parameter groups with the properties we are looking to flag.
        for region in context.regions:
            redshift = client(context, region_name=region)
            for page in redshift.get_paginator('describe_cluster_parameter_groups').paginate():
                for parameter_group in page['ParameterGroups']:
                    parameter_group_count += 1
                    group_name = parameter_group['ParameterGroupName']
                    for parameter in redshift.describe_cluster_parameters(ParameterGroupName=group_name)['Parameters']:
                        if parameter['ParameterName'] == self.name and parameter['ParameterValue'] == self.value:
                            flagged_parameter_group_count += 1
                            if region not in flagged:
                                flagged[region] = []
                            flagged[region].append({'group_name': group_name,
                                                    'parameter_name': self.name,
                                                    'parameter_value': self.value,
                                                    'in_use': False})

        # Next see if those parameter groups are actually used.
        severity = 'INFO'
        instances = {}
        for region in context.regions:
            redshift = client(context, region_name=region)
            for page in redshift.get_paginator('describe_clusters').paginate():
                for cluster in page['Clusters']:
                    for parameter_group in cluster['ClusterParameterGroups']:
                        group_name = parameter_group['ParameterGroupName']
                        for other_group in flagged[region]:
                            if other_group['group_name'] == group_name:
                                other_group['in_use'] = True
                                severity = 'MEDIUM'

        # If the default parameter group isn't used, then unflag it.
        for region in flagged:
            default_group = None
            for group in flagged[region]:
                if group['group_name'] == 'default.redshift-1.0' and not group['in_use']:
                    default_group = group
                    break
            if default_group:
                flagged_parameter_group_count -= 1
                flagged[region].remove(default_group)

        if flagged_parameter_group_count:
            findings.append(Finding(context.state,
                                    self.title,
                                    severity,
                                    parameter_group_count=parameter_group_count,
                                    flagged_parameter_group_count=flagged_parameter_group_count,
                                    instances=flagged))
        return findings


class SSLEnabledScan(ParameterGroupScan):
    title = 'Verifying Redshift clusters are using SSL'
    permissions = ['']

    def __init__(self):
        super().__init__('require_ssl',
                         'false',
                         'Redshift cluster parameter groups with SSL disabled')


class LoggingEnabledScan(ParameterGroupScan):
    title = 'Verifying Redshift clusters are using activity logging'
    permissions = ['']

    def __init__(self):
        super().__init__('enable_user_activity_logging',
                         'false',
                         'Redshift cluster parameter groups with activity logging disabled')


scans = ScanSuite('Redshift Scans',
                  {'public': PubliclyAccessibleScan(),
                   'logging': LoggingEnabledScan(),
                   'ssl': SSLEnabledScan()})
