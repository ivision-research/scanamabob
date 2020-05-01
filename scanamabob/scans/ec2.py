import boto3
import os
from scanamabob.scans import Finding, Scan, ScanSuite

ec2 = boto3.client('ec2')


def get_regions():
    return [i['RegionName'] for i in ec2.describe_regions()['Regions']]


def _get_region_instances(region_name):
    region = boto3.resource('ec2', region_name=region_name)
    return region.instances.all()


def tee(fp, msg):
    print(msg)
    fp.write(msg + '\n')


def _dump_intance(path, region, instance):
    name = 'Unnamed Instance'
    if instance.tags:
        for tag in instance.tags:
            key, value = tag['Key'], tag['Value']
            if key == 'Name':
                name = value

    inst_path = '{}/ec2/{}/'.format(path, region)
    if not os.path.exists(inst_path):
        os.makedirs(inst_path)
    with open('{}/{}.md'.format(inst_path, instance.id), 'w') as fp:
        tee(fp, f'# EC2 Instance ({name})\n')

        tee(fp, f'Instance ID: `{instance.id}`')
        state = instance.state['Name']
        tee(fp, f'State: `{state}`\n')

        tee(fp, '## Network interfaces')
        for iface in instance.network_interfaces_attribute:
            print(iface)
#        tee(fp, f'VPC ID: `{instance.vpc_id}`')
#        tee(fp, f'Public IP: `{instance.public_ip_address}`')
#        tee(fp, f'Public DNS: `{instance.public_dns_name}`')
#        tee(fp, f'Private IP: `{instance.private_ip_address}`')
#        tee(fp, f'Private DNS: `{instance.private_dns_name}`\n')


def summary():
    ec2_regions = get_regions()

    instances = 0
    for region_name in ec2_regions:
        for instance in _get_region_instances(region_name):
            instances += 1
    print('- {} EC2 instances'.format(instances))


def dump(path):
    ec2_regions = get_regions()
    for region_name in ec2_regions:
        for instance in _get_region_instances(region_name):
            _dump_intance(path, region_name, instance)


class EncryptionScan(Scan):
    title = 'Scanning EC2 instances for EBS volume encryption'
    permissions = ['']

    def run(self, context, profile=None):
        findings = []
        total_volumes = 0
        unencrypted_volumes = 0
        # { 'region': [instances, affected] }
        unencrypted = {}

        for region in get_regions():
            region_client = boto3.client('ec2', region_name=region)
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
            finding = Finding('ebs_encryption',
                              'EBS block storage volumes without encryption',
                              'MEDIUM',
                              count_total=total_volumes,
                              count_unenc=unencrypted_volumes,
                              unenc_volumes=unencrypted)
            findings.append(finding)

        return findings


scans = ScanSuite('EC2 Scans',
                  {'encryption': EncryptionScan()})
