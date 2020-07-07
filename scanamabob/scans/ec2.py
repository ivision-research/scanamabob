import os
import json
from scanamabob.scans import Finding, Scan, ScanSuite
from scanamabob.services.ec2 import client, get_regions, \
    get_region_instances, get_region_secgroups


class EncryptionScan(Scan):
    title = 'Scanning EC2 instances for EBS volume encryption'
    permissions = ['']

    def run(self, context):
        findings = []
        total_volumes = 0
        unencrypted_volumes = 0
        # { 'region': [instances, affected] }
        unencrypted = {}

        for region in context.regions:
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


class SecurityGroupScan(Scan):
    title = 'Scanning EC2 Security Groups'
    permissions = ['']

    def run(self, context):
        used_security_groups = {}
        open_to_all = {}
        open_but_unused = {}
        used_open_gids = []
        for region in context.regions:
            for instance in get_region_instances(context, region):
                for interface in instance['NetworkInterfaces']:
                    for group in interface['Groups']:
                        gid = group['GroupId']
                        info = {
                            'instance': instance['InstanceId'],
                            'interface': interface['NetworkInterfaceId'],
                            'name': group['GroupName'],
                            'ip': {
                                'private': interface['PrivateIpAddress'],
                                'public': None
                            }
                        }
                        if 'Association' in interface:
                            info['ip']['public'] = interface['Association']['PublicIp']
                        if gid not in used_security_groups:
                            used_security_groups[gid] = [info]
                        else:
                            used_security_groups[gid].append(info)

        for region in context.regions:
            for group in get_region_secgroups(context, region):
                for permission in group['IpPermissions']:
                    if permission['IpRanges'] == []:
                        # Empty Security Group
                        continue
                    if {"CidrIp": "0.0.0.0/0"} in permission['IpRanges']:
                        proto = permission['IpProtocol']
                        toport = permission['ToPort']
                        fromport = permission['FromPort']
                        if toport == fromport:
                            port = toport
                        else:
                            port = f"{fromport}-{toport}"
                        gid = group['GroupId']
                        if gid in used_security_groups:
                            used_open_gids.append(gid)
                            if region not in open_to_all:
                                open_to_all[region] = {proto: {port: [gid]}}
                            elif proto not in open_to_all[region]:
                                open_to_all[region][proto] = {port: [gid]}
                            elif port not in open_to_all[region][proto]:
                                open_to_all[region][proto][port] = [gid]
                            else:
                                open_to_all[region][proto][port].append(gid)
                        else:
                            if region not in open_but_unused:
                                open_but_unused[region] = {proto: {port: [gid]}}
                            elif proto not in open_but_unused[region]:
                                open_but_unused[region][proto] = {port: [gid]}
                            elif port not in open_but_unused[region][proto]:
                                open_but_unused[region][proto][port] = [gid]
                            else:
                                open_but_unused[region][proto][port].append(gid)
        # Filter out unused for findings
        flagged_groups = {}
        for group in used_security_groups:
            if group in used_open_gids:
                flagged_groups[group] = used_security_groups[group]
        if len(open_to_all.keys()):
            return [Finding(context.state,
                            'Security Groups with ports open to all IPs',
                            'MEDIUM',
                            open_all=open_to_all,
                            open_unused=open_but_unused,
                            used=flagged_groups)]
        elif len(open_but_unused.keys()):
            return [Finding(context.state,
                            'Unused Security Groups with ports open to all IPs',
                            'INFO',
                            open_all=open_to_all,
                            open_unused=open_but_unused,
                            used=flagged_groups)]

        return []


class PublicAMIScan(Scan):
    title = 'Scanning for public AMIs'
    permissions = ['']

    def run(self, context):
        findings = []
        total_images = 0
        public_images = 0
        images = {}

        for region in context.regions:
            region_client = client(context, region_name=region)
            for image in region_client.describe_images(Owners=['self'])['Images']:
                total_images += 1
                if image['Public']:
                    public_images += 1
                    if region not in images:
                        images[region] = []
                    images[region].append(image['ImageId'])

        if public_images:
            finding = Finding(context.state,
                              'Public Amazon Machine Images',
                              'MEDIUM',
                              count_total=total_images,
                              count_public=public_images,
                              public_images=images)
            findings.append(finding)

        return findings


scans = ScanSuite('EC2 Scans',
                  {'encryption': EncryptionScan(),
                   'securitygroups': SecurityGroupScan(),
                   'publicamis': PublicAMIScan()})
