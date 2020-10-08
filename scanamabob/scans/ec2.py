import json
import os

from scanamabob.scans import Finding, Scan, ScanSuite
from scanamabob.services.ec2 import (
    client,
    get_region_instances,
    get_region_secgroups,
    get_regions,
    get_region_running_instances,
)

from IPython import embed


class EncryptionScan(Scan):
    title = "Scanning EC2 instances for EBS volume encryption"
    permissions = [""]

    def run(self, context):
        findings = []
        total_volumes = 0
        unencrypted_volumes = 0
        # { 'region': [instances, affected] }
        unencrypted = {}

        for region in context.regions:
            region_client = client(context, region_name=region)
            paginator = region_client.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page["Volumes"]:
                    total_volumes += 1
                    if not volume["Encrypted"]:
                        unencrypted_volumes += 1
                        if region not in unencrypted:
                            unencrypted[region] = []
                        unencrypted[region].append(volume["VolumeId"])

        if unencrypted_volumes:
            finding = Finding(
                context.state,
                "EBS block storage volumes without encryption",
                "MEDIUM",
                count_total=total_volumes,
                count_unenc=unencrypted_volumes,
                unenc_volumes=unencrypted,
            )
            findings.append(finding)

        return findings


class SecurityGroupScan(Scan):
    title = "Scanning EC2 Security Groups"
    permissions = [""]

    def run(self, context):
        used_security_groups = {}
        open_to_all = {}
        open_but_unused = {}
        used_open_gids = []

        # Collect list of security groups attached to a network interface
        for region in context.regions:
            try:
                for instance in get_region_instances(context, region):
                    for interface in instance["NetworkInterfaces"]:
                        for group in interface["Groups"]:
                            gid = group["GroupId"]
                            info = {
                                "instance": instance["InstanceId"],
                                "interface": interface["NetworkInterfaceId"],
                                "name": group["GroupName"],
                                "ip": {
                                    "private": interface["PrivateIpAddress"],
                                    "public": None,
                                },
                            }
                            if "Association" in interface:
                                info["ip"]["public"] = interface["Association"][
                                    "PublicIp"
                                ]
                            if gid not in used_security_groups:
                                used_security_groups[gid] = [info]
                            else:
                                used_security_groups[gid].append(info)
            except Exception as e:
                print(e)
        # Collect list of problematic security groups
        for region in context.regions:
            try:
                for group in get_region_secgroups(context, region):
                    # Ingress rules
                    for permission in group["IpPermissions"]:
                        if permission["IpRanges"] == []:
                            # Empty Security Group
                            continue
                        # Test for ports allowed from any IP
                        if any(
                            iprange.get("CidrIpv6", "") == "::/0"
                            or iprange.get("CidrIp", "") == "0.0.0.0/0"
                            for iprange in permission["IpRanges"]
                        ):
                            proto = permission.get("IpProtocol", "-1")
                            toport = permission.get("ToPort", -1)
                            fromport = permission.get("FromPort", -1)
                            if toport == fromport:
                                port = toport
                            else:
                                port = f"{fromport}-{toport}"
                            gid = group["GroupId"]
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
            except Exception as e:
                print(e)

        # Categorize unused security groups for findings
        flagged_groups = {}
        for group in used_security_groups:
            if group in used_open_gids:
                flagged_groups[group] = used_security_groups[group]
        if len(open_to_all.keys()):
            return [
                Finding(
                    context.state,
                    "Security Groups with ports open to all IPs",
                    "MEDIUM",
                    open_all=open_to_all,
                    open_unused=open_but_unused,
                    used=flagged_groups,
                )
            ]
        elif len(open_but_unused.keys()):
            return [
                Finding(
                    context.state,
                    "Unused Security Groups with ports open to all IPs",
                    "INFO",
                    open_all=open_to_all,
                    open_unused=open_but_unused,
                    used=flagged_groups,
                )
            ]
        return []


class PublicAMIScan(Scan):
    title = "Scanning for public AMIs"
    permissions = [""]

    def run(self, context):
        findings = []
        total_images = 0
        public_images = 0
        images = {}

        for region in context.regions:
            region_client = client(context, region_name=region)
            for image in region_client.describe_images(Owners=["self"])["Images"]:
                total_images += 1
                if image["Public"]:
                    public_images += 1
                    if region not in images:
                        images[region] = []
                    images[region].append(image["ImageId"])

        if public_images:
            finding = Finding(
                context.state,
                "Public Amazon Machine Images",
                "MEDIUM",
                count_total=total_images,
                count_public=public_images,
                public_images=images,
            )
            findings.append(finding)

        return findings


class ExposedEC2Scan(Scan):
    title = "Scanning exposed EC2 instances"
    permissions = [""]

    def run(self, context):

        results = []

        for region in context.regions:
            print(f"Parsing region {region}")
            try:
                region_secgroup_ipperms_map = {}
                for g in get_region_secgroups(context, region):
                    # Create a lookup map between groups and corresponding rules
                    region_secgroup_ipperms_map[g["GroupId"]] = g["IpPermissions"]

                    for instance in get_region_running_instances(context, region):
                        # We only care about EC2 instances with public IPs and attached security groups
                        if (
                            instance.public_ip_address is not None
                            and instance.security_groups is not None
                        ):
                            # Look up instance's rules by finding the security group in the lookup map
                            for instance_group in instance.security_groups:
                                if (
                                    instance_group["GroupId"]
                                    in region_secgroup_ipperms_map.keys()
                                ):
                                    for rule in region_secgroup_ipperms_map[
                                        instance_group["GroupId"]
                                    ]:
                                        for iprange in rule["IpRanges"]:
                                            if (
                                                iprange.get("CidrIpv6", "") == "::/0"
                                                or iprange.get("CidrIp", "")
                                                == "0.0.0.0/0"
                                            ) and rule["IpProtocol"] in ("tcp", "udp"):
                                                entry = {
                                                    "Region": region,
                                                    "GroupId": instance_group[
                                                        "GroupId"
                                                    ],
                                                    "InstanceId": instance.instance_id,
                                                    "PublicIpAddress": instance.public_ip_address,
                                                    "ToPort": rule["ToPort"],
                                                }
                                                if entry not in results:
                                                    results.append(entry)
            except Exception as e:
                print(e)

        if len(results) > 0:
            return [
                Finding(
                    context.state,
                    "Instances with open security groups",
                    "INFO",
                    results=results,
                )
            ]
        return []


scans = ScanSuite(
    "EC2 Scans",
    {
        "encryption": EncryptionScan(),
        "securitygroups": SecurityGroupScan(),
        "publicamis": PublicAMIScan(),
        "exposedec2": ExposedEC2Scan(),
    },
)
