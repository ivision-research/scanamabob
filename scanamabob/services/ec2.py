__cache_regions = {}
__cache_ec2_instances = {}
__cache_security_groups = {}


def client(context, **kwargs):
    ''' Return an EC2 client handle for the given context '''
    return context.session.client('ec2', **kwargs)


def resources(context, **kwargs):
    ''' Return an EC2 resource handle for the given context '''
    return context.session.resource('ec2', **kwargs)


def get_regions(context, region_name='us-east-1'):
    ''' Get all EC2 Regions. Caches result '''
    if context.current_profile in __cache_regions:
        return __cache_regions[context.current_profile]

    ec2 = client(context, region_name=region_name)

    regions = [i['RegionName'] for i in ec2.describe_regions()['Regions']]
    __cache_regions[context.current_profile] = regions
    return regions


def get_region_instances(context, region):
    if context.current_profile in __cache_ec2_instances:
        if region in __cache_ec2_instances[context.current_profile]:
            return __cache_ec2_instances[context.current_profile]

    instances = []
    region_client = client(context, region_name=region)
    paginator = region_client.get_paginator('describe_instances')
    for page in paginator.paginate():
        for reservation in page['Reservations']:
            for instance in reservation['Instances']:
                instances.append(instance)
            for group in reservation['Groups']:
                print(group)

    if context.current_profile not in __cache_ec2_instances:
        __cache_ec2_instances[context.current_profile] = {region: instances}
    else:
        __cache_ec2_instances[context.current_profile][region] = instances
    return instances


def get_region_secgroups(context, region):
    if context.current_profile in __cache_security_groups:
        if region in __cache_security_groups[context.current_profile]:
            return __cache_security_groups[context.current_profile][region]

    groups = []
    region_client = client(context, region_name=region)
    paginator = region_client.get_paginator('describe_security_groups')
    for page in paginator.paginate():
        for group in page['SecurityGroups']:
            groups.append(group)
    
    if context.current_profile not in __cache_security_groups:
        __cache_security_groups[context.current_profile] = {region: groups}
    else:
        __cache_security_groups[context.current_profile][region] = groups
    return groups
