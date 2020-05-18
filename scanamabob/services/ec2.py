__cache_regions = {}


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


def get_region_instances(context, region_name):
    region = resources(context, region_name=region_name)
    return region.instances.all()
