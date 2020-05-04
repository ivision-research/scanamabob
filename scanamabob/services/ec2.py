import boto3

__cache_regions = {}


def client(context, profile=None, **kwargs):
    ''' Return an EC2 client handle for the given context and profile '''
    access_key, secret = context.get_credentials(profile)
    return boto3.client('ec2',
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret,
                        **kwargs)


def resources(context, profile=None, **kwargs):
    ''' Return an EC2 resource handle for the given context and profile '''
    access_key, secret = context.get_credentials(profile)
    return boto3.resource('ec2',
                          aws_access_key_id=access_key,
                          aws_secret_access_key=secret,
                          **kwargs)


def get_regions(context, profile):
    ''' Get all EC2 Regions. Caches result '''
    if profile in __cache_regions:
        return __cache_regions[profile]

    ec2 = client(context, profile)

    regions = [i['RegionName'] for i in ec2.describe_regions()['Regions']]
    __cache_regions[profile] = regions
    return regions


def get_region_instances(context, profile, region_name):
    region = resources(context, profile, region_name=region_name)
    return region.instances.all()
