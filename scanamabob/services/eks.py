import botocore


def client(context, **kwargs):
    """ Return an EKS client handle for the given context """
    return context.session.client("eks", **kwargs)


def list_clusters(context, region):
    eks = client(context, region_name=region)

    # EKS is not available in all regions and `boto` throws a `ClientError`
    # exception when the service is *not* available.
    try:
        for page in eks.get_paginator("list_clusters").paginate():
            for cluster_name in page["clusters"]:
                yield cluster_name
    except botocore.exceptions.ClientError as err:
        pass
