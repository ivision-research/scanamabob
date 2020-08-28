def client(context, **kwargs):
    """ Return an RDS client handle for the given context """
    return context.session.client("rds", **kwargs)


def describe_db_instances(context, region):
    rds = client(context, region_name=region)

    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            yield db


def describe_db_cluster(context, region, cluster_id):
    rds = client(context, region_name=region)
    return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
