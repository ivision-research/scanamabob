from scanamabob.services.eks import client, list_clusters
from scanamabob.scans import Finding, Scan, ScanSuite


class PubliclyAccessibleAPIServerScan(Scan):
    title = "Verifying EKS API servers are not publicly accessible"
    permissions = [""]

    def run(self, context):
        findings = []
        cluster_count = 0
        public_count = 0
        public = {}

        for region in context.regions:
            eks = client(context, region_name=region)
            for cluster_name in list_clusters(context, region):
                cluster_count += 1
                cluster = eks.describe_cluster(name=cluster_name)["cluster"]
                if cluster["resourcesVpcConfig"]["endpointPublicAccess"]:
                    public_count += 1
                    if region not in public:
                        public[region] = []
                    public[region].append(
                        {"name": cluster_name, "endpoint": cluster["endpoint"]}
                    )

        if public_count:
            findings.append(
                Finding(
                    context.state,
                    "EKS API server endpoints are publicly accessible",
                    "MEDIUM",
                    cluster_count=cluster_count,
                    public_count=public_count,
                    instances=public,
                )
            )
        return findings


scans = ScanSuite("EKS Scans", {"public": PubliclyAccessibleAPIServerScan()})
