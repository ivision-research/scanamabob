import boto3
from botocore.exceptions import ClientError
from scanamabob.scans import Finding, Scan, ScanSuite

s3 = boto3.client('s3')
resources = boto3.resource('s3')
control = boto3.client('s3control')
PUBLIC_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'
ENC_NOT_FOUND = 'ServerSideEncryptionConfigurationNotFoundError'


def _get_all_buckets():
    return [x['Name'] for x in s3.list_buckets()['Buckets']]


def _get_accountid():
    return boto3.client('sts').get_caller_identity().get('Account')


class PermissionScan(Scan):
    title = 'Scanning S3 buckets for unsafe permissions'
    permissions = ['s3:ListAllMyBuckets',
                   's3:GetBucketPublicAccessBlock',
                   'iam:GetUser']

    def run(self, context, profile=None):
        buckets = _get_all_buckets()
        findings = []

        # No buckets? No problem!
        if not len(buckets):
            return findings

        # Get account ID to get account level S3 public access block data
        # TODO: This means of getting the account id works but is weak, and
        #       likely breaks if ran cross-organizationally
        try:
            acctid = _get_accountid()
            acct_pub_block = control.get_public_access_block(AccountId=acctid)
            acct_pub_access = acct_pub_block['PublicAccessBlockConfiguration']
            # This will be true if public access is blocked for the account
            acct_pub_blocked = (acct_pub_access['IgnorePublicAcls'] and
                                acct_pub_access['RestrictPublicBuckets'])
        # TODO: catch expected exception
        except:
            # No public access block on the account level defined
            acct_pub_blocked = False

        # Check each bucket
        acls_readonly = []
        acls_write = []
        acls_mitigated = []
        for bucket in buckets:
            # Check if a public access block is set for the bucket
            try:
                pub_block = s3.get_public_access_block(Bucket=bucket)
                pub_access = pub_block['PublicAccessBlockConfiguration']
                # True if public access is blocked on bucket level
                pub_blocked = (pub_access['IgnorePublicAcls'] and
                               pub_access['RestrictPublicBuckets'])
            # TODO: catch expected exception
            except:
                # No bucket level public access block defined
                pub_blocked = False

            # Scan for dangerous grants in ACLs
            acl = s3.get_bucket_acl(Bucket=bucket)
            for grant in acl['Grants']:
                grantee, permission = grant['Grantee'], grant['Permission']
                read = False
                write = False
                if grantee['Type'] == 'Group' and grantee['URI'] == PUBLIC_URI:
                    if permission == 'FULL_CONTROL':
                        read = True
                        write = True
                    elif permission in ['WRITE', 'WRITE_ACP']:
                        write = True
                    elif permission == 'READ':
                        read = True
            # Flip table?
            if write and acct_pub_blocked or pub_blocked:
                # A public access block mitigates this acl grant
                acls_mitigated.append(bucket)
            elif write:
                # WE FLIP TABLE
                acls_write.append(bucket)
            elif read:
                acls_readonly.append(bucket)

        if acls_readonly or acls_write or acls_mitigated:
            sev = 'INFO'
            title = 'S3 Buckets with public access'
            if len(acls_write):
                sev = 'HIGH'
                title = 'World writable S3 Buckets'

            findings.append(Finding('s3_acls', title, sev,
                            acls_write=acls_write,
                            acls_mitigated=acls_mitigated,
                            acls_readonly=acls_readonly))

        # TODO bucket policies
        # TODO object level permissions

        return findings


class EncryptionScan(Scan):
    title = 'Scanning S3 buckets for encryption'
    permissions = ['s3:ListAllMyBuckets', 's3:GetEncryptionConfiguration']

    def run(self, context, profile=None):
        without = []
        for bucket in _get_all_buckets():
            try:
                # Most operations are region independent, but sometimes you
                # have to request encryption from the region the bucket
                # resides in
                location = s3.get_bucket_location(Bucket=bucket)['LocationConstraint']
                client = s3
                if location:
                    client = boto3.client('s3', region_name=location)
                enc = client.get_bucket_encryption(Bucket=bucket)['ServerSideEncryptionConfiguration']
                # If we get this far, there should be defined encryption :good:
            except ClientError as err:
                # Best way I've found to handle the error raised when a bucket
                # has no encryption settings defined, which is common
                if err.response['Error']['Code'] != ENC_NOT_FOUND:
                    raise err
                else:
                    without.append(bucket)
        if len(without):
            return [Finding('s3_encryption', 'S3 buckets without encryption',
                            'MEDIUM',
                            buckets=without)]
        return []


scans = ScanSuite('S3 Scans',
                  {'encryption': EncryptionScan()})
