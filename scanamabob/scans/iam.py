import boto3
from scanamabob.scans import Finding, Scan, ScanSuite
from scanamabob.services.iam import client, resources, get_all_users, \
    get_credential_report


class MfaScan(Scan):
    title = 'AWS IAM Users without Multi-Factor Authentication'
    permissions = ['iam:ListUsers', 'iam:ListMFADevices',
                   'iam:GetLoginProfile']

    def run(self, context, profile=None):
        usernames = get_all_users(context, profile)
        users_without_mfa = []
        iam = client(context, profile)

        for username in usernames:
            user = resources(context, profile).User(username)

            # Determine if user has a login profile (Console access)
            try:
                _ = iam.get_login_profile(UserName=username)
            except iam.exceptions.NoSuchEntityException:
                # This user does not have access to the AWS Console
                continue
            except Exception as err:
                print(f'Unexpected error: {err}')
                continue

            # Check if user has any MFA devices registered
            mfa_devices = list(user.mfa_devices.all())
            if len(mfa_devices) < 1:
                users_without_mfa.append(username)

        # If any users have a login profile, but no MFA, generate a finding
        if len(users_without_mfa):
            finding = Finding(context.state, self.title, 'HIGH',
                              users=users_without_mfa)
            return [finding]

        return []


class RootAccessKey(Scan):
    title = 'AWS Account with enabled Root Access Key'
    permissions = ['iam:GenerateCredentialReport', 'iam:GetCredentialReport']

    def run(self, context, profile=None):
        iam = client(context, profile)
        creds_csv = get_credential_report(context, profile)
        for row in creds_csv.split('\n')[1:]:
            col = row.split(',')
            user = col[0]
            if user == '<root_account>':
                key1 = col[8]
                key2 = col[13]
                if key1 == 'true' or key2 == 'true':
                    return [Finding(context.state, self.title, 'HIGH')]
        return []


class PasswordPolicy(Scan):
    title = 'Checking AWS account password policies'
    permissions = ['iam:GetAccountPasswordPolicy']

    def run(self, context, profile=None):
        iam = client(context, profile)
        try:
            policy = resources(context).AccountPasswordPolicy()
            policy.load()
        except iam.exceptions.NoSuchEntityException:
            return [Finding(context.state,
                            'No AWS account-level password policy', 'HIGH')]
        # TODO define and add findings for weak password policies
        return []


scans = ScanSuite('IAM Scans',
                  {'mfa': MfaScan(),
                   'rootkey': RootAccessKey(),
                   'password_policy': PasswordPolicy()})
