from datetime import datetime, timezone
from scanamabob.scans import Finding, Scan, ScanSuite
from scanamabob.services.iam import client, resources, get_all_users, \
    get_credential_report


class MfaScan(Scan):
    title = 'AWS IAM Users without Multi-Factor Authentication'
    permissions = ['iam:ListUsers', 'iam:ListMFADevices',
                   'iam:GetLoginProfile']

    def run(self, context):
        usernames = get_all_users(context)
        users_without_mfa = []
        iam = client(context)

        for username in usernames:
            user = resources(context).User(username)

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

    def run(self, context):
        iam = client(context)
        creds_csv = get_credential_report(context)
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
    title = 'AWS account password policies'
    permissions = ['iam:GetAccountPasswordPolicy']

    def run(self, context):
        iam = client(context)
        try:
            policy = resources(context).AccountPasswordPolicy()
            policy.load()
        except iam.exceptions.NoSuchEntityException:
            return [Finding(context.state, 'No AWS account-level password policy', 'HIGH')]
        res = list()
        if policy.minimum_password_length < 16:
            sev = 'LOW'
            if policy.minimum_password_length < 10:
                sev = 'MEDIUM'
            if policy.minimum_password_length <= 8:
                sev = 'HIGH'
            if policy.minimum_password_length <= 6:
                sev = 'CRITICAL'
            res.append(Finding(context.state, 'Minimum password length too low', sev, password_length=policy.minimum_password_length))
        complexity = policy.require_lowercase_characters + policy.require_numbers + policy.require_symbols + policy.require_uppercase_characters
        if complexity < 4:
            sev = 'LOW'
            if complexity < 2:
                sev = 'MEDIUM'
            res.append(Finding(context.state, 'Few complexity requirements', sev,
                require_lowercase_characters=policy.require_lowercase_characters,
                require_numbers=policy.require_numbers,
                require_symbols=policy.require_symbols,
                require_uppercase_characters=policy.require_uppercase_characters))
        if not policy.password_reuse_prevention:
            res.append(Finding(context.state, 'No password reuse prevention', 'LOW'))

        # Unused policy attributes:
        # allow_users_to_change_password
        # expire_passwords
        # hard_expiry
        # max_password_age
        return res


class KeyRotation(Scan):
    title = 'Checking for old AWS access keys'
    permissions = []

    def run(self, context):
        year_plus = []
        ninetydays_plus = []
        iam = client(context)
        for user in get_all_users(context):
            keys = iam.list_access_keys(UserName=user)['AccessKeyMetadata']
            for key in keys:
                created = key['CreateDate']
                now = datetime.now(timezone.utc)
                delta_days = (now - created).days
                if delta_days >= 365:
                    year_plus.append(user)
                elif delta_days >= 90:
                    ninetydays_plus.append(user)
        if len(year_plus):
            return [Finding(context.state,
                            'Access keys older than 1 year',
                            'MEDIUM',
                            year_plus=year_plus,
                            ninetydays_plus=ninetydays_plus)]
        elif len(ninetydays_plus):
            return [Finding(context.state,
                            'Access keys older than 90 days',
                            'LOW',
                            year_plus=year_plus,
                            ninetydays_plus=ninetydays_plus)]
        return []


scans = ScanSuite('IAM Scans',
                  {'mfa': MfaScan(),
                   'rootkey': RootAccessKey(),
                   'password_policy': PasswordPolicy(),
                   'key_rotation': KeyRotation()})
