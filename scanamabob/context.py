import os
import sys
from configparser import ConfigParser


def add_context_to_argparse(parser):
    parser.add_argument('-P', '--profiles', default='default',
                        help="AWS profiles to use, '*' for all")
    parser.add_argument('-r', '--regions', default='*',
                        help="AWS regions to use, '*' for all")


class Context(object):
    def __init__(self, profiles, regions):
        if ',' in profiles:
            self.profiles = profiles.split(',')
        else:
            self.profiles = [profiles]
        if ',' in regions:
            self.regions = regions.split(',')
        else:
            self.regions = [regions]

    def get_credentials(self, profile_name=None):
        if profile_name is None:
            profile_name = self.profiles[0]

        config = ConfigParser()
        credential_path = '~/.aws/credentials'
        config.read(os.path.expanduser(credential_path))
        if profile_name not in config.sections():
            print(f'Profile {profile_name} not found in {credential_path}')
            sys.exit(1)
        profile = config[profile_name]
        if 'aws_access_key_id' not in profile:
            print(f'AWS access key for profile {profile_name} not found')
            sys.exit(1)
        if 'aws_secret_access_key' not in profile:
            print(f'AWS secret key for profile {profile_name} not found')
            sys.exit(1)

        return profile['aws_access_key_id'], profile['aws_secret_access_key']
