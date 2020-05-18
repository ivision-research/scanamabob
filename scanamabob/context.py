import os
import sys
from configparser import ConfigParser
from scanamabob.services.ec2 import get_regions
from boto3.session import Session


def add_context_to_argparse(parser):
    parser.add_argument('-p', '--profiles', default='default',
                        help="AWS profiles to use, '*' for all")
    parser.add_argument('-r', '--regions', default='*',
                        help="AWS regions to use, '*' for all")


class Context(object):
    def __init__(self, profiles, regions, output='stdout'):
        # Profiles are the credential sets to use
        if ',' in profiles:
            self.profiles = profiles.split(',')
        elif '*' in profiles:
            filtered = [x for x in Session().available_profiles if x != 'test']
            self.profiles = filtered
        else:
            self.profiles = [profiles]

        # Current running profile of the context
        if 'default' in self.profiles:
            self.set_profile('default')
        else:
            self.set_profile(self.profiles[0])

        # Regions specify the regions to work with, when supported
        if ',' in regions:
            self.regions = regions.split(',')
        elif '*' in regions:
            self.regions = get_regions(self)
        else:
            self.regions = [regions]

        # Output gives other code a way to determine output format
        self.output = output

        # State is a flexible member that can be used to track within a command
        self.state = None

    def set_profile(self, profile):
        self.current_profile = profile
        self.session = Session(profile_name=profile)

    def regions_valid(self):
        valid = True
        for region in self.regions:
            if region not in get_regions(self):
                print(f'{region} was not found to be a valid region')
                valid = False
        return valid
