import sys
from argparse import ArgumentParser
import time

DESCRIPTION = 'Identify publicly accessible S3 buckets and objects'
USAGE = f'''{sys.argv[0]} s3audit [-h]'''


def parse_args(args):
    parser = ArgumentParser(description=DESCRIPTION,
                            usage=USAGE)
    return parser.parse_args(args)


def command(args):
    arguments = parse_args(args)
    print('Will scan S3 for publicly accessible buckets and objects...')


COMMAND = {'description': DESCRIPTION,
           'function': command}
