# -*- coding: utf-8 -*-

from .context import scanamabob
from scanamabob.scans.s3 import PermissionScan
from scanamabob.context import Context

def test_world_writeable_s3_bucket():
    findings = PermissionScan().run(Context('default', 'us-east-1'))
    found = False

    for finding in findings:
        if finding.title == 'World writable S3 Buckets':
            found = True

    assert found
