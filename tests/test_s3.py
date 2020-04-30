# -*- coding: utf-8 -*-

from .context import scanamabob
from scanamabob.s3 import PermissionScan

def test_world_writeable_s3_bucket():
    findings = PermissionScan().run()
    found = False

    for finding in findings:
        if finding.title == 'World writable S3 Buckets':
            found = True

    assert found
