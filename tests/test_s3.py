# -*- coding: utf-8 -*-

from scanamabob.context import Context
from scanamabob.scans.s3 import PermissionScan

from .context import scanamabob


def test_world_writeable_s3_bucket():
    findings = PermissionScan().run(Context("default", "us-east-1"))
    found = False

    for finding in findings:
        if finding.title == "World writable S3 Buckets":
            found = True

    assert found
