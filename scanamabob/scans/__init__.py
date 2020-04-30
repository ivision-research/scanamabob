class Scan(object):
    title = 'Unnamed Scan'
    permissions = []
    finding_template = None

    def run(self):
        print('Scan "{}" has no defined run method'.format(self.title))
        return []


class ScanSet(object):
    def __init__(self, title, *scans):
        self.title = title
        self.scans = scans

    def run(self):
        print('Running Scan Set "{}"'.format(self.title))
        findings = []
        for scan in self.scans:
            print(' - Running Scan "{}"'.format(scan.title))
            findings.extend(scan.run())
        return findings

    def get_permissions(self):
        permissions = []
        for scan in self.scans:
            permissions.extend(scan.permissions)
        return sorted(set(permissions))


class Finding(object):
    def __init__(self, tag, title, severity, **data):
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        if severity not in severities:
            raise Exception(f'Severity must be within set {severities}')
        self.title = title
        self.severity = severity
        self.data = data
