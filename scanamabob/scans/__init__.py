import json
import colorama

colorama.init()
reset_style = colorama.Style.RESET_ALL
severity_colors = {
    'CRITICAL': colorama.Fore.BLACK + colorama.Back.RED,
    'HIGH': colorama.Fore.RED,
    'MEDIUM': colorama.Fore.YELLOW,
    'LOW': colorama.Fore.MAGENTA,
    'INFO': colorama.Fore.CYAN
}


class Scan(object):
    ''' Base object that each scan will be a subclass of '''
    title = 'Unnamed Scan'
    permissions = []
    finding_template = None

    def run(self, context):
        print('Scan "{}" has no defined run method'.format(self.title))
        return []


class ScanSuite(object):
    ''' Facilitates running a set of scans together '''
    def __init__(self, title, scans):
        self.title = title
        self.scans = scans

    def run(self, context):
        if context.output == 'stdout':
            print('Running Scan Suite "{}"'.format(self.title))
        findings = []
        here_state = context.state
        for scantype in self.scans:
            context.state = f'{here_state}.{scantype}'
            scan = self.scans[scantype]
            if context.output == 'stdout':
                print(' - Running Scan "{}"'.format(scan.title))
            findings.extend(scan.run(context))
        return findings

    def get_permissions(self):
        permissions = []
        for scan in self.scans:
            permissions.extend(self.scans[scan].permissions)
        return sorted(set(permissions))


class Finding(object):
    ''' Represents a finding '''
    def __init__(self, tag, title, severity, **data):
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        # Scan tag helps to identify which scan found the finding
        self.tag = tag
        # Title of finding
        self.title = title
        # Severity of the finding
        if severity not in severities:
            raise Exception(f'Severity must be within set {severities}')
        self.severity = severity
        # Data holds additional data regarding a finding
        self.data = data

    def as_dict(self):
        return self.__dict__

    def as_stdout(self):
        data = json.dumps(self.data, indent=4)
        color = colorama.Fore.RED
        return (f'{color} * {self.severity} * ' +
                f'{self.title} ({self.tag}){reset_style}\n' +
                f'{data}')
