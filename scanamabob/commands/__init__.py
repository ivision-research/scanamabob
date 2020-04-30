from .s3audit import COMMAND as s3audit
from .scan import COMMAND as scan

commands = {
    's3audit': s3audit,
    'scan': scan
}
