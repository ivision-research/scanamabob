from .s3audit import COMMAND as s3audit
from .scan import COMMAND as scan
from .summary import COMMAND as summary

commands = {
    's3audit': s3audit,
    'scan': scan,
    'summary': summary
}
