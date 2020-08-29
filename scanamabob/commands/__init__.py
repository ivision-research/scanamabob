from .s3audit import add_parser as s3audit
from .scan import add_parser as scan
from .summary import add_parser as summary

add_parser_funcs = {"s3audit": s3audit, "scan": scan, "summary": summary}
