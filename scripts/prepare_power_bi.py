"""Prepare or verify a frozen Power BI file bundle; no training or SQL writes."""
import argparse

from cybershield.powerbi import prepare, verify_bundle

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--verify',metavar='BUNDLE',help='Verify an existing bundle offline without PostgreSQL')
args=parser.parse_args()
if args.verify:
    manifest=verify_bundle(args.verify)
    print('Verified:',manifest['report_bundle_id'])
else:
    print('Prepared:',prepare())
