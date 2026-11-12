"""Validate generated PBIR against Microsoft schemas; caches schemas locally."""
import argparse
import hashlib
import json
import urllib.error
import urllib.request

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from cybershield.db import ROOT

cache=ROOT/'.tmp/powerbi_schema_cache';cache.mkdir(parents=True,exist_ok=True)
aliases={}
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--allow-published-schema-fallback',action='store_true',
                    help='Validate Desktop-upgraded files against the generated format when their exact Microsoft schema returns 404; records this limitation.')
args=parser.parse_args()
fallbacks={
    'report/3.3.0/schema.json':'report/3.0.0/schema.json',
    'page/2.1.0/schema.json':'page/2.0.0/schema.json',
    'visualContainer/2.14.0/schema.json':'visualContainer/2.3.0/schema.json',
}
schema_fallbacks={}


def fetch(url):
    path=cache/(hashlib.sha256(url.encode()).hexdigest()+'.json')
    if not path.exists():
        try:
            data=urllib.request.urlopen(url,timeout=30).read()
        except urllib.error.HTTPError as exc:
            # Microsoft's 2.3 schema contains this stale spelling in a $ref.
            if exc.code!=404 or 'schema.embedded.json' not in url:raise
            canonical=url.replace('schema.embedded.json','schema-embedded.json')
            data=urllib.request.urlopen(canonical,timeout=30).read();aliases[url]=canonical
        path.write_bytes(data)
    return json.loads(path.read_text(encoding='utf-8'))


errors=[];checked=[]
registry=Registry(retrieve=lambda uri:Resource.from_contents(fetch(uri),default_specification=DRAFT7))
for path in sorted((ROOT/'power_bi/CyberShield.Report/definition').rglob('*.json')):
    data=json.loads(path.read_text(encoding='utf-8'));url=data.get('$schema')
    if not url:continue
    try:
        definition=fetch(url)
    except urllib.error.HTTPError as exc:
        replacement=next((url[:-len(old)]+new for old,new in fallbacks.items() if url.endswith(old)),None)
        if exc.code!=404 or not args.allow_published_schema_fallback or replacement is None:raise
        definition=fetch(replacement)
        schema_fallbacks[url]=replacement
    resource=Resource.from_contents(definition,default_specification=DRAFT7)
    local_registry=registry.with_resource(url,resource)
    # The published schema constrains its own $schema URI. Only normalize that
    # metadata in memory; every report property is still checked, files unchanged.
    validation_data={**data,'$schema':schema_fallbacks[url]} if url in schema_fallbacks else data
    for error in jsonschema.Draft7Validator(definition,registry=local_registry).iter_errors(validation_data):
        errors.append({'file':str(path.relative_to(ROOT)),'path':list(error.path),'message':error.message})
    checked.append({'file':str(path.relative_to(ROOT)),'schema':url,
                    'validated_against':schema_fallbacks.get(url,url)})
result={'status':'failed' if errors else ('passed_with_schema_fallback' if schema_fallbacks else 'passed'),
        'checked':checked,'errors':errors,'schema_url_aliases':aliases,'schema_fallbacks':schema_fallbacks,
        'scope':'PBIR JSON schema validation; does not substitute for Desktop refresh or DAX checks',
        'limitation':'Exact Desktop-upgraded schemas returned 404; listed files validated against the generated format schemas.' if schema_fallbacks else None}
folder=ROOT/'power_bi/validation';folder.mkdir(exist_ok=True)
(folder/'project_schema.json').write_text(json.dumps(result,indent=2))
print(f'PBIR schema validation: {len(checked)} files; {len(errors)} errors')
if errors:raise SystemExit(json.dumps(errors,indent=2))
