"""Fetch the pinned, bounded-size public researcher archive, without extracting it."""
import hashlib
import json
import urllib.request

from cybershield.db import ROOT, file_hash

URL = 'https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip'
SHA256 = '97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883'
SIZE = 343549013
target = ROOT / 'data/raw/CICIDS2017_improved.zip'
target.parent.mkdir(parents=True,exist_ok=True)
if target.exists():
    if file_hash(target) != SHA256:
        raise ValueError('Existing archive differs from pinned release; inspect before replacing it.')
    print('Pinned corrected archive already present.')
else:
    temporary = target.with_suffix('.partial')
    try:
        with urllib.request.urlopen(URL,timeout=60) as response:
            if int(response.headers.get('Content-Length',0)) != SIZE:
                raise ValueError('Remote size differs from pinned source; review changed release.')
            received = 0; digest = hashlib.sha256()
            with temporary.open('wb') as stream:
                while chunk := response.read(1024*1024):
                    received += len(chunk)
                    if received > SIZE:
                        raise ValueError('Download exceeds pinned size')
                    stream.write(chunk); digest.update(chunk)
            if received != SIZE or digest.hexdigest() != SHA256:
                raise ValueError('Source size/hash verification failed')
            metadata = {'url':URL,'bytes':received,'sha256':SHA256,
                        'response_last_modified':response.headers.get('Last-Modified')}
        temporary.replace(target)
        target.with_suffix('.download.json').write_text(json.dumps(metadata,indent=2))
    finally:
        temporary.unlink(missing_ok=True)
    print('Downloaded and verified pinned corrected archive; no members extracted.')
