"""Smoke-check the running synthetic SQL workflow; no raw archives or API calls."""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0))
        port=listener.getsockname()[1]
    base=f'http://127.0.0.1:{port}'
    # Ignore machine-level proxies for this loopback-only smoke check.
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def fetch(path,payload=None,token=None):
        headers={'Content-Type':'application/json'}
        if token:headers['X-Workspace-Token']=token
        request=urllib.request.Request(base+path,
            data=None if payload is None else json.dumps(payload).encode(),headers=headers)
        with client.open(request,timeout=10) as response:
            return response.read()

    process=subprocess.Popen([sys.executable,'-m','cybershield','serve','--port',str(port)],cwd=ROOT)
    try:
        deadline=time.monotonic()+30
        while True:
            if process.poll() is not None:
                raise RuntimeError('The SQL workspace exited before becoming ready.')
            try:
                health=json.loads(fetch('/api/health'))
                assert health['status']=='ok'
                break
            except (urllib.error.URLError,TimeoutError):
                if time.monotonic()>=deadline:raise
                time.sleep(.2)
        page=fetch('/').decode()
        assert 'id="data-question"' in page and 'id="view-chart"' in page
        token=re.search(r'name="workspace-token" content="([^"]+)"',page).group(1)
        status=json.loads(fetch('/api/sql-assistant/status'))
        assert isinstance(status['configured'],bool) and status['model']
        try:
            fetch('/api/sql-assistant/draft',{'question':'Count flows','dataset':'fixture'})
        except urllib.error.HTTPError as exc:
            assert exc.code==403
        else:
            raise AssertionError('SQL drafting accepted a request without the page token.')
        metadata=json.loads(fetch('/api/bootstrap?dataset=fixture'))
        assert metadata['schema']=='cs_fixture' and metadata['flows']>0
        assert metadata['windows']>0 and metadata['experiment_id']
        for example in metadata['examples']:
            result=json.loads(fetch('/api/query',{
                'sql':example['sql'],'dataset':'fixture','limit':100},token))
            assert result['dataset']=='fixture' and result['columns']
            if example['id']=='triage':assert result['rows']
        try:
            fetch('/api/query',{'sql':'DELETE FROM flow','dataset':'fixture'},token)
        except urllib.error.HTTPError as exc:
            assert exc.code==400
        else:
            raise AssertionError('The workspace accepted a destructive statement.')
        print(json.dumps({'status':'passed','dataset':'synthetic fixture',
            'flows':metadata['flows'],'windows':metadata['windows'],
            'http_example_queries':len(metadata['examples']),'write_rejected':True,
            'question_and_chart_ui':True,'draft_token_required':True}))
    finally:
        process.terminate()
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill();process.wait(timeout=5)


if __name__=='__main__':main()
