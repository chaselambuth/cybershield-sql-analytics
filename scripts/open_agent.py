"""Start/reuse the local investigation workbench; no Docker or database required."""
import json
import subprocess
import sys
import time
import urllib.request
import webbrowser

from cybershield.db import ROOT

URL='http://127.0.0.1:8766'


def ready():
    try:
        with urllib.request.urlopen(URL+'/api/health',timeout=1) as response:
            return json.load(response).get('service')=='cybershield-query-workspace'
    except (OSError,ValueError):return False


def main():
    if not ready():
        logs=ROOT/'reports';logs.mkdir(exist_ok=True)
        options={'creationflags':subprocess.CREATE_NO_WINDOW} if sys.platform=='win32' else {'start_new_session':True}
        with (logs/'agent-server.log').open('a',encoding='utf-8') as out, (logs/'agent-server-error.log').open('a',encoding='utf-8') as err:
            process=subprocess.Popen([sys.executable,str(ROOT/'scripts/serve_agent.py')],cwd=ROOT,stdout=out,stderr=err,**options)
            (ROOT/'.agent.pid').write_text(str(process.pid))
        for _ in range(40):
            if ready():break
            if process.poll() is not None:raise RuntimeError('Agent stopped. Check reports/agent-server-error.log.')
            time.sleep(.25)
        else:raise RuntimeError('Agent workbench did not start.')
    print('CyberShield investigation agent: '+URL+'/investigate')
    webbrowser.open(URL+'/investigate')


if __name__=='__main__':main()
