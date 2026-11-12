"""User-invoked launcher: reuse/start the local workspace, then open its URL."""
from pathlib import Path
import json
import subprocess
import sys
import time
import urllib.request
import webbrowser

ROOT=Path(__file__).resolve().parents[1]
URL='http://127.0.0.1:8765'


def ready():
    try:
        with urllib.request.urlopen(URL+'/api/health',timeout=1) as response:
            return json.load(response).get('service')=='cybershield-query-workspace'
    except (OSError,ValueError):
        return False


def main():
    if not ready():
        subprocess.run(['docker','compose','up','-d','--wait'],cwd=ROOT,check=True)
        logs=ROOT/'reports';logs.mkdir(exist_ok=True)
        options={'creationflags':subprocess.CREATE_NO_WINDOW} if sys.platform=='win32' else {'start_new_session':True}
        with (logs/'workspace-server.log').open('a',encoding='utf-8') as output, \
             (logs/'workspace-server-error.log').open('a',encoding='utf-8') as error:
            process=subprocess.Popen([sys.executable,'-m','cybershield','serve','--port','8765'],
                                     cwd=ROOT,stdout=output,stderr=error,**options)
            (ROOT/'.workspace.pid').write_text(str(process.pid),encoding='utf-8')
        for _ in range(50):
            if ready():break
            if process.poll() is not None:
                raise RuntimeError('Workspace stopped. Check reports/workspace-server-error.log.')
            time.sleep(.3)
        else:
            raise RuntimeError('Workspace did not start. Check Docker Desktop and the workspace logs.')
    print('CyberShield SQL workspace: '+URL)
    webbrowser.open(URL)


if __name__=='__main__':
    try:
        main()
    except (OSError,RuntimeError,subprocess.CalledProcessError) as exc:
        print(str(exc),file=sys.stderr)
        raise SystemExit(1)

