"""Validate the selected immutable bundle before opening Power BI Desktop."""
import subprocess
from pathlib import Path

from cybershield.db import ROOT
from cybershield.powerbi import load_json, require, verify_bundle

context=load_json(ROOT/'power_bi/project_context.json')
manifest=verify_bundle(context['bundle_path'])
require(manifest['report_bundle_id']==context['report_bundle_id'],'Selected project/bundle identity differs')
executable=Path('C:/Program Files/Microsoft Power BI Desktop/bin/PBIDesktop.exe')
if not executable.is_file():
    raise SystemExit('Install Microsoft Power BI Desktop, then open power_bi/CyberShield.pbip.')
subprocess.Popen([str(executable),str(ROOT/'power_bi/CyberShield.pbip')])
print('Opened the verified CyberShield Power BI project.')
