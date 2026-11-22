"""A benchmark must reject changed result rows even with Python assertions disabled."""
import subprocess
import sys

from cybershield.db import ROOT


def test_optimized_benchmark_rejects_empty_reordered_and_changed_results():
    code = '''
import runpy
check = runpy.run_path('scripts/benchmark_sql.py')['check_result']
reference = {}
expected = [(1, 'a'), (2, 'b')]
first = check(reference, 0, expected)
if check(reference, 0, expected) != first:
    raise SystemExit('Equal results changed digest')
for bad in [[], expected[::-1], [(1, 'a'), (2, 'changed')]]:
    try:
        check(reference, 0, bad)
    except RuntimeError:
        continue
    raise SystemExit('Invalid benchmark result accepted under python -O')
print('Three invalid probes rejected; equal rows accepted under python -O')
'''
    result = subprocess.run([sys.executable, '-O', '-c', code], cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'Three invalid probes rejected' in result.stdout
