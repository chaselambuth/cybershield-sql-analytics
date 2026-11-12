"""Run explicit live or free reference evaluations. Never treats reference runs as LLM quality."""
import argparse
import json
import statistics
from datetime import datetime,timezone

from cybershield.agent import evidence_store,run_investigation
from cybershield.db import ROOT


def grade(case,result):
    evidence=result['evidence']; tools={e['tool'] for e in evidence}
    report=result.get('report') or {}
    checks={'completed':result['status']=='completed','expected_tools':set(case['expected_tools'])<=tools,
        'appropriate_verdict':report.get('verdict') in case['expected_verdicts'],
        'citation_integrity':set(report.get('evidence_ids',[]))<={e['evidence_id'] for e in evidence},
        'tool_budget':result['tool_calls']<=8}
    kind=case['check']
    if kind=='flow_membership':
        details=[e['data'] for e in evidence if e['tool']=='inspect_window']
        checks['exact_flow_membership']=bool(details) and all(d['window'] and d['supporting_flow_count']==d['window']['flow_count']
            and all(f['src_ip']==d['window']['src_ip'] for f in d['supporting_flows']) for d in details)
    elif kind=='constraints':
        models=[e['data'] for e in evidence if e['tool']=='compare_models']
        checks['requested_constraints']=bool(models) and any(m['constraints']=={'max_false_positives':40,'max_p95_ms':2}
            and m['models'] and all(r['fp']<=40 and r['single_pipeline_p95_ms']<=2 for r in m['models']) for m in models)
    elif kind=='empty_source':
        selections=[e for e in evidence if e['tool']=='search_windows']
        checks['no_substitution']=bool(selections) and all(e['parameters'][1]=='203.0.113.250' and not e['data']['windows'] for e in selections) and 'inspect_window' not in tools
    elif kind=='ties':
        passages=[p for e in evidence if e['tool']=='search_knowledge' for p in e['data']['passages']]
        text=report.get('synthesis','').lower()
        checks['retrieved_tie_evidence']=any(p['id']=='ties' for p in passages)
        checks['mentions_limits']=('tie' in text and any(w in text for w in ['development','correlated','campaign','production']))
    elif kind=='no_tools':
        checks['no_action_tools']=tools<={'get_context','search_knowledge'} and report.get('verdict')=='out_of_scope'
    return checks


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=['live','reference'],default='reference')
    parser.add_argument('--cases',nargs='*',help='Optional case IDs; default all cases.')
    args=parser.parse_args()
    cases=json.loads((ROOT/'evals/agent_cases.json').read_text())
    if args.cases:cases=[c for c in cases if c['id'] in args.cases]
    if not cases:raise SystemExit('No matching evaluation cases.')
    store=evidence_store(); rows=[]
    for case in cases:
        result=run_investigation(case['question'],args.mode,store=store)
        checks=grade(case,result)
        rows.append({'case':case['id'],'passed':all(checks.values()),'checks':checks,'run':result})
        print(case['id'],result['status'],'PASS' if all(checks.values()) else 'FAIL',round(result['latency_ms']/1000,2),'s',flush=True)
    latencies=sorted(row['run']['latency_ms'] for row in rows)
    summary={'created_utc':datetime.now(timezone.utc).isoformat(),'mode':args.mode,'model':rows[0]['run']['model'],
        'benchmark_id':store.manifest['benchmark_id'],'report_bundle_id':store.manifest['report_bundle_id'],
        'passed':sum(r['passed'] for r in rows),'cases':len(rows),'median_latency_ms':statistics.median(latencies),
        'max_latency_ms':max(latencies),'estimated_cost_usd':sum((r['run']['estimated_cost_usd'] or 0) for r in rows),
        'scope':'Small integration/adversarial scenario suite. Checks tool selection, constraints, citations and boundaries; not a semantic truth guarantee or production readiness benchmark.',
        'latency_note':'One run per heterogeneous question; descriptive timings, no comparable workload percentile claim.',
        'results':rows}
    output=ROOT/'reports/agent_evaluation';output.mkdir(exist_ok=True)
    target=output/(args.mode+'.json')
    history=output/'history';history.mkdir(exist_ok=True)
    if target.exists():
        previous=json.loads(target.read_text(encoding='utf-8'))
        stamp=previous['created_utc'].replace(':','').replace('+','_')
        (history/(args.mode+'_'+stamp+'.json')).write_text(json.dumps(previous,indent=2),encoding='utf-8')
    target.write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(f'{summary["passed"]}/{len(rows)} passed; saved {target}')
    if summary['passed']!=len(rows):raise SystemExit(1)


if __name__=='__main__':main()
