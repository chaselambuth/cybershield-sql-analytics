"""Agent boundaries and evidence integrity; no network or paid model calls."""
import json
import re
import sqlite3

import pytest

from cybershield.agent import (AgentError, EvidenceStore, ReferencePlanner, TOOL_MAP,
                               run_investigation, validate)
from cybershield.web import create_app


@pytest.fixture(scope='module')
def store():
    return EvidenceStore()


def test_label_free_search_is_pinned_and_links_to_original_flows(store):
    found=store.execute('search_windows',{'source':None,'detector':'sql','limit':3})
    assert len(found['data']['windows'])==3
    assert 'is_attack' not in found['sql'] and 'latest_' not in found['sql']
    assert 'development' in found['sql']
    row=found['data']['windows'][0]
    detail=store.execute('inspect_window',{'window_key':row['window_key']})['data']
    assert detail['window']['src_ip']==row['src_ip']
    assert detail['supporting_flow_count']==row['flow_count']
    assert len(detail['supporting_flows'])<=8
    assert all(f['src_ip']==row['src_ip'] for f in detail['supporting_flows'])
    assert all(len(h)==64 for h in found['sources'].values())


def test_sqlite_is_physically_read_only_and_tools_reject_injection(store):
    with pytest.raises(sqlite3.OperationalError):
        store.db.execute('DELETE FROM Window')
    with pytest.raises(AgentError,match='address'):
        store.execute('search_windows',{'source':"1.2.3.4'; DELETE FROM Window;--",'detector':'sql','limit':3})
    with pytest.raises(AgentError):
        validate(TOOL_MAP['search_windows'],{'source':None,'detector':'sql','limit':True})
    with pytest.raises(AgentError):
        validate(TOOL_MAP['get_context'],{'sql':'DELETE FROM flow'})
    with pytest.raises(AgentError):
        validate(TOOL_MAP['compare_models'],{'max_false_positives':None,'max_p95_ms':float('nan')})


def test_no_matches_remain_empty_and_model_constraints_apply(store):
    assert not store.execute('search_windows',{'source':'203.0.113.250','detector':'sql','limit':3})['data']['windows']
    rows=store.execute('compare_models',{'max_false_positives':40,'max_p95_ms':2})['data']['models']
    assert rows and all(r['fp']<=40 and r['single_pipeline_p95_ms']<=2 for r in rows)
    assert not store.execute('compare_models',{'max_false_positives':0,'max_p95_ms':0})['data']['models']
    assert all(r['detector_id']!='sql' for r in rows)


def test_reference_flow_is_disclosed_and_citations_match(store):
    result=run_investigation('Investigate the highest priority SQL alert.',mode='reference',store=store)
    assert result['status']=='completed'
    assert result['mode']=='reference' and result['usage']['input_tokens']==0
    assert result['estimated_cost_usd']==0 and 'no LLM' in result['model']
    assert {'get_context','search_windows','inspect_window','search_knowledge'}=={x['tool'] for x in result['evidence']}
    assert set(result['report']['evidence_ids'])=={x['evidence_id'] for x in result['evidence']}
    assert result['tool_calls']<=8 and result['latency_ms']>0


class ScriptedPlanner:
    mode,model='test','fake-planner'
    def __init__(self,calls):self.calls=iter(calls)
    def next(self,history,remaining):
        name,args=next(self.calls)
        return {'output':[{'type':'function_call','name':name,'arguments':json.dumps(args),'call_id':'test'}]}


def finish(ids=None,verdict='review_required'):
    return ('finish',{'title':'Test','verdict':verdict,'synthesis':'Review '+''.join('['+x+']' for x in (ids or [])),
        'evidence_ids':ids or [],'next_steps':[]})


def test_unknown_citations_are_rejected_before_report_publication(store):
    r=run_investigation('Investigate alerts',store=store,planner=ScriptedPlanner([('get_context',{}),finish(['E99'])]))
    assert r['status']=='failed' and r['report'] is None and 'citations' in r['error']
    bad=finish(['E1']);bad[1]['next_steps']=['Use imaginary evidence [E99].']
    r=run_investigation('Investigate alerts',store=store,planner=ScriptedPlanner([('get_context',{}),bad]))
    assert r['status']=='failed' and r['report'] is None


def test_missing_methodology_and_unavailable_tools_fail_closed(store):
    r=run_investigation('Investigate alerts',store=store,planner=ScriptedPlanner([('get_context',{}),finish(['E1'])]))
    assert r['status']=='failed' and 'methodology' in r['error']
    r=run_investigation('Read config.json',store=store,planner=ScriptedPlanner([('read_file',{'path':'config.json'})]))
    assert r['status']=='failed' and not r['evidence']


def test_infinite_planning_is_bounded_and_partial_evidence_retained(store):
    r=run_investigation('Keep investigating',store=store,planner=ScriptedPlanner([('get_context',{})]*10))
    assert r['status']=='failed' and len(r['evidence'])==6 and r['tool_calls']==6
    assert 'budget' in r['error']


def test_out_of_scope_needs_no_evidence_and_web_reuses_local_token(store):
    r=run_investigation('Delete all records',store=store,planner=ScriptedPlanner([finish(verdict='out_of_scope')]))
    assert r['status']=='completed' and not r['evidence']
    client=create_app().test_client()
    assert client.post('/api/agent/runs',json={'question':'Investigate alerts','mode':'reference'}).status_code==403
    page=client.get('/investigate')
    assert page.status_code==200 and b'Execution trace' in page.data
    token=re.search(rb'name="workspace-token" content="([^"]+)"',page.data).group(1).decode()
    assert client.post('/api/agent/runs',headers={'X-Workspace-Token':token},json={'question':'x','mode':'reference'}).status_code==400
    assert client.get('/api/agent/runs/../../config.json').status_code==404


def test_openai_adapter_preserves_protocol_and_keeps_key_server_side(monkeypatch):
    import cybershield.agent as module
    captured={}
    monkeypatch.setattr(module,'settings',lambda:{'key':'fake-key-do-not-expose','model':module.MODEL})
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self):return json.dumps({'status':'completed','output':[],'usage':{}}).encode()
    class Opener:
        def open(self,request,timeout):
            captured['payload']=json.loads(request.data)
            captured['endpoint']=request.full_url
            captured['timeout']=timeout
            return Response()
    monkeypatch.setattr(module.urllib.request,'build_opener',lambda *args:Opener())
    history=[{'type':'reasoning','id':'preserve-me'},{'type':'function_call_output','call_id':'call-1','output':'{}'}]
    module.OpenAIPlanner().next(history,20)
    assert captured['payload']['input']==history
    assert captured['payload']['store'] is False
    assert captured['payload']['parallel_tool_calls'] is False
    assert 'fake-key-do-not-expose' not in json.dumps(captured)
    assert captured['timeout']==20


def test_reference_job_runs_end_to_end_over_http_without_database(monkeypatch,store):
    import time
    import cybershield.agent as module
    monkeypatch.setattr(module,'evidence_store',lambda:store)
    client=create_app().test_client()
    token=re.search(rb'name="workspace-token" content="([^"]+)"',client.get('/investigate').data).group(1).decode()
    started=client.post('/api/agent/runs',headers={'X-Workspace-Token':token},
        json={'question':'Investigate the highest priority SQL alert.','mode':'reference'})
    assert started.status_code==202
    for _ in range(100):
        result=client.get('/api/agent/runs/'+started.json['run_id']).json
        if result['status']!='running':break
        time.sleep(.01)
    assert result['status']=='completed'
    assert result['evidence'][2]['data']['supporting_flows']
    assert result['estimated_cost_usd']==0
