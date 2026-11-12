"""Local SQL workspace. Browser input is executed only as the dedicated reader."""
from __future__ import annotations

import secrets
from pathlib import Path

from flask import Flask, jsonify, render_template, request
import psycopg

from .workspace import QueryRejected, dataset_metadata, prepare_workspace, run_query
from .agent import AgentError, InvestigationService, MODEL, settings

WEB_ROOT=Path(__file__).resolve().parent/'web_assets'
EXAMPLES=[
    {'id':'triage','title':'Highest-priority windows','description':'Explore the ranked development queue.',
     'sql':'''SELECT host(src_ip) AS source, window_start, split,
       ROUND(score::numeric, 2) AS score,
       flow_count, service_flows, fired_rules
FROM latest_triage
WHERE split = 'development'
ORDER BY score DESC, window_start
LIMIT 20;'''},
    {'id':'traffic','title':'Traffic over time','description':'Aggregate observed morning activity by hour.',
     'sql':'''SELECT date_trunc('hour', window_start) AS hour,
       SUM(flow_count) AS flows,
       COUNT(DISTINCT src_ip) AS active_sources,
       SUM(bytes) AS total_bytes
FROM latest_features
GROUP BY 1
ORDER BY 1;'''},
    {'id':'labels','title':'Label distribution','description':'Review the benchmark annotations in the full file.',
     'sql':'''SELECT label, COUNT(*) AS flows
FROM flow_label
GROUP BY label
ORDER BY flows DESC;'''},
    {'id':'services','title':'Repeated service traffic','description':'Find sources contacting FTP or SSH services.',
     'sql':'''SELECT host(src_ip) AS source,
       SUM(service_flows) AS service_flows,
       SUM(flow_count) AS total_flows,
       MAX(service_flows) AS peak_service_window
FROM latest_features
GROUP BY src_ip
HAVING SUM(service_flows) > 0
ORDER BY service_flows DESC
LIMIT 20;'''},
    {'id':'comparison','title':'Rules versus ML','description':'Compare exact development confusion counts.',
     'sql':'''SELECT p.method,
       COUNT(*) FILTER (WHERE p.predicted_attack AND l.attack_flows > 0) AS true_positives,
       COUNT(*) FILTER (WHERE p.predicted_attack AND l.attack_flows = 0) AS false_positives,
       COUNT(*) FILTER (WHERE NOT p.predicted_attack AND l.attack_flows > 0) AS missed_windows
FROM latest_predictions p
JOIN latest_window_labels l USING (feature_run_id, src_ip, window_start)
WHERE p.split = 'development' AND l.unknown_flows = 0
GROUP BY p.method
ORDER BY false_positives, p.method;'''},
    {'id':'flows','title':'Inspect supporting flows','description':'Trace a source back to original flow records.',
     'sql':'''SELECT flow_id, host(src_ip) AS source, host(dst_ip) AS destination,
       dst_port, raw_timestamp, packets, bytes, row_number AS source_row
FROM flow
WHERE src_ip = '172.16.0.1' AND clock_usable
ORDER BY reported_end, flow_id
LIMIT 25;'''}
]


def create_app():
    app=Flask(__name__,template_folder=str(WEB_ROOT),static_folder=str(WEB_ROOT/'static'))
    app.config.update(MAX_CONTENT_LENGTH=32_000,JSON_SORT_KEYS=False)
    token=secrets.token_urlsafe(32)
    investigations=InvestigationService()

    @app.before_request
    def local_request():
        hostname=request.host.split(':',1)[0].lower()
        if hostname not in {'localhost','127.0.0.1'}:
            return jsonify(error='Use the local workspace address.'),403
        if request.method=='POST':
            if not request.is_json or not secrets.compare_digest(request.headers.get('X-Workspace-Token',''),token):
                return jsonify(error='Refresh the workspace and try again.'),403

    @app.after_request
    def response_headers(response):
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Cache-Control']='no-store'
        return response

    @app.get('/')
    def index():
        return render_template('index.html',token=token)

    @app.get('/investigate')
    def investigate():
        return render_template('investigate.html',token=token)

    @app.get('/api/agent/status')
    def agent_status():
        config=settings()
        return jsonify(configured=bool(config['key']),model=config['model'],default_model=MODEL,
                       max_tools=8,max_turns=6,max_seconds=90)

    @app.post('/api/agent/runs')
    def agent_run():
        payload=request.get_json(silent=True)
        if not isinstance(payload,dict) or set(payload)-{'question','mode'}:
            raise AgentError('Send an investigation question and mode.')
        run_id=investigations.submit(payload.get('question'),payload.get('mode','live'))
        return jsonify(run_id=run_id),202

    @app.get('/api/agent/runs/<run_id>')
    def agent_result(run_id):
        result=investigations.get(run_id)
        return (jsonify(result) if result else (jsonify(error='Run not found or expired. Start a new investigation.'),404))

    @app.errorhandler(AgentError)
    def agent_rejected(exc):
        return jsonify(error=str(exc)),400

    @app.get('/api/health')
    def health():
        return jsonify(status='ok',service='cybershield-query-workspace')

    @app.get('/api/bootstrap')
    def bootstrap():
        return jsonify(**dataset_metadata(request.args.get('dataset','real')),examples=EXAMPLES)

    @app.post('/api/query')
    def query():
        payload=request.get_json(silent=True)
        if not isinstance(payload,dict):
            raise QueryRejected('Send a SQL query to continue.')
        return jsonify(run_query(payload.get('sql',''),payload.get('dataset','real'),payload.get('limit',250)))

    @app.errorhandler(QueryRejected)
    def rejected(exc):
        return jsonify(error=str(exc)),400

    @app.errorhandler(psycopg.OperationalError)
    def unavailable(exc):
        return jsonify(error='PostgreSQL is unavailable. Run docker compose up -d --wait, then refresh.'),503

    @app.errorhandler(psycopg.Error)
    def database_error(exc):
        if exc.sqlstate=='57014':
            return jsonify(error='The query exceeded 5 seconds. Add a filter or simplify the joins.'),408
        return jsonify(error=exc.diag.message_primary or 'PostgreSQL could not run this query.',sqlstate=exc.sqlstate),400

    @app.errorhandler(psycopg.errors.QueryCanceled)
    def timed_out(exc):
        return jsonify(error='The query exceeded 5 seconds. Add a filter or simplify the joins.'),408

    @app.errorhandler(413)
    def too_large(exc):
        return jsonify(error='This query is too large. Keep it under 20,000 characters.'),413

    return app


def serve(port=8765):
    from waitress import serve as waitress_serve
    prepare_workspace()
    app=create_app()
    print(f'CyberShield SQL workspace: http://127.0.0.1:{port}',flush=True)
    waitress_serve(app,host='127.0.0.1',port=port,threads=4,max_request_body_size=32_000,
                   channel_timeout=15)

