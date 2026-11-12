from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import precision_recall_curve

from .db import ROOT
from .evaluate import frame


def export_analyses(conn, feature_id, experiment_id, source_ids, out):
    folder=out/'analytics'; folder.mkdir(exist_ok=True)
    for query in sorted((ROOT/'sql/analytics').glob('*.sql')):
        result=frame(conn,query.read_text(encoding='utf-8'),
                     {'feature_run_id':feature_id,'experiment_id':experiment_id,'source_ids':source_ids})
        result.to_csv(folder/f'{query.stem}.csv',index=False)
    queue=frame(conn,'''SELECT * FROM v_triage_queue WHERE experiment_id=%s
        ORDER BY rank LIMIT 200''',(experiment_id,))
    queue.to_csv(out/'triage_queue.csv',index=False)
    evidence=frame(conn,'''SELECT q.rank,host(q.src_ip) AS src_ip,q.window_start,e.flow_id,e.source_id,e.row_number
        FROM v_triage_queue q CROSS JOIN LATERAL (
            SELECT flow_id,source_id,row_number FROM flow f
            WHERE f.src_ip=q.src_ip AND f.clock_usable AND f.source_id=ANY(%s)
              AND f.reported_end>=q.window_start AND f.reported_end<q.window_start+interval '5 minutes'
            ORDER BY f.flow_id LIMIT 5) e
        WHERE q.experiment_id=%s AND q.rank<=30 ORDER BY q.rank,e.flow_id''',(source_ids,experiment_id))
    evidence.to_csv(out/'triage_evidence.csv',index=False)
    return queue


def figures(data, metrics_frame, out, synthetic):
    folder=out/'figures';folder.mkdir(exist_ok=True)
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,
                         'axes.spines.right':False,'figure.facecolor':'#f8fafc','axes.facecolor':'white'})
    prefix='SYNTHETIC FIXTURE' if synthetic else 'CIC-IDS2017 Tuesday | morning-clock subset'
    traffic=pd.read_csv(out/'analytics/01_activity.csv',parse_dates=['window_start'])
    fig,axes=plt.subplots(2,1,figsize=(10,6),sharex=True,layout='constrained')
    axes[0].plot(traffic.window_start,traffic.flows,color='#2563eb');axes[0].set_ylabel('Flows / 5 min')
    axes[1].plot(traffic.window_start,traffic.attack_flows,color='#dc2626');axes[1].set_ylabel('Labeled attack flows')
    axes[1].set_xlabel('Reported capture clock (timezone unknown)')
    fig.suptitle(f'{prefix}\nRetrospective observed activity; excluded clocks are not zeros',fontsize=12)
    fig.savefig(folder/'01_activity.png',dpi=150);plt.close(fig)

    rows=metrics_frame[(metrics_frame.split=='development') & metrics_frame.method.isin(
        ['sql_combined','logistic_regression','flow_count_baseline','random_baseline'])]
    labels=rows.method.str.replace('_',' ').to_list()
    fig,axes=plt.subplots(1,2,figsize=(10,4.5),layout='constrained')
    axes[0].barh(labels,rows.recall.fillna(0),color='#2563eb');axes[0].set_xlim(0,1);axes[0].set_xlabel('Attack-window recall')
    axes[1].barh(labels,rows.false_positives_per_1000.fillna(0),color='#d97706');axes[1].set_xlabel('False alerts / 1,000 benign windows')
    axes[1].axvline(10,color='#64748b',linestyle='--',label='Calibration target');axes[1].legend(fontsize=8)
    for ax in axes:ax.grid(axis='x',alpha=.15)
    fig.suptitle(f'{prefix}\nDevelopment check at frozen benign-calibrated cutoffs',fontsize=11)
    fig.savefig(folder/'02_comparison.png',dpi=150);plt.close(fig)

    mask=(data.split=='development')&(data.unknown_flows==0)
    y=data.loc[mask,'attack_flows'].gt(0)
    fig,ax=plt.subplots(figsize=(7,5),layout='constrained')
    if y.any():
        for method,color in [('sql_combined','#2563eb'),('logistic_regression','#0f766e'),('flow_count_baseline','#d97706')]:
            precision,recall,_=precision_recall_curve(y,data.loc[mask,method])
            ax.step(recall,precision,where='post',label=method.replace('_',' '),color=color)
        ax.axhline(float(y.mean()),color='#64748b',linestyle='--',label='Prevalence')
        ax.legend(fontsize=9)
    else:
        ax.text(.5,.5,'No positive windows: PR curve undefined',ha='center')
    ax.set(xlabel='Recall',ylabel='Precision',xlim=(0,1),ylim=(0,1.03),
           title=f'{prefix}\nDevelopment score rankings; correlated windows')
    fig.savefig(folder/'03_precision_recall.png',dpi=150);plt.close(fig)


def findings(out: Path,audit,summary,metrics_frame,synthetic):
    subset=metrics_frame[metrics_frame.split=='development']
    lines=['# CyberShield Analytics — Prototype Findings','',
        '**SYNTHETIC FIXTURE**' if synthetic else '**REAL DATA: original CIC-IDS2017 Tuesday file**','',
        '**Development-only evaluation. No Friday data scored; no final benchmark claims.**','',
        '## Data reconciliation','',
        f"- Input rows: {audit['input_rows']:,}; accepted: {audit['accepted_rows']:,}; quarantined: {audit['rejected_rows']:,}.",
        f"- Morning-clock records eligible for temporal features: {audit['clock_usable_rows']:,}.",
        f"- Repeated-content rows flagged and retained: {audit['content_duplicate_rows']:,}.",
        f"- Benign calibration windows: {summary['benign_calibration_windows']:,}; target: 10 false alerts per 1,000.",
        '', '## Development comparison','',
        '| Method | Caught / attack windows | False alerts / benign windows | Precision |',
        '|---|---:|---:|---:|']
    for row in subset.itertuples():
        precision='undefined' if pd.isna(row.precision) else f'{row.precision:.3f}'
        lines.append(f'| {row.method} | {row.tp} / {row.positives} | {row.fp} / {row.negatives} | {precision} |')
    lines.extend(['','## Interpretation and limits','',
        '- All predictors, rolling summaries, and native rule scores are generated in PostgreSQL.',
        '- The full selected file is ingested. Temporal analyses exclude reported hours 1–7 and 12, and flows ending at noon or later; raw values remain in the database.',
        '- No AM/PM repair is applied. Clock values 8–11 are treated as morning based on the documented daytime capture; timezone remains unknown and timestamp precision is one minute.',
        '- Completion time is a coarse proxy (minute-rounded start plus duration), not a measured arrival timestamp. Boundary membership can be uncertain.',
        '- Adjacent development intervals can share one attack episode and source identity. Exact window counts do not represent independent attacks.',
        '- Thresholds use benign calibration traffic only. The observed development false-alert rate can exceed the calibration target.',
        f"- Calibration has {summary['benign_calibration_windows']:,} benign windows. The final-study support gate also requires independent attack support, which this single-day prototype does not establish.",
        '- Historical averages cover observed ACTIVE windows, excluding current and future windows; missing windows are not fabricated zeros. The ML baseline excludes history and raw identity.',
        '- Sparse support prevents reliable uncertainty intervals. No generalization or real-time effectiveness claim is made.',
        '', '## Outputs','',
        '- `triage_queue.csv` ranks windows without exposing ground-truth labels; `triage_evidence.csv` links sample supporting flows.',
        '- `analytics/` contains eight inspectable query outputs; `metrics.csv` and `window_scores.csv` provide reproducible evaluation evidence.',
        '- `development_protocol.json` records cutoffs/configuration; `artifact_manifest.json` records model, code, SQL, and library hashes.',
        '- `figures/` contains activity, operating-point comparison, and precision-recall figures.'])
    (out/'findings.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    claims=[{'claim':'accepted_flows','value':audit['accepted_rows'],'numerator':audit['accepted_rows'],
             'denominator':audit['input_rows'],'population':'selected source file','source_artifact':'data_quality.json'},
            {'claim':'quarantined_flows','value':audit['rejected_rows'],'numerator':audit['rejected_rows'],
             'denominator':audit['input_rows'],'population':'selected source file','source_artifact':'data_quality.json'}]
    for row in subset.itertuples():
        claims.extend([{'claim':f'{row.method}_development_recall','value':row.recall,'numerator':row.tp,
                        'denominator':row.positives,'population':'known-label development windows','source_artifact':'metrics.csv'},
                       {'claim':f'{row.method}_development_false_positives','value':row.fp,'numerator':row.fp,
                        'denominator':row.negatives,'population':'benign development windows','source_artifact':'metrics.csv'}])
    for claim in claims:
        claim.update({'experiment_id':summary['experiment_id'],'status':'development_only','synthetic':synthetic})
    pd.DataFrame(claims).to_csv(out/'claim_evidence.csv',index=False)

