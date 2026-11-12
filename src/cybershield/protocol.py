"""Versioned development protocol validation, role allocation and support gates."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .evaluate import FEATURES

MODELS = ['Logistic regression','Linear SVM','Random forest','Extra trees',
          'Histogram boosting','XGBoost','LightGBM','CatBoost']
ROLES = ['train','calibration','validation']


def utc(value):
    value = pd.Timestamp(value)
    if value.tzinfo is None:
        raise ValueError('Protocol boundaries require explicit UTC timezone')
    return value.tz_convert('UTC').tz_localize(None)


def validate_protocol(config):
    if config.get('status') != 'development_validation_only' or config.get('final_test_enabled') is not False:
        raise ValueError('This workflow cannot authorize final-test scoring')
    fixed={'features':FEATURES,'window_minutes':5,
        'source_release':'CIC-IDS2017-CNS2022-corrected','window_origin':'2000-01-01 00:00:00',
        'boundary_policy':'entire_window_and_all_constituent_flow_starts_inside_role',
        'episode_policy':'utc_day_source_attack_family; attempted labels linked to base family; no arbitrary gap segmentation',
        'dependency_block':'utc_day_source; shared actors across days remain a limitation',
        'models':MODELS,'controls':['sql_combined','always_benign'],
        'attempted_policy':'unknown_exclude_entire_window',
        'timestamp_policy':'corrected_explicit_utc_microseconds_no_repair','duration_unit':'microseconds',
        'false_positive_target':.01,
        'timing':{'fit_repeats':3,'warmup_calls':5,'single_repeats':60,'batch_repeats':25,
                  'batch_sizes':[1,32,256],'include_full_validation_batch':True,'threads':1}}
    unsupported=[key for key,value in fixed.items() if config.get(key)!=value]
    if unsupported:
        raise ValueError(f'Unsupported protocol settings: {", ".join(unsupported)}')
    targets = [config['false_positive_target'],*config.get('sensitivity_targets',[])]
    if len(set(targets)) != len(targets) or any(not 0 <= v < 1 for v in targets):
        raise ValueError('Invalid/duplicate registered alert budgets')
    if set(config['roles']) != set(ROLES):
        raise ValueError('Exactly train, calibration and validation roles are supported')
    previous = None
    for role in ROLES:
        start,end = map(utc,config['roles'][role])
        if not start < end:
            raise ValueError('Role interval must be increasing')
        if previous is not None and start-previous < pd.Timedelta(minutes=config['embargo_minutes']):
            raise ValueError('Roles overlap or violate temporal embargo')
        if start.second or end.second or start.minute%5 or end.minute%5:
            raise ValueError('Role boundaries must align with five-minute bins')
        previous=end
    if config['embargo_minutes'] < 65:
        raise ValueError('This protocol requires a 65-minute embargo')
    members=config['members']
    if not members or len(set(members)) != len(members) or set(members)&set(config['excluded_members']):
        raise ValueError('Source members overlap or are duplicated')
    if 'friday.csv' in members:
        raise ValueError('Friday is excluded from this registered development design')
    if config.get('mlp',{}).get('enabled'):
        raise ValueError('MLP is deferred pending independent-support review')
    if not 0 < config['rule_reference_quantile'] < 1:
        raise ValueError('Invalid training rule reference quantile')
    if not config.get('prior_access'):
        raise ValueError('Prior-access disclosure is required')
    minimums={'train_positive_episode_groups':2,'validation_positive_episode_groups':2,
        'validation_positive_days':2,'validation_positive_dependency_blocks':2,'benign_calibration_windows':100}
    if set(config.get('support_gates') or {})!=set(minimums) or any(
        not isinstance(config['support_gates'][name],int) or config['support_gates'][name]<minimum
        for name,minimum in minimums.items()):
        raise ValueError('Support gates cannot be weaker than the implemented development screen')
    return config


def episode_key(day, source, family):
    """No arbitrary sub-campaign gap splitting. Readable stable annotation identity."""
    return json.dumps([str(day),str(source),str(family)],separators=(',',':'))


def family(label):
    return str(label).split(' - Attempted')[0]


def allocate(data, config):
    validate_protocol(config)
    data=data.copy().reset_index(drop=True)
    if data.empty or data.duplicated(['src_ip','window_start']).any():
        raise ValueError('Missing data or duplicate source-window identities')
    for name in ['window_start','min_flow_start','max_flow_end']:
        data[name]=pd.to_datetime(data[name],utc=True,format='mixed').dt.tz_localize(None)
        if data[name].isna().any():
            raise ValueError('Missing source/window time')
    if not data.window_start.eq(data.window_start.dt.floor('5min')).all():
        raise ValueError('Scoring windows do not match fixed SQL bin boundaries')
    if not data.episode_labels.map(lambda values:isinstance(values,(list,tuple)) and all(isinstance(x,str) for x in values)).all():
        raise ValueError('Episode annotation lists must be explicit strings')
    if ((data.min_flow_start>data.max_flow_end)|(data.max_flow_end<data.window_start)|
        (data.max_flow_end>=data.window_start+pd.Timedelta(minutes=5))).any():
        raise ValueError('Flow and completion-window memberships do not reconcile')
    data['role']='unscored'
    data['role_reason']='outside_roles_or_embargo'
    for role in ROLES:
        start,end=map(utc,config['roles'][role])
        nominal=data.window_start.ge(start)&data.window_start.lt(end)
        whole=nominal & (data.window_start+pd.Timedelta(minutes=5)).le(end) & data.min_flow_start.ge(start)
        data.loc[nominal&~whole,'role_reason']='flow_or_window_crosses_role_boundary'
        data.loc[whole,'role']=role
        data.loc[whole,'role_reason']='assigned'
    counts=data[['attack_flows','unknown_flows','flow_count']]
    if counts.isna().any().any() or (counts%1).ne(0).any().any() or data.flow_count.le(0).any() or \
       (counts<0).any().any() or \
       (data.attack_flows+data.unknown_flows>data.flow_count).any():
        raise ValueError('Invalid flow/target reconciliation')
    data['known']=data.unknown_flows.eq(0)
    data['is_attack']=data.attack_flows.gt(0)
    data['day']=data.window_start.dt.date.astype(str)
    data['dependency_block']=[episode_key(d,s,'all_families') for d,s in zip(data.day,data.src_ip)]
    data['episode_groups']=[sorted({episode_key(d,s,family(label)) for label in labels if label!='BENIGN'})
                            for d,s,labels in zip(data.day,data.src_ip,data.episode_labels)]
    return data


def episode_overlap(data):
    assigned=data.loc[data.role.isin(ROLES),['role','episode_groups']].explode('episode_groups').dropna()
    return assigned.groupby('episode_groups').role.agg(lambda values:sorted(set(values))).loc[lambda s:s.map(len)>1]


def support(data, config):
    rows=[]
    for role in [*ROLES,'unscored']:
        part=data.loc[data.role.eq(role)]
        known=part.loc[part.known]
        positive=known.loc[known.is_attack]
        groups={g for values in positive.episode_groups for g in values}
        rows.append({'role':role,'all_active_windows':len(part),'known_label_windows':len(known),
                     'unknown_excluded_windows':int((~part.known).sum()),'positive_windows':len(positive),
                     'benign_windows':int((~known.is_attack).sum()),'positive_episode_proxy_groups':len(groups),
                     'positive_days':int(positive.day.nunique()),
                     'positive_dependency_blocks':int(positive.dependency_block.nunique()),
                     'positive_sources':int(positive.src_ip.nunique())})
    table=pd.DataFrame(rows).set_index('role')
    checks={
        'train_positive_episode_groups':int(table.loc['train','positive_episode_proxy_groups']),
        'validation_positive_episode_groups':int(table.loc['validation','positive_episode_proxy_groups']),
        'validation_positive_days':int(table.loc['validation','positive_days']),
        'validation_positive_dependency_blocks':int(table.loc['validation','positive_dependency_blocks']),
        'benign_calibration_windows':int(table.loc['calibration','benign_windows'])}
    reasons=[f'{name}: observed {checks[name]}, requires {minimum}'
             for name,minimum in config['support_gates'].items() if checks[name]<minimum]
    if table.loc['train','positive_windows']==0 or table.loc['train','benign_windows']==0:
        reasons.append('Training requires both known classes')
    overlap=episode_overlap(data)
    if len(overlap):
        reasons.append(f'{len(overlap)} episode groups cross prohibited roles')
    train_sources=set(data.loc[data.role.eq('train'),'src_ip'])
    validation_sources=set(data.loc[data.role.eq('validation'),'src_ip'])
    purged=data.loc[data.role.eq('unscored')].explode('episode_groups').dropna(subset=['episode_groups'])
    assigned_groups={g for values in data.loc[data.role.isin(ROLES),'episode_groups'] for g in values}
    return table.reset_index(), {'passed':not reasons,'reasons':reasons,'observed':checks,
        'episode_overlap':overlap.to_dict(),
        'groups_with_unscored_fragments':len(set(purged.episode_groups)&assigned_groups),
        'train_validation_overlapping_sources':len(train_sources&validation_sources),
        'independence':'Episode groups and source/day blocks are proxies; independence is not established.',
        'uncertainty':'No confidence intervals; report raw counts and correlation caveats.',
        'mlp':'deferred; support gates do not authorize neural training',
        'final_test':'unsupported; development/validation only'}


def write_support(data, config, output):
    output=Path(output); output.mkdir(parents=True,exist_ok=True)
    table,gate=support(data,config)
    table.to_csv(output/'role_support.csv',index=False)
    (output/'support_gate.json').write_text(json.dumps(gate,indent=2),encoding='utf-8')
    for column in ['day','src_ip','dependency_block']:
        rows=data.groupby(['role',column],dropna=False).apply(lambda p:pd.Series({
            'all_windows':len(p),'known_windows':int(p.known.sum()),
            'positive_windows':int((p.known&p.is_attack).sum()),
            'unknown_excluded_windows':int((~p.known).sum())}),include_groups=False).reset_index()
        rows.to_csv(output/f'support_by_{column}.csv',index=False)
    links=data.explode('episode_groups').dropna(subset=['episode_groups']).reset_index(drop=True)
    if not links.empty:
        links['family']=links.episode_groups.map(lambda key:json.loads(key)[2])
        links['known_positive']=links.known & links.is_attack
        links.groupby(['role','episode_groups','family'],dropna=False).agg(
            windows=('src_ip','size'),positive_known_windows=('known_positive','sum')
        ).to_csv(output/'episode_support.csv')
    return gate
