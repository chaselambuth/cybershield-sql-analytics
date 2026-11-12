"""Generate the editable PBIP/TMDL/PBIR report from one verified local bundle."""
import argparse
import json
import uuid
from pathlib import Path

from cybershield.db import ROOT
from cybershield.powerbi import load_json, verify_bundle

SCHEMA_ROOT='https://developer.microsoft.com/json-schemas/fabric/item/report/definition/'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bundle',required=True,type=Path)
args=parser.parse_args()
bundle=args.bundle.resolve(); manifest=verify_bundle(bundle); schema=load_json(bundle/'schema.json')
OUT=ROOT/'power_bi'; model=OUT/'CyberShield.SemanticModel'; report=OUT/'CyberShield.Report'


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False) if not isinstance(value,str) else value,encoding='utf-8')


def stable(name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL,'cybershield:'+name))


def quoted(value):
    return "'"+value.replace("'","''")+"'"


write(OUT/'CyberShield.pbip',{'version':'1.0','artifacts':[{'report':{'path':'CyberShield.Report'}}],
                             'settings':{'enableAutoRecovery':True}})
write(model/'definition.pbism',{'version':'4.0','settings':{'qnaEnabled':False}})
write(model/'definition/database.tmdl','database\n\tcompatibilityLevel: 1601\n')
model_text='''model Model
\tculture: en-US
\tdefaultPowerBIDataSourceVersion: powerBI_V3
\tdiscourageImplicitMeasures
\tsourceQueryCulture: en-US

\tdataAccessOptions
\t\tlegacyRedirects
\t\treturnErrorValuesAsNull

annotation __PBI_TimeIntelligenceEnabled = 0
annotation PBI_ProTooling = ["DevMode"]
'''
model_text+='\n'.join('ref table '+quoted(name) for name in schema)+'\n'
write(model/'definition/model.tmdl',model_text)
expressions=f'''expression BundleRoot = "{bundle.as_posix()}" meta [IsParameterQuery=true, Type="Text", IsParameterQueryRequired=true]
\tannotation PBI_ResultType = Text

expression ExpectedPayloadId = "{manifest['payload_id']}"
\tannotation PBI_ResultType = Text

expression BundleDocument =
\t\tlet
\t\t    Raw = Json.Document(Binary.Buffer(File.Contents(BundleRoot & "/report_data.json"))),
\t\t    Checked = if Raw[schema_version] = 1 and Raw[payload_id] = ExpectedPayloadId and Raw[validation][status] = "passed" then Raw
\t\t        else error "Packed bundle identity, schema, or validation status differs. Regenerate for a new bundle."
\t\tin Checked

expression LoadBundleTable =
\t\t(name as text) as table =>
\t\tlet
\t\t    Document = BundleDocument,
\t\t    Spec = Record.Field(Document[schema], name),
\t\t    Packed = Record.Field(Document[tables], name),
\t\t    Names = List.Transform(Spec[columns], each _[name]),
\t\t    Source = if Packed[columns] = Names then Table.FromRows(Packed[rows], Names) else error "Packed columns differ",
\t\t    TypeMap = [text=type text, int64=Int64.Type, double=type number, boolean=type logical, datetime=type datetime],
\t\t    Types = List.Transform(Spec[columns], each {{_[name], Record.Field(TypeMap, _[type])}}),
\t\t    Typed = Table.Buffer(Table.TransformColumnTypes(Source, Types, "en-US")),
\t\t    CountChecked = if Table.RowCount(Typed) = Spec[rows] then Typed else error "Packed row count differs",
\t\t    Keys = if name = "Window" then {{"window_key"}} else if name = "SupportingFlows" then {{"flow_id"}}
\t\t        else if name = "FactPrototypeDecision" then {{"window_key", "detector_id"}} else {{}},
\t\t    Checked = if List.IsEmpty(Keys) or Table.RowCount(Table.Distinct(Table.SelectColumns(CountChecked, Keys))) = Spec[rows]
\t\t        then CountChecked else error "Duplicate packed key"
\t\tin Checked
'''
write(model/'definition/expressions.tmdl',expressions)
measures={
 'Window':{
  'Observed flows':("SUM('Window'[flow_count])",'#,0'),
  'Observed windows':("COUNTROWS('Window')",'#,0'),
  'Active sources':("DISTINCTCOUNT('Window'[src_ip])",'#,0'),
  'Alerts':("IF(HASONEVALUE('DimDetector'[detector_id]), CALCULATE(COUNTROWS('FactPrototypeDecision'), 'FactPrototypeDecision'[predicted_attack] = TRUE()), BLANK())",'#,0'),
  'False alerts':("CALCULATE([Alerts], 'Window'[is_attack] = FALSE(), 'Window'[unknown_flows] = 0)",'#,0'),
  'Role context':("SELECTEDVALUE('Window'[role_context], \"Multiple roles; retrospective decisions\")",None)},
 'FactEvaluation':{
  'Caught positives':("IF(HASONEVALUE('DimDetector'[detector_id]), SUM('FactEvaluation'[tp]), BLANK())",'0'),
  'False positive windows':("IF(HASONEVALUE('DimDetector'[detector_id]), SUM('FactEvaluation'[fp]), BLANK())",'#,0'),
  'Recall rate':("IF(HASONEVALUE('DimDetector'[detector_id]), DIVIDE(SUM('FactEvaluation'[tp]), SUM('FactEvaluation'[tp]) + SUM('FactEvaluation'[fn])), BLANK())",'0.0%'),
  'Precision rate':("IF(HASONEVALUE('DimDetector'[detector_id]), DIVIDE(SUM('FactEvaluation'[tp]), SUM('FactEvaluation'[tp]) + SUM('FactEvaluation'[fp])), BLANK())",'0.0%'),
  'F1 score':("IF(HASONEVALUE('DimDetector'[detector_id]), DIVIDE(2 * SUM('FactEvaluation'[tp]), 2 * SUM('FactEvaluation'[tp]) + SUM('FactEvaluation'[fp]) + SUM('FactEvaluation'[fn])), BLANK())",'0.000'),
  'False alerts per 1000':("IF(HASONEVALUE('DimDetector'[detector_id]), DIVIDE(1000 * SUM('FactEvaluation'[fp]), SUM('FactEvaluation'[fp]) + SUM('FactEvaluation'[tn])), BLANK())",'0.00'),
  'Caught of total':("IF(HASONEVALUE('DimDetector'[detector_id]), FORMAT(SUM('FactEvaluation'[tp]), \"0\") & \" of \" & FORMAT(SUM('FactEvaluation'[positives]), \"0\"), \"Select one detector\")",None),
  'Average precision':("IF(HASONEVALUE('DimDetector'[detector_id]), SELECTEDVALUE('FactEvaluation'[average_precision]), BLANK())",'0.000'),
  'Fit median ms':("IF(HASONEVALUE('DimDetector'[detector_id]), SELECTEDVALUE('FactEvaluation'[fit_median_ms]), BLANK())",'0.00'),
  'Model bytes':("IF(HASONEVALUE('DimDetector'[detector_id]), SELECTEDVALUE('FactEvaluation'[serialized_bytes]), BLANK())",'#,0')},
 'FactLatency':{
  'Median call ms':("IF(HASONEVALUE('DimDetector'[detector_id]), SELECTEDVALUE('FactLatency'[median_ms]), BLANK())",'0.000'),
  'P95 call ms':("IF(HASONEVALUE('DimDetector'[detector_id]), SELECTEDVALUE('FactLatency'[p95_ms]), BLANK())",'0.000'),
  'Measured calls':("IF(HASONEVALUE('DimDetector'[detector_id]), SELECTEDVALUE('FactLatency'[calls]), BLANK())",'0'),
  'Rows per second':("IF(HASONEVALUE('DimDetector'[detector_id]), SELECTEDVALUE('FactLatency'[rows_per_second]), BLANK())",'#,0'),
  'Amortized us per row':("IF(HASONEVALUE('DimDetector'[detector_id]), SELECTEDVALUE('FactLatency'[amortized_us_per_row]), BLANK())",'0.00')},
 'FactSourceAudit':{
  'Audit value':("IF(HASONEVALUE('FactSourceAudit'[metric]) && HASONEVALUE('FactSourceAudit'[time_scope]) && HASONEVALUE('FactSourceAudit'[label_policy]) && HASONEVALUE('DimDataset'[dataset_id]), SELECTEDVALUE('FactSourceAudit'[value]), BLANK())",'#,0'),
  'Original accepted':("CALCULATE(MAX('FactSourceAudit'[value]), REMOVEFILTERS('DimDataset'), 'DimDataset'[dataset_id] = \"original\", 'FactSourceAudit'[metric] = \"accepted_rows\")",'#,0'),
  'Original quarantined':("CALCULATE(MAX('FactSourceAudit'[value]), REMOVEFILTERS('DimDataset'), 'DimDataset'[dataset_id] = \"original\", 'FactSourceAudit'[metric] = \"rejected_rows\")",'#,0'),
  'Original eligible':("CALCULATE(MAX('FactSourceAudit'[value]), REMOVEFILTERS('DimDataset'), 'DimDataset'[dataset_id] = \"original\", 'FactSourceAudit'[metric] = \"temporal_eligible_rows\")",'#,0')},
 'RunContext':{
  'Evidence banner':('"Original CIC-IDS2017 | unrepaired morning clock | development: 6 positive / 3,407 benign | one correlated campaign"',None)}}
types={'text':'string','int64':'int64','double':'double','boolean':'boolean','datetime':'dateTime'}
for name,spec in schema.items():
    lines=['table '+quoted(name),'\tlineageTag: '+stable('table:'+name),'']
    for label,(dax,fmt) in measures.get(name,{}).items():
        lines+=['\tmeasure '+quoted(label)+' = '+dax]
        if fmt:lines+=['\t\tformatString: '+fmt]
        lines+=['\t\tlineageTag: '+stable(name+':measure:'+label),'']
    for column in spec['columns']:
        col=column['name'];typ=column['type']
        lines+=['\tcolumn '+quoted(col),'\t\tdataType: '+types[typ],
                '\t\tlineageTag: '+stable(name+':column:'+col),'\t\tsummarizeBy: none',
                '\t\tsourceColumn: '+col]
        if col.endswith('_key') or col in ['detector_id','dataset_id']:
            lines+=['\t\tisHidden']
        if typ=='datetime':lines+=['\t\tformatString: yyyy-MM-dd HH:mm']
        elif typ=='double' and ('share' in col or col in ['precision','recall']):lines+=['\t\tformatString: 0.0%']
        lines+=['']
    lines+=['\tpartition '+quoted(name)+' = m','\t\tmode: import','\t\tsource = LoadBundleTable("'+name+'")',
            '', '\tannotation PBI_ResultType = Table','']
    write(model/'definition/tables'/f'{name}.tmdl','\n'.join(lines))
relationships=[]
for child,parent,key in [('FactPrototypeDecision','Window','window_key'),('SupportingFlows','Window','window_key'),
    ('FactPrototypeDecision','DimDetector','detector_id'),('FactEvaluation','DimDetector','detector_id'),
    ('FactLatency','DimDetector','detector_id'),('FactSourceAudit','DimDataset','dataset_id')]:
    relationships += ['relationship '+stable(child+parent+key),
                      '\tfromColumn: '+quoted(child)+'.'+quoted(key),
                      '\ttoColumn: '+quoted(parent)+'.'+quoted(key), '']
write(model/'definition/relationships.tmdl','\n'.join(relationships))
write(report/'definition.pbir',{'version':'4.0','datasetReference':{'byPath':{'path':'../CyberShield.SemanticModel'}}})
write(report/'definition/version.json',{'$schema':SCHEMA_ROOT+'versionMetadata/1.0.0/schema.json','version':'2.0.0'})
theme={'name':'CyberShield','dataColors':['#147D92','#D56B45','#496591','#7F8C9D','#6E9C81'],
       'background':'#F5F7FA','foreground':'#182A3A','tableAccent':'#147D92',
       'textClasses':{'title':{'fontFace':'Segoe UI Semibold','fontSize':13},
                      'label':{'fontFace':'Segoe UI','fontSize':11}},
       'visualStyles':{'tableEx':{'*':{'columnHeaders':[{'fontSize':12,'wordWrap':True}],
           'values':[{'fontSize':11,'wordWrap':True}],'grid':[{'rowPadding':5}],
           'total':[{'totals':False}]}},
           'slicer':{'*':{'items':[{'textSize':11}]}}}}
write(report/'StaticResources/RegisteredResources/CyberShield.json',theme)
theme_version={'visual':'2.3.0','page':'2.0.0','report':'3.0.0'}
write(report/'definition/report.json',{'$schema':SCHEMA_ROOT+'report/3.0.0/schema.json',
    'themeCollection':{'customTheme':{'name':'CyberShield','reportVersionAtImport':theme_version,'type':'RegisteredResources'}},
    'resourcePackages':[{'name':'RegisteredResources','type':'RegisteredResources',
                         'items':[{'name':'CyberShield','path':'CyberShield.json','type':'CustomTheme'}]}],
    'settings':{'useStylableVisualContainerHeader':True,'exportDataMode':'AllowSummarized','defaultDrillFilterOtherVisuals':True}})


def literal(value):
    if isinstance(value,bool):return {'expr':{'Literal':{'Value':'true' if value else 'false'}}}
    if isinstance(value,(int,float)):return {'expr':{'Literal':{'Value':str(value)+'D'}}}
    return {'expr':{'Literal':{'Value':"'"+str(value).replace("'","''")+"'"}}}


def column(table,name):
    return {'Column':{'Expression':{'SourceRef':{'Entity':table}},'Property':name}}


def measure(table,name):
    return {'Measure':{'Expression':{'SourceRef':{'Entity':table}},'Property':name}}


def projection(table,name,is_measure=False):
    labels={'display_name':'Detector','dataset_name':'Dataset','metric_label':'Audit metric','value':'Value',
            'unit':'Unit','status':'Evidence','time_scope':'Time scope','label_policy':'Label policy',
            'src_ip':'Source','dst_ip':'Destination','window_start':'Reported completion window',
            'flow_count':'Flows','service_flows':'Service flows','attack_flows':'Attack-labeled flows',
            'flow_id':'Record ID','dst_port':'Destination port','raw_timestamp':'Raw timestamp',
            'retrospective_label':'Original label','distinct_scores':'Distinct scores',
            'largest_tie_share':'Largest tied share','caveat':'Evidence caveat','window_key':'Window key',
            'source_file_id':'Source file','source_flow_id':'CIC flow identifier','reported_end':'Reported completion',
            'packets':'Packets','bytes':'Bytes','src_port':'Source port'}
    return {'field':measure(table,name) if is_measure else column(table,name),
            'queryRef':table+'.'+name,'nativeQueryRef':name,'displayName':labels.get(name,name)}


def categorical_filter(table,col,values,name=None):
    expressions=[{'Column':{'Expression':{'SourceRef':{'Source':'t'}},'Property':col}}]
    def val(v):
        if isinstance(v,bool):return 'true' if v else 'false'
        if isinstance(v,int):return str(v)+'L'
        return "'"+str(v).replace("'","''")+"'"
    return {'name':name or table+'_'+col,'field':column(table,col),'type':'Categorical',
            'filter':{'Version':2,'From':[{'Name':'t','Entity':table,'Type':0}],
                'Where':[{'Condition':{'In':{'Expressions':expressions,
                    'Values':[[{'Literal':{'Value':val(v)}}] for v in values]}}}]},
            'howCreated':'User','isHiddenInViewMode':False,'isLockedInViewMode':False}


pages=[];visual_index=0


def page(name,label,filters=None,hidden=False):
    folder=report/'definition/pages'/name
    body={'$schema':SCHEMA_ROOT+'page/2.0.0/schema.json','name':name,'displayName':label,
          'displayOption':'FitToWidth','height':950,'width':1440}
    if filters:body['filterConfig']={'filters':filters}
    if hidden:body['visibility']='HiddenInViewMode'
    write(folder/'page.json',body);pages.append(name)
    return folder


def visual(folder,kind,title,position,roles=None,objects=None,filters=None):
    global visual_index
    visual_index+=1;name='v'+str(visual_index).zfill(4)
    config={'visualType':kind,'drillFilterOtherVisuals':True,
      'visualContainerObjects':{'title':[{'properties':{'show':literal(kind!='textbox'),'text':literal(title),
          'fontSize':literal(12),'fontColor':{'solid':{'color':literal('#182A3A')}}}}],
         'background':[{'properties':{'show':literal(True),'color':{'solid':{'color':literal('#FFFFFF')}},'transparency':literal(0)}}]}}
    if roles:config['query']={'queryState':{role:{'projections':items} for role,items in roles.items()}}
    if objects:config['objects']=objects
    x,y,w,h=position
    body={'$schema':SCHEMA_ROOT+'visualContainer/2.3.0/schema.json','name':name,
          'position':{'x':x,'y':y,'z':visual_index,'height':h,'width':w,'tabOrder':visual_index},'visual':config}
    if filters:body['filterConfig']={'filters':filters}
    write(folder/'visuals'/name/'visual.json',body)


def text(folder,heading,content,y=12,height=74):
    visual(folder,'textbox',heading,(24,y,1392,height),objects={
        'general':[{'properties':{'paragraphs':[{'textRuns':[{'value':heading,'textStyle':{'fontFamily':'Segoe UI Semibold','fontSize':'18pt','color':'#147D92'}}]}, {'textRuns':[{'value':content,'textStyle':{'fontFamily':'Segoe UI','fontSize':'11pt','color':'#182A3A'}}]}]}}]})


def table(folder,title,fields,pos):
    widths={'dataset_name':180,'metric_label':190,'value':95,'unit':75,'status':130,'time_scope':260,
            'label_policy':300,'display_name':180,'caveat':700,'distinct_scores':120,'largest_tie_share':140,
            'window_key':180,'src_ip':145,'window_start':200}
    column_widths=[{'selector':{'metadata':f[0]+'.'+f[1]},'properties':{'value':literal(widths[f[1]])}}
                   for f in fields if f[1] in widths]
    visual(folder,'tableEx',title,pos,{'Values':[projection(*field) for field in fields]},
           objects={'columnWidth':column_widths,'total':[{'properties':{'totals':literal(False)}}]})


def card(folder,title,source,pos):
    visual(folder,'card',title,pos,{'Values':[projection(*source,True)]},
           objects={'labels':[{'properties':{'labelDisplayUnits':literal(0),'fontSize':literal(25)}}],
                    'categoryLabels':[{'properties':{'show':literal(False)}}]})


def slicer(folder,title,source,pos):
    visual(folder,'slicer',title,pos,{'Values':[projection(*source)]})


p=page('01_quality','01 · Data quality')
text(p,'DATA QUALITY / SOURCE FITNESS','CYBERSHIELD  |  Original source is active. Corrected Tuesday is a candidate; UNSW data is uninspected. Scope and policy differ across rows.')
for i,(label,m) in enumerate([('Accepted original flows','Original accepted'),('Quarantined original flows','Original quarantined'),('Morning-eligible original flows','Original eligible')]):
    card(p,label,('FactSourceAudit',m),(24+i*360,104,340,110))
slicer(p,'Audit candidate',('DimDataset','dataset_name'),(1110,104,306,160))
table(p,'Source audit · units and scopes are explicit',[
    ('DimDataset','dataset_name'),('FactSourceAudit','metric_label'),('FactSourceAudit','value'),
    ('FactSourceAudit','unit'),('FactSourceAudit','status'),('FactSourceAudit','time_scope'),('FactSourceAudit','label_policy')],(24,280,1392,470))
text(p,'SOURCE DECISION','Next adapter: corrected CIC-IDS2017. Resolve attempted labels and episode-separated evaluation first. Original: morning-only temporal scope; corrected: full Tuesday. Null is unknown / not applicable, never zero.',780,110)

p=page('02_investigations','02 · Security investigations',[
    categorical_filter('Window','split',['development'],'Role'),
    categorical_filter('DimDetector','detector_id',['sql'],'Detector')])
text(p,'SECURITY INVESTIGATIONS / RETROSPECTIVE','CYBERSHIELD  |  Defaults: development + combined SQL. Change Role/Detector in the Filters pane. Select a source/window row to inspect supporting records; right-click a window for Flow evidence.')
for i,(title,m) in enumerate([('Observed flows','Observed flows'),('Active windows','Observed windows'),('Detector alerts','Alerts'),('False alerts','False alerts')]):
    card(p,title,('Window',m),(24+i*270,100,250,95))
slicer(p,'Source address',('Window','src_ip'),(1120,100,296,160))
visual(p,'lineChart','Observed flows · reported capture clock',(24,220,650,245),
       {'Category':[projection('Window','window_start')],'Y':[projection('Window','Observed flows',True)]})
visual(p,'clusteredBarChart','Sources dominating retrospective false alerts',(700,220,716,245),
       {'Category':[projection('Window','src_ip')],'Y':[projection('Window','False alerts',True)]})
table(p,'Source windows · click a row; flow counts never multiply by detector',[
    ('Window','src_ip'),('Window','window_start'),('Window','flow_count'),('Window','service_flows'),
    ('Window','attack_flows'),('Window','Alerts',True),('Window','False alerts',True),('Window','window_key')],(24,490,1392,190))
table(p,'Supporting original records · linked by prepared window key',[
    ('SupportingFlows','flow_id'),('SupportingFlows','src_ip'),('SupportingFlows','dst_ip'),
    ('SupportingFlows','dst_port'),('SupportingFlows','raw_timestamp'),('SupportingFlows','retrospective_label')],(24,705,1392,200))

p=page('03_models','03 · Model quality and cost',[
    categorical_filter('DimDetector','default_comparison',[True],'Default comparison'),
    categorical_filter('FactLatency','scope',['pipeline'],'Timing scope'),
    categorical_filter('FactLatency','batch_size',[1],'Batch size')])
text(p,'MODEL QUALITY / COMPUTE COST','ORIGINAL CIC-IDS2017  |  Fixed development cohort: 6 positive / 3,407 benign windows, one correlated campaign. Warm CPU calls; 60 at batch 1, 25 otherwise. No model winner is established.')
visual(p,'clusteredBarChart','False alerts / 3,407 benign windows',(24,105,665,250),
       {'Category':[projection('DimDetector','display_name')],'Y':[projection('FactEvaluation','False positive windows',True)]})
visual(p,'clusteredBarChart','P95 call latency (ms) · pipeline, batch 1 by default',(715,105,701,250),
       {'Category':[projection('DimDetector','display_name')],'Y':[projection('FactLatency','P95 call ms',True)]})
table(p,'Detection support and fixed-cohort quality · precision needs support',[
    ('DimDetector','display_name'),('FactEvaluation','Caught of total',True),('FactEvaluation','False positive windows',True),
    ('FactEvaluation','Recall rate',True),('FactEvaluation','Precision rate',True),('FactEvaluation','Average precision',True),
    ('FactEvaluation','Fit median ms',True),('FactLatency','Measured calls',True)],(24,380,1392,235))
table(p,'Score concentration and evidence caveats · no raw-score comparison',[
    ('DimDetector','display_name'),('DimDetector','distinct_scores'),('DimDetector','largest_tie_share'),
    ('DimDetector','caveat')],(24,640,1392,200))
text(p,'READING THE RESULTS','XGBoost: only 2 distinct scores; 3,409 windows tied. Its calibration-alert field is excluded. SQL has no model-call latency. Filters pane: timing scope / batch size; model quality stays on the full cohort.',855,70)

p=page('04_flow_evidence','Flow evidence',hidden=True)
body=load_json(p/'page.json')
body['pageBinding']={'name':'FlowEvidence','type':'Drillthrough','acceptsFilterContext':'Default',
    'parameters':[{'name':'WindowKey','boundFilter':'FlowWindow','asAggregation':False,
                   'fieldExpr':column('Window','window_key')} ]}
body['filterConfig']={'filters':[{'name':'FlowWindow','field':column('Window','window_key'),
    'type':'Categorical','howCreated':'Drillthrough','isHiddenInViewMode':False,'isLockedInViewMode':False}]}
write(p/'page.json',body)
text(p,'FLOW EVIDENCE / PINNED SOURCE RECORDS','Right-click a source-window row on Security investigations and drill through here. Record key = schema + flow_id; source_file_id identifies the file. Reported completion is an availability proxy.')
table(p,'Selected source window',[
    ('Window','src_ip'),('Window','window_start'),('Window','split'),('Window','flow_count'),('Window','attack_flows')],(24,110,1392,150))
table(p,'Underlying flows',[
    ('SupportingFlows','flow_id'),('SupportingFlows','source_file_id'),('SupportingFlows','source_flow_id'),
    ('SupportingFlows','src_ip'),('SupportingFlows','dst_ip'),('SupportingFlows','src_port'),('SupportingFlows','dst_port'),
    ('SupportingFlows','raw_timestamp'),('SupportingFlows','reported_end'),('SupportingFlows','packets'),
    ('SupportingFlows','bytes'),('SupportingFlows','retrospective_label')],(24,290,1392,610))
write(report/'definition/pages/pages.json',{'$schema':SCHEMA_ROOT+'pagesMetadata/1.0.0/schema.json',
                                         'pageOrder':pages,'activePageName':pages[0]})
write(OUT/'project_context.json',{'report_bundle_id':manifest['report_bundle_id'],'bundle_path':str(bundle),
                                'benchmark_id':manifest['benchmark_id'],'visible_pages':3,'hidden_drillthrough_pages':1,
                                'desktop_validation':'pending'})
write(OUT/'measures.dax','\n\n'.join(f"-- {table}\n{label} = {dax}" for table,items in measures.items() for label,(dax,_) in items.items()))
write(OUT/'power_query.m',expressions)
print('Generated:',OUT/'CyberShield.pbip')
print('Tables:',len(schema),'relationships: 6; visible pages: 3; hidden flow drill-through: 1; visuals:',visual_index)
