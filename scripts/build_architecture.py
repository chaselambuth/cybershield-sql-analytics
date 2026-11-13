"""Generate the CyberShield architecture as a compact, reproducible vector figure."""
import argparse
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, Ellipse, FancyArrowPatch, Polygon
from matplotlib.path import Path as DrawingPath


ROOT = Path(__file__).resolve().parents[1]
W, H = 1600, 1120
BG, PANEL, BORDER = '#080F1D', '#101C2E', '#293951'
WHITE, BODY, MUTED = '#EFF5FF', '#C5D2E7', '#8E9FB9'
CYAN, VIOLET, TEAL, AMBER = '#62DDF5', '#B09AFF', '#66E2B5', '#F7C17B'


def build(output, png=None):
    plt.rcParams.update({'font.family': ['DejaVu Sans', 'Arial', 'sans-serif'],
                         'svg.fonttype': 'none', 'svg.hashsalt': 'cybershield-architecture'})
    fig, ax = plt.subplots(figsize=(16, 11.2), facecolor=BG)
    fig.subplots_adjust(0, 0, 1, 1)
    ax.set(xlim=(0, W), ylim=(H, 0), facecolor=BG)
    ax.axis('off')

    def text(x, y, value, size=11, color=BODY, bold=False, mono=False, align='left'):
        return ax.text(x, y, value, fontsize=size, color=color, va='top', ha=align,
                       fontweight='bold' if bold else 'normal', linespacing=1.5,
                       fontfamily='DejaVu Sans Mono' if mono else None, zorder=6)

    def line(points, color=BORDER, width=1, alpha=1):
        ax.plot(*zip(*points), color=color, linewidth=width, alpha=alpha,
                solid_capstyle='round', zorder=2)

    def flow(points, color=CYAN, arrow=True):
        path = DrawingPath(points, [DrawingPath.MOVETO]+[DrawingPath.LINETO]*(len(points)-1))
        for width, alpha in [(9, .035), (5, .065)]:
            ax.add_patch(FancyArrowPatch(path=path, arrowstyle='-', color=color,
                                         linewidth=width, alpha=alpha, zorder=2))
        ax.add_patch(FancyArrowPatch(path=path, arrowstyle='-|>' if arrow else '-',
                                     mutation_scale=11, color=color, linewidth=1.15,
                                     joinstyle='round', zorder=3))

    def port(x, y, color=CYAN):
        ax.add_patch(Circle((x, y), 6, color=color, alpha=.09, zorder=4))
        ax.add_patch(Circle((x, y), 2.4, color=color, zorder=5))

    def card(x, y, width, height, color=CYAN):
        points=[(x+12,y),(x+width-12,y),(x+width,y+12),(x+width,y+height-12),
                (x+width-12,y+height),(x+12,y+height),(x,y+height-12),(x,y+12)]
        ax.add_patch(Polygon(points, closed=True, facecolor=PANEL, edgecolor=BORDER,
                             linewidth=.9, zorder=4))
        # Accent marks remain above the panel fill.
        ax.plot([x+18,x+80],[y,y],color=color,linewidth=2,zorder=5)
        ax.plot([x+width-24,x+width-16],[y+20,y+20],color=color,linewidth=1.5,zorder=5)

    def eyebrow(x, y, label, color=CYAN):
        text(x, y, label, 9.3, color, mono=True)

    def pill(x, y, width, label, color=CYAN):
        points=[(x+5,y),(x+width,y),(x+width,y+25),(x,y+25),(x,y+5)]
        ax.add_patch(Polygon(points,facecolor=color,alpha=.07,edgecolor=color,linewidth=.7,zorder=5))
        text(x+width/2,y+6,label,8.4,color,mono=True,align='center')

    # A faint circuit grid provides depth without competing with the data flow.
    for x in range(55,1546,48):
        line([(x,180),(x,1030)], '#39506C', .35, .14)
    for y in range(186,1031,48):
        line([(55,y),(1545,y)], '#39506C', .35, .14)

    shield=[(55,55),(84,44),(113,55),(109,89),(84,110),(59,89),(55,55)]
    line(shield,CYAN,8,.045)
    line(shield,CYAN,1.6)
    line([(69,78),(80,89),(100,64)],CYAN,2)
    text(137,39,'CyberShield',38,WHITE,True)
    text(140,105,'SQL  /  SECURITY  /  ANALYTICS',11.5,CYAN,mono=True)
    text(55,146,'From validated network flows to explainable, evidence-linked investigations.',13,MUTED)
    pill(1225,48,320,'IMPLEMENTED / OFFLINE RESEARCH',TEAL)
    pill(1135,94,150,'POSTGRESQL',CYAN)
    pill(1300,94,105,'PYTHON',VIOLET)
    pill(1420,94,125,'POWER BI',TEAL)
    eyebrow(55,188,'DATA PROCESSING & EVALUATION',MUTED)
    line([(370,195),(1545,195)],BORDER,.65)

    # Primary data path and the two separately evaluated detector branches.
    flow([(350,363),(410,363)])
    flow([(760,363),(790,363),(790,279),(820,279)])
    flow([(790,363),(790,447),(820,447)],VIOLET)
    flow([(1120,279),(1155,279),(1155,363),(1190,363)])
    flow([(1120,447),(1155,447),(1155,363)],VIOLET,False)

    card(55,230,295,265)
    eyebrow(75,249,'01 / INGEST')
    text(75,280,'Flow ingestion',19,WHITE,True)
    pill(75,323,130,'CIC-IDS2017')
    pill(215,323,115,'FIXTURE')
    line([(75,365),(330,365)],BORDER,.7)
    text(75,384,'Python parser → PostgreSQL COPY\nType checks and quarantine\nReconciled rows and provenance',10.8)
    text(75,461,'HASH-BOUND / REPEATABLE LOADS',8.6,CYAN,mono=True)

    card(410,230,350,265)
    eyebrow(430,249,'02 / TRANSFORM')
    text(430,280,'PostgreSQL',23,WHITE,True)
    text(430,322,'Flows + provenance; labels separate',10.8,MUTED)
    ax.add_patch(Polygon([(430,355),(740,355),(740,435),(430,435)],
                          facecolor=CYAN,alpha=.045,zorder=5))
    eyebrow(443,365,'FIVE-MINUTE SOURCE WINDOWS')
    text(443,390,'Volume, ports, destinations\nServices, packets, bytes, duration',10.6)
    text(430,454,'Prior-hour RANGE history',10.3,MUTED)

    card(820,210,300,138)
    eyebrow(840,229,'03A / SQL RULES')
    text(840,258,'Explainable scoring',17,WHITE,True)
    text(840,296,'Volume / port diversity / services\nContinuous rules → maximum score',10.1)

    card(820,378,300,138,VIOLET)
    eyebrow(840,397,'03B / MODEL COMPARISON',VIOLET)
    text(840,426,'Fixed CPU models',17,WHITE,True)
    text(840,464,'Eight models, including logistic\n7 features; train-only transforms',10)

    card(1190,230,355,265)
    eyebrow(1210,249,'04 / VALIDATE')
    text(1210,280,'Calibrate & compare',18.5,WHITE,True)
    text(1210,329,'Known-benign cutoffs\nMatched scoring populations\nCaught positives + false alerts\nMedian / P95 + throughput',11.5)
    text(1210,463,'SEPARATE METHOD SCORES',8.8,CYAN,mono=True)
    for x,y,c in [(350,363,CYAN),(410,363,CYAN),(760,363,CYAN),(820,279,CYAN),
                  (820,447,VIOLET),(1120,279,CYAN),(1120,447,VIOLET),(1190,363,CYAN)]:
        port(x,y,c)

    # The workspace queries PostgreSQL directly; report surfaces consume a pinned bundle.
    flow([(585,495),(585,539),(275,539),(275,598)])
    flow([(1367,495),(1367,539),(1062,539),(1062,598)],TEAL)
    eyebrow(55,562,'EVIDENCE PLANE',MUTED)
    card(55,598,440,160)
    eyebrow(75,617,'QUERY INTERFACE')
    text(75,648,'SQL investigation workspace',16.8,WHITE,True)
    text(75,681,'Read-only PostgreSQL queries\nTriage queue → original flow records\nInteractive results and CSV export',10.7)

    card(580,598,965,160,TEAL)
    eyebrow(602,617,'05 / FREEZE & VERIFY',TEAL)
    text(602,648,'A traceable evidence bundle',23,WHITE,True)
    text(602,694,'Scores, thresholds, metrics, figures and supporting records',11.8)
    text(602,725,'Run identity + source / code / SQL hashes',10.5,MUTED)
    pill(1260,620,245,'PINNED PROTOTYPE RUN',TEAL)
    for offset in (12,6,0):
        ax.add_patch(Polygon([(1450+offset,674-offset),(1495+offset,674-offset),
                              (1505+offset,684-offset),(1505+offset,723-offset),
                              (1450+offset,723-offset)],facecolor=PANEL,
                             edgecolor=TEAL,linewidth=.75,zorder=5))
    text(1478,690,'JSON',9,TEAL,mono=True,align='center')
    port(275,598)
    port(1062,598,TEAL)

    flow([(1062,758),(1062,803),(800,803),(800,850)],TEAL)
    flow([(1062,803),(1325,803),(1325,850)],VIOLET)
    eyebrow(55,813,'APPLICATION CONTEXT',MUTED)
    eyebrow(580,813,'ANALYST INTERFACES',MUTED)

    card(55,850,440,170,AMBER)
    eyebrow(75,869,'SCOPE / DATA BOUNDARY',AMBER)
    text(75,900,'Two study populations',19,WHITE,True)
    text(75,944,'Original Tuesday application snapshot\nCorrected multi-day study stays separate\nValidated export required for new imports',10.6)

    card(580,850,440,170,TEAL)
    eyebrow(602,869,'06 / REPORT',TEAL)
    text(602,900,'Power BI',24,WHITE,True)
    text(602,938,'Power Query + DAX on packed JSON\nQuality, triage and model-cost pages\nWindow-to-flow drill-through',10.9)
    for index,height in enumerate((14,25,38)):
        x=942+index*15
        ax.add_patch(Polygon([(x,927),(x+8,927),(x+8,927-height),(x,927-height)],
                              facecolor=TEAL,alpha=.7,zorder=5))

    card(1105,850,440,170,VIOLET)
    eyebrow(1127,869,'07 / INVESTIGATE',VIOLET)
    text(1127,902,'Evidence-grounded agent',18.5,WHITE,True)
    text(1127,938,'Read-only SQLite evidence snapshot\nBounded tools → cited investigation brief\nTool trace, latency, tokens and cost',10.9)
    for x,y in [(1480,865),(1502,879),(1480,893)]:
        port(x,y,VIOLET)
    ax.plot([1480,1502,1480],[865,879,893],color=VIOLET,linewidth=.8,zorder=5)

    line([(55,1050),(1545,1050)],BORDER,.7)
    text(55,1070,'Ground-truth labels stay outside feature generation and alert ranking.',10,MUTED)
    text(1545,1072,'PYTHON / MATPLOTLIB  •  REPRODUCIBLE SVG',8.6,MUTED,mono=True,align='right')

    output.parent.mkdir(parents=True,exist_ok=True)
    fig.savefig(output,format='svg',facecolor=BG,
                metadata={'Date':None,'Title':'CyberShield Analytics — Project Architecture',
                          'Description':'Network-flow ingestion, PostgreSQL features, separate SQL/ML evaluation, and evidence-linked investigation interfaces.'})
    if png:
        png.parent.mkdir(parents=True,exist_ok=True)
        fig.savefig(png,dpi=140,facecolor=BG)
    plt.close(fig)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'docs/assets/architecture.svg')
    parser.add_argument('--png',type=Path,help='Optional PNG preview; SVG remains the canonical asset')
    args=parser.parse_args()
    build(args.output,args.png)
    print(f'Created {args.output}')
