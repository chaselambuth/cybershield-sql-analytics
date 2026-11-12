"""Deterministic synthetic flows, always labeled as fixtures in output metadata."""
import csv
from datetime import datetime, timedelta
from pathlib import Path

from .ingest import REQUIRED


def make_fixture(path: Path):
    path.parent.mkdir(parents=True,exist_ok=True)
    header = REQUIRED + ['Flow Bytes/s','Flow Packets/s',' Fwd Header Length','Fwd Header Length']
    rows = []

    def row(src,port,when,label='BENIGN',sequence=0):
        values = {name:'0' for name in REQUIRED}
        values.update({'Flow ID':f'{src}-192.0.2.10-{port}-{sequence}',
            'Source IP':src,'Source Port':'49152','Destination IP':'192.0.2.10',
            'Destination Port':str(port),'Protocol':'6','Timestamp':when.strftime('%d/%m/%Y %H:%M'),
            'Flow Duration':'1000','Total Fwd Packets':'3','Total Backward Packets':'2',
            'Total Length of Fwd Packets':'240','Total Length of Bwd Packets':'180','Label':label})
        return [values[h] for h in REQUIRED] + ['420000','5000','40','40']

    start=datetime(2017,7,4,8,54)
    for minute in range(132):
        stamp=start+timedelta(minutes=minute)
        for entity in range(1,26):
            for sequence in range(1+(entity+minute)%3):
                rows.append(row(f'192.0.2.{entity}',443 if entity%2 else 80,stamp,sequence=sequence))
        if (9,20) <= (stamp.hour,stamp.minute) < (9,35) or (10,0) <= (stamp.hour,stamp.minute) < (10,15):
            for sequence in range(60):
                rows.append(row('198.51.100.66',21,stamp,'FTP-Patator',sequence))
        if (10,15) <= (stamp.hour,stamp.minute) < (10,25):
            for port in range(1,41):
                rows.append(row('198.51.100.77',port,stamp,'PortScan',port))
    rows.append(list(rows[0]))  # A legitimate repeated content record is retained.
    invalid=list(rows[0]); invalid[REQUIRED.index('Source IP')]='invalid-ip'; rows.append(invalid)
    nonfinite=list(rows[1]); nonfinite[len(REQUIRED)]='Infinity'; rows.append(nonfinite)
    rows.append(['']*len(header))
    with path.open('w',newline='',encoding='cp1252') as stream:
        writer=csv.writer(stream); writer.writerow(header); writer.writerows(rows)
    return path

