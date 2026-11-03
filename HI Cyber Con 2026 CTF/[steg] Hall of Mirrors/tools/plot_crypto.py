#!/usr/bin/env python3
"""Regenerate TLV layout and nonce-bias figures from recovered challenge data.

Run in repo root: python3 tools/plot_crypto.py
Needs matplotlib only; private scalar is the independently verified solution.
"""
import csv, json, struct
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

root=Path(__file__).resolve().parent.parent
out=root/'assets'
raw=(root/'evidence/hom_vm_output.bin').read_bytes()
assert raw[:8]==b'MIRRORS1'
labels={1:'Curve order n',2:'Field prime p',3:'Curve a',4:'Curve b',5:'Generator Gx',6:'Generator Gy',7:'Public point Q',8:'Parameter L',9:'Tuple count',10:'Signature tuples',11:'Sealed blob'}
records=[];pos=8
while pos<len(raw):
    start=pos;t=raw[pos];pos+=1
    if not t:break
    n=struct.unpack_from('<H',raw,pos)[0];pos+=2
    records.append((t,start,n+3))
    pos+=n
assert len(records)==58
kinds=sorted({t for t,_,_ in records})
colors={t:plt.get_cmap('tab20')(i%20) for i,t in enumerate(kinds)}
fig,ax=plt.subplots(figsize=(15,7))
for typ,start,length in records:
    ax.broken_barh([(start,length)],(kinds.index(typ)-.36,.72),facecolors=colors[typ],edgecolors='none')
ax.set_yticks(range(len(kinds)),[f'0x{t:02X} {labels[t]}' for t in kinds])
ax.set_xlabel('Offset in VM output (bytes)')
ax.set_title('Hall of Mirrors — Recovered TLV Layout\n5,083 output bytes, 58 records, 48 tuples')
ax.set_xlim(0,len(raw));ax.grid(axis='x',alpha=.2);ax.invert_yaxis();fig.tight_layout()
fig.savefig(out/'04_tlv_layout_regenerated.png',dpi=190,bbox_inches='tight')
plt.close(fig)

D=0x278c1c0ea08921ba895d3d4c971e4e0a8c8b29d8016f42d9861fe49c6fa826c6
c={k:int(v,16) for k,v in json.loads((root/'data/hom_curve.json').read_text()).items()};order=c['n'];L=c['L']
with (root/'data/hom_signature_tuples.csv').open() as f:
    values=[tuple(int(row[f'value{i}'],16) for i in range(3)) for row in csv.DictReader(f)]
nonces=[((z+r*D)*pow(s,-1,order))%order for z,r,s in values]
assert len(nonces)==48 and all(k<1<<(256-L) for k in nonces)
fig,ax=plt.subplots(figsize=(13,5))
ax.scatter(range(len(nonces)),[k.bit_length() for k in nonces],s=45)
ax.axhline(256-L,linestyle='--',label=f'Nonce upper bound: {256-L} bits')
ax.set_xlabel('Signature index');ax.set_ylabel('Recovered nonce bit length')
ax.set_title('Hall of Mirrors — ECDSA nonce analysis (48 signatures)')
ax.legend();ax.grid(alpha=.25);fig.tight_layout()
fig.savefig(out/'05_nonce_bias_regenerated.png',dpi=190)
print('Wrote regenerated TLV layout and nonce-bias figures')
