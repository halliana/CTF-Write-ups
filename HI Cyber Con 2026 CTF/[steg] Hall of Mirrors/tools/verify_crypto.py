#!/usr/bin/env python3
"""Independent verification of recovered (z,r,s) records and plaintext.

The key here is a previously recovered value, deliberately included only in this
verification utility. solve.py does NOT read it; solve.py recovers the key via LLL.
"""
import csv
import json
import struct
from pathlib import Path

root=Path(__file__).resolve().parent.parent
c={k:int(v,16) for k,v in json.loads((root/'data/hom_curve.json').read_text()).items()}
with (root/'data/hom_signature_tuples.csv').open() as f:
    sigs=[tuple(int(row[f'value{i}'],16) for i in range(3)) for row in csv.DictReader(f)]
p,n,a,b=(c[k] for k in ('p','n','a','b'))
G=(c['Gx'],c['Gy']); Q=(c['Qx'],c['Qy'])
D=0x278c1c0ea08921ba895d3d4c971e4e0a8c8b29d8016f42d9861fe49c6fa826c6


def add(A,B):
    if A is None: return B
    if B is None: return A
    x,y=A; u,v=B
    if x==u and (y+v)%p==0: return None
    slope=((3*x*x+a)*pow(2*y,-1,p) if A==B else (v-y)*pow(u-x,-1,p))%p
    xp=(slope*slope-x-u)%p
    return xp,(slope*(x-xp)-y)%p


def mul(A,k):
    B=None
    while k:
        if k&1: B=add(B,A)
        A=add(A,A)
        k>>=1
    return B

assert mul(G,n) is None
assert mul(G,D)==Q
print('[+] Curve: secp256k1; Q == dG: PASS')

for z,r,s in sigs:
    assert 1 <= r < n and 1 <= s < n
    w=pow(s,-1,n)
    R=add(mul(G,(z*w)%n),mul(Q,(r*w)%n))
    assert R is not None and R[0]%n==r
print('[+] ECDSA signatures verified:',len(sigs),'/',len(sigs))

nonces=[((z+r*D)*pow(s,-1,n))%n for z,r,s in sigs]
assert len(nonces)==48
assert all(0<k<1<<244 for k in nonces)
assert not all(k%4096==0 for k in nonces)
print('[+] L=12 leading-zero nonce condition: 48/48 PASS')
print('[+] Nonce bit lengths:', min(k.bit_length() for k in nonces), 'to', max(k.bit_length() for k in nonces))

M=(1<<64)-1; C=0x9e3779b97f4a7c15; F=0x100000001b3
st=0x4d6972726f72734b;key=bytearray()
for rnd in range(4):
    for byte in D.to_bytes(32,'big'):
        st=((st^byte)*F)&M
        st^=st>>29
        st=(st*C)&M
        st^=st>>32
    st=(st+rnd*0xff51afd7ed558ccd)&M
    key+=st.to_bytes(8,'big')

def rol(v,r):return ((v<<r)|(v>>(64-r)))&M

A,B,Cc,E=struct.unpack('<4Q',key)
ctr=0;keystream=bytearray();blob=(root/'data/hom_sealed.bin').read_bytes()
while len(keystream)<len(blob):
    ctr=(ctr+C)&M
    E^=ctr
    for _ in range(4):
        A=(A+B)&M; E=rol(E^A,32)
        Cc=(Cc+E)&M; B=rol(B^Cc,24)
        A=(A+B)&M; E=rol(E^A,16)
        Cc=(Cc+E)&M; B=rol(B^Cc,37)
    keystream+=struct.pack('<Q',A^Cc)
plaintext=bytes(x^y for x,y in zip(blob,keystream))
assert plaintext==b'hiCTF{h1dd3n_numb3r_l4ttice_le4k}'
print('[+] KDF key:',bytes(key).hex())
print('[+] Decrypted:',plaintext.decode())
