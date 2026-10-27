from pyasn1.codec.der import decoder
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.kerberosv5 import getKerberosTGT,getKerberosTGS
from impacket.krb5.types import Principal
old='OLD.VELOCITY.HACKLU'; parent='VELOCITY.HACKLU'
user=Principal('svc_test',type=constants.PrincipalNameType.NT_PRINCIPAL.value)
tgt,cipher,oldkey,sess=getKerberosTGT(user,'svc_test',old,None,None,kdcHost='10.244.0.20')
ref=Principal('krbtgt/'+parent,type=constants.PrincipalNameType.NT_SRV_INST.value)
rt,cipher2,sess1,sess2=getKerberosTGS(ref,old,'10.244.0.20',tgt,cipher,sess)
r=decoder.decode(rt,asn1Spec=TGS_REP())[0]
print('referral ticket realm=',r['ticket']['realm'],'sname=',r['ticket']['sname'],'etype=',r['ticket']['enc-part']['etype'])
spn=Principal('ldap/dc-new.velocity.hacklu',type=constants.PrincipalNameType.NT_SRV_INST.value)
tgs,cipher3,sess3,sess4=getKerberosTGS(spn,parent,'10.244.0.10',rt,cipher2,sess2)
r=decoder.decode(tgs,asn1Spec=TGS_REP())[0]
print('service ticket realm=',r['ticket']['realm'],'sname=',r['ticket']['sname'],'etype=',r['ticket']['enc-part']['etype'])
