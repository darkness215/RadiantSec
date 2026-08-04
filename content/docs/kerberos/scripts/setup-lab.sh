#!/usr/bin/env bash
# ============================================================================
# setup-lab.sh  —  Samba4 Active Directory lab for Kerberos attack practice
# ============================================================================
# Domain      : radiant.local
# Realm       : RADIANT.LOCAL
# NetBIOS     : RADIANT
# DC FQDN     : dc01.radiant.local
# Admin creds : Administrator / Admin@Radiant1!
#
# Run as root on a fresh Ubuntu 22.04 LTS VM inside VMware:
#     sudo bash setup-lab.sh
#
# After completion, the following lab accounts are ready:
#   jdoe       / Password123!   standard domain user
#   svc_sql    / Service123!    SQL service account with SPN — Kerberoastable
#   svc_iis    / Service456!    IIS service account with SPN — Kerberoastable
#   nopreauth  / Roast123!      pre-authentication disabled — AS-REP roastable
# ============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()     { echo -e "${GREEN}[+]${NC} $*"; }
info()    { echo -e "${CYAN}[*]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
section() { echo -e "\n${BOLD}${CYAN}━━  $*  ━━${NC}"; }
die()     { echo -e "${RED}[✗] FATAL:${NC} $*" >&2; exit 1; }

# ── Configuration ─────────────────────────────────────────────────────────────
DOMAIN="radiant.local"
REALM="RADIANT.LOCAL"
NETBIOS="RADIANT"
DC_HOSTNAME="dc01"
DC_FQDN="${DC_HOSTNAME}.${DOMAIN}"
ADMIN_PASS="Admin@Radiant1!"
SAMBA_DB="/var/lib/samba/private"

# Lab account passwords (referenced throughout the script and in the summary)
JDOE_PASS="Password123!"
SVC_SQL_PASS="Service123!"
SVC_IIS_PASS="Service456!"
NOPREAUTH_PASS="Roast123!"

# ── Step 0: Preflight ────────────────────────────────────────────────────────
section "Preflight"

[[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"

# Ubuntu 22.04 is the tested target. Other versions may work but are untested.
UBUNTU_VER=$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID:-unknown}" || echo "unknown")
if [[ "${UBUNTU_VER}" != "22.04" ]]; then
  warn "This script targets Ubuntu 22.04 LTS. Detected version: ${UBUNTU_VER}"
  warn "Proceeding anyway — behaviour on other versions is untested."
fi

# Detect the primary outbound interface IP — Samba uses this for DNS A records.
# 'ip route get 1' asks the kernel which source IP it would use to reach 1.0.0.0,
# which reliably returns the primary interface address even with multiple NICs.
DC_IP=$(ip -4 route get 1 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1) \
  || die "Could not detect primary IP. Check network: ip -4 route get 1"
log "Primary IP detected: ${DC_IP}"

# Enable NTP time sync — Kerberos enforces a 5-minute clock skew limit.
# If the VM clock drifts more than 5 minutes from any Kerberos client,
# authentication will fail with KRB_AP_ERR_SKEW.
timedatectl set-ntp true 2>/dev/null || warn "Could not enable NTP — sync time manually before testing."

# ── Step 1: Install packages ─────────────────────────────────────────────────
section "Installing packages"

# The krb5-user package installer opens a TUI asking for the default realm name.
# debconf-set-selections pre-fills those answers so apt runs non-interactively.
echo "krb5-config krb5-config/default_realm string ${REALM}"         | debconf-set-selections
echo "krb5-config krb5-config/kerberos_servers string ${DC_FQDN}"    | debconf-set-selections
echo "krb5-config krb5-config/admin_server string ${DC_FQDN}"        | debconf-set-selections

DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  samba          \
  winbind        \
  libnss-winbind \
  libpam-winbind \
  krb5-user      \
  pipx           \
  python3-venv   \
  dnsutils       \
  net-tools

log "System packages installed"

# Install Impacket via pipx — this gives scripts named getTGT.py, GetNPUsers.py,
# GetUserSPNs.py etc. (not the impacket-* prefixed wrappers from apt).
# pipx creates an isolated venv so Impacket doesn't conflict with system Python.
# Scripts land in /root/.local/bin/ — we export that into PATH for this session.
info "Installing Impacket via pipx..."
pipx install impacket
# Make the pipx bin dir available in this script session immediately
export PATH="${PATH}:/root/.local/bin"
# Persist the PATH for future logins (sudo, root, and any user that sources /etc/profile)
echo 'export PATH="${PATH}:/root/.local/bin"' > /etc/profile.d/pipx-impacket.sh
log "Impacket installed — scripts available as getTGT.py, GetNPUsers.py, etc."

# ── Step 2: Hostname ─────────────────────────────────────────────────────────
section "Hostname configuration"

hostnamectl set-hostname "${DC_HOSTNAME}"
log "Hostname set to ${DC_HOSTNAME}"

# Kerberos requires that dc01.radiant.local resolves correctly before the Samba
# DNS server is up. Add it to /etc/hosts as a static fallback.
# Ubuntu typically adds a '127.0.1.1 <old-hostname>' line — remove it first.
sed -i '/127\.0\.1\.1/d' /etc/hosts

if ! grep -qF "${DC_FQDN}" /etc/hosts; then
  echo "${DC_IP}    ${DC_FQDN}    ${DC_HOSTNAME}" >> /etc/hosts
  log "Added ${DC_FQDN} → ${DC_IP} to /etc/hosts"
fi

# ── Step 3: DNS configuration ────────────────────────────────────────────────
section "DNS configuration"

# Ubuntu's systemd-resolved runs a stub resolver on 127.0.0.53:53.
# Samba's internal DNS server needs to bind 127.0.0.1:53.
# Both cannot hold port 53 simultaneously — disable the stub listener.
# We drop a config file in resolved.conf.d/ rather than editing the main file,
# which avoids conflicts with system updates overwriting our changes.
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/samba-lab.conf << 'EOF'
[Resolve]
# Disable the stub resolver so Samba can bind port 53 on 127.0.0.1.
# Without this, both processes compete for port 53 and Samba fails to start.
DNSStubListener=no
EOF
systemctl restart systemd-resolved
log "systemd-resolved stub listener disabled"

# Point resolv.conf at 127.0.0.1 — once Samba starts it becomes the DNS server.
# Note: NetworkManager may overwrite this file on reboot. If DNS breaks after
# reboot, re-run: echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
rm -f /etc/resolv.conf
cat > /etc/resolv.conf << EOF
# Managed by setup-lab.sh — Samba AD DC is the DNS server on 127.0.0.1
# If this file is overwritten by NetworkManager, re-run setup-lab.sh
# or manually: echo "nameserver 127.0.0.1" > /etc/resolv.conf
nameserver 127.0.0.1
search ${DOMAIN}
EOF
log "resolv.conf → 127.0.0.1 (Samba internal DNS)"

# Prevent NetworkManager from overwriting resolv.conf on reboot.
# By default NM regenerates resolv.conf from DHCP lease data each time it
# manages a connection. Setting dns=none tells it to leave the file alone.
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/samba-lab.conf << 'EOF'
[main]
# Do not manage /etc/resolv.conf — Samba is the DNS server for this machine
dns=none
EOF
log "NetworkManager configured to leave resolv.conf alone"

# ── Step 4: Mask conflicting Samba services ──────────────────────────────────
section "Service configuration"

# The samba package ships three separate daemons for file sharing:
#   smbd    — SMB/CIFS file server
#   nmbd    — NetBIOS name server
#   winbind — Windows authentication bridge
# When running as an AD DC, these must not run — samba-ad-dc is a single
# monolithic process that replaces all three. Masking prevents them from
# starting automatically (even if something tries to enable them).
for svc in smbd nmbd winbind; do
  systemctl stop    "${svc}" 2>/dev/null || true
  systemctl disable "${svc}" 2>/dev/null || true
  systemctl mask    "${svc}" 2>/dev/null || true
done
log "Masked smbd, nmbd, winbind — samba-ad-dc handles everything"

# ── Step 5: Provision Samba4 AD ──────────────────────────────────────────────
section "Samba4 AD provision"

if [[ -f "${SAMBA_DB}/sam.ldb" ]]; then
  warn "sam.ldb already exists — Samba appears provisioned. Skipping."
  warn "To start over: sudo rm -rf /var/lib/samba /etc/samba/smb.conf && sudo bash $0"
else
  # The samba package may leave a default smb.conf behind. The provision command
  # refuses to overwrite an existing smb.conf — remove it first.
  rm -f /etc/samba/smb.conf

  info "Provisioning domain ${REALM} (typically takes 30–60 seconds)..."

  samba-tool domain provision \
    --server-role=dc           \
    --use-rfc2307              \
    --dns-backend=SAMBA_INTERNAL \
    --realm="${REALM}"         \
    --domain="${NETBIOS}"      \
    --adminpass="${ADMIN_PASS}" \
    --host-name="${DC_HOSTNAME}" \
    --host-ip="${DC_IP}"

  # Flags:
  #   --server-role=dc         — configure as a full Active Directory domain controller
  #   --use-rfc2307            — adds POSIX attributes (uid/gid) to user and group objects,
  #                              required for Linux AD integration tools
  #   --dns-backend=SAMBA_INTERNAL — Samba runs its own authoritative DNS server for
  #                              radiant.local, handling all SRV and A records that
  #                              Kerberos clients need to locate the KDC
  #   --host-name              — the DC's short name (dc01); Samba derives dc01.radiant.local
  #   --host-ip                — the IP address to register in DNS for dc01.radiant.local

  log "Domain ${REALM} provisioned"
fi

# ── Step 6: Kerberos configuration ───────────────────────────────────────────
section "Kerberos configuration"

# samba-tool domain provision generates a ready-to-use krb5.conf and stores it
# in its private directory. We copy it to /etc/krb5.conf so that krb5-user tools
# (kinit, klist) and Impacket libraries pick it up automatically.
if [[ -f "${SAMBA_DB}/krb5.conf" ]]; then
  cp "${SAMBA_DB}/krb5.conf" /etc/krb5.conf
  log "Installed Samba's generated krb5.conf → /etc/krb5.conf"
else
  # Fallback: write it manually. This covers Samba versions that don't generate
  # the file, or if the private directory path differs.
  cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    # forwardable = true lets tools request forwardable tickets by default —
    # required for delegation-based techniques like S4U2Proxy
    forwardable = true

[realms]
    ${REALM} = {
        kdc = ${DC_FQDN}
        admin_server = ${DC_FQDN}
    }

[domain_realm]
    .${DOMAIN} = ${REALM}
    ${DOMAIN} = ${REALM}
EOF
  log "Wrote /etc/krb5.conf manually (Samba did not generate one)"
fi

# ── Step 7: Domain password policy ───────────────────────────────────────────
# samba-tool commands operate directly on the LDB files and do NOT require the
# samba-ad-dc daemon to be running. We configure everything here — before starting
# the service — so the LDB is in its final state when Samba first comes up.
# Modifying the LDB directly while Samba is running risks lock conflicts.

section "Password policy"

# Set the domain-level password policy for the lab:
#   --max-pwd-age=0               — passwords never expire
#   --min-pwd-age=0               — allow immediate password changes
#   --min-pwd-length=8            — our passwords all exceed this
#   --complexity=on               — Windows-style complexity requirements
#   --account-lockout-threshold=0 — disable lockout so Kerberoasting / AS-REP
#                                   roasting attempts don't lock out lab accounts
samba-tool domain passwordsettings set \
  --max-pwd-age=0               \
  --min-pwd-age=0               \
  --min-pwd-length=8            \
  --complexity=on               \
  --account-lockout-threshold=0

log "Password policy set — no expiry, no lockout, min length 8"

# ── Step 8: Create lab users ─────────────────────────────────────────────────
section "Creating lab users"

# create_user <username> <password> — idempotent: skips if user already exists.
# samba-tool user create writes directly to the LDB; no daemon needed.
create_user() {
  local username="$1"
  local password="$2"

  if samba-tool user show "${username}" &>/dev/null; then
    warn "User ${username} already exists — skipping creation"
  else
    samba-tool user create "${username}" "${password}"
    log "Created user: ${username}"
  fi

  # setexpiry --noexpiry sets account expiry to never, separate from password
  # expiry (controlled by the domain policy set above)
  samba-tool user setexpiry "${username}" --noexpiry
}

create_user "jdoe"      "${JDOE_PASS}"
create_user "svc_sql"   "${SVC_SQL_PASS}"
create_user "svc_iis"   "${SVC_IIS_PASS}"
create_user "nopreauth" "${NOPREAUTH_PASS}"

# ── Step 9: Register Service Principal Names ──────────────────────────────────
section "Registering SPNs"

# An SPN (Service Principal Name) is the unique identifier that ties a service
# to the account running it (e.g. MSSQLSvc/sqlserver.radiant.local:1433 → svc_sql).
# Accounts with registered SPNs are targetable by Kerberoasting — the KDC will
# issue a service ticket encrypted with the account's password hash, which an
# attacker can crack offline.

# register_spn <spn> <account> — idempotent: skips if the SPN is already present.
register_spn() {
  local spn="$1"
  local account="$2"

  if samba-tool spn list "${account}" 2>/dev/null | grep -qF "${spn}"; then
    warn "SPN already registered: ${spn} → ${account}"
  else
    samba-tool spn add "${spn}" "${account}"
    log "Registered SPN: ${spn} → ${account}"
  fi
}

# SQL Server service account — both the port-qualified and port-less SPNs are
# registered because Kerberos clients may query either form
register_spn "MSSQLSvc/sqlserver.${DOMAIN}:1433" "svc_sql"
register_spn "MSSQLSvc/sqlserver.${DOMAIN}"       "svc_sql"

# IIS service account — HTTP SPN, used for Silver Ticket practice
# The hostnames sqlserver.radiant.local / webserver.radiant.local don't need to
# physically exist — the SPN is registered on the account, not the machine.
# A Silver Ticket targets the account, not the hostname.
register_spn "HTTP/webserver.${DOMAIN}"            "svc_iis"

# ── Step 10: Disable pre-authentication for nopreauth ────────────────────────
section "Configuring AS-REP roastable user"

# Kerberos pre-authentication requires a client to prove knowledge of its password
# before the KDC will issue a TGT. When DONT_REQUIRE_PREAUTH is set on an account,
# the KDC will hand out an AS-REP (Authentication Service Response — the KDC's
# reply to an initial login request) to anyone who asks, without credentials.
# The response is partially encrypted with the account's password hash — making
# it crackable offline. This is the AS-REP Roasting attack.
#
# userAccountControl bit values:
#   UF_NORMAL_ACCOUNT       =   512  (0x00000200) — standard user account
#   UF_DONT_REQUIRE_PREAUTH = 4194304 (0x00400000) — disables pre-auth requirement
#   Combined value          = 4194816
#
# samba-tool has no direct CLI flag for this setting. We use ldbmodify to write
# directly to the LDB (Lightweight Directory B-tree — Samba's internal LDAP
# database). ldbmodify is the Samba equivalent of ldapmodify.
# We do this now, before starting samba-ad-dc, to avoid concurrent LDB access.

PREAUTH_UAC=4194816

# ldbsearch queries the LDB and returns LDIF-formatted output.
# awk extracts the distinguishedName (DN) — the unique path to the object in
# the directory tree, e.g. CN=nopreauth,CN=Users,DC=radiant,DC=local
NOPREAUTH_DN=$(ldbsearch -H "${SAMBA_DB}/sam.ldb" \
  -b "CN=Users,DC=radiant,DC=local" \
  "(sAMAccountName=nopreauth)" \
  dn \
  | awk '/^dn:/ { sub(/^dn: /, ""); print; exit }' \
  | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

[[ -n "${NOPREAUTH_DN}" ]] \
  || die "Could not find DN for nopreauth in sam.ldb. Was the user created successfully?"

ldbmodify -H "${SAMBA_DB}/sam.ldb" << LDBEOF
dn: ${NOPREAUTH_DN}
changetype: modify
replace: userAccountControl
userAccountControl: ${PREAUTH_UAC}
LDBEOF

log "AS-REP roasting enabled for nopreauth (userAccountControl = ${PREAUTH_UAC})"

# ── Step 11: Start samba-ad-dc ────────────────────────────────────────────────
section "Starting Samba AD DC"

systemctl unmask  samba-ad-dc
systemctl enable  samba-ad-dc
systemctl restart samba-ad-dc

# Wait for the Kerberos port (88/TCP) to open — that's the signal that the KDC
# is ready to issue tickets. We use /dev/tcp (a bash built-in) to probe the port
# without needing nc or telnet installed.
info "Waiting for KDC to come up on port 88..."
READY=false
for i in $(seq 1 45); do
  if bash -c 'echo >/dev/tcp/127.0.0.1/88' 2>/dev/null; then
    READY=true
    break
  fi
  sleep 1
done

[[ "${READY}" == "true" ]] \
  || die "KDC did not start within 45 seconds. Debug: journalctl -u samba-ad-dc -n 50"

log "Samba AD DC is up — KDC listening on port 88"

# ── Step 12: Verification ────────────────────────────────────────────────────
section "Verification"

VERIFY_PASS=true
VERIFY_DIR=$(mktemp -d)
# Clean up the temp directory when the script exits (on success or failure)
trap 'rm -rf "${VERIFY_DIR}"' EXIT

# verify_tgt <user> <password> — requests a TGT from the KDC using real credentials.
# getTGT.py saves the ticket as <user>.ccache in the current directory.
# If the KDC issues a ticket, Kerberos authentication is working for this account.
verify_tgt() {
  local user="$1"
  local pass="$2"

  info "Requesting TGT for ${user}..."
  if ( cd "${VERIFY_DIR}" && \
       getTGT.py "${DOMAIN}/${user}:${pass}" \
       -dc-ip "${DC_IP}" ) &>/dev/null; then
    log "  TGT OK: ${user}"
  else
    warn "  TGT FAILED for ${user}. Retry manually:"
    warn "    getTGT.py ${DOMAIN}/${user}:'${pass}' -dc-ip ${DC_IP}"
    VERIFY_PASS=false
  fi
}

verify_tgt "jdoe"    "${JDOE_PASS}"
verify_tgt "svc_sql" "${SVC_SQL_PASS}"
verify_tgt "svc_iis" "${SVC_IIS_PASS}"

# AS-REP Roasting test — nopreauth should return a crackable hash without needing
# to supply a password. The hash starts with $krb5asrep$23$ (RC4) or $krb5asrep$18$
# (AES) and can be cracked with hashcat or john.
info "Testing AS-REP Roasting for nopreauth..."
if GetNPUsers.py "${DOMAIN}/nopreauth" \
     -no-pass -dc-ip "${DC_IP}" 2>&1 | grep -q '$krb5asrep$'; then
  log "  AS-REP Roasting OK: nopreauth returns crackable hash"
else
  warn "  AS-REP Roasting test did not return expected hash. Retry manually:"
  warn "    GetNPUsers.py ${DOMAIN}/nopreauth -no-pass -dc-ip ${DC_IP}"
  VERIFY_PASS=false
fi

# Kerberoasting test — enumerate service accounts with registered SPNs.
# GetUserSPNs.py queries the DC's LDAP for accounts with non-empty
# servicePrincipalName attributes, then requests service tickets for each,
# returning tickets encrypted with the account's password hash.
info "Testing Kerberoasting (SPN enumeration) as jdoe..."
if GetUserSPNs.py "${DOMAIN}/jdoe:${JDOE_PASS}" \
     -dc-ip "${DC_IP}" 2>&1 | grep -q "MSSQLSvc"; then
  log "  Kerberoasting OK: svc_sql SPN visible"
else
  warn "  SPN enumeration did not return svc_sql. Retry manually:"
  warn "    GetUserSPNs.py ${DOMAIN}/jdoe:'${JDOE_PASS}' -dc-ip ${DC_IP}"
  VERIFY_PASS=false
fi

# ── Step 13: Summary ─────────────────────────────────────────────────────────
section "Lab summary"

echo ""
printf "  ${BOLD}%-18s${NC} %s\n" "Domain"      "${REALM}"
printf "  ${BOLD}%-18s${NC} %s\n" "DC hostname"  "${DC_FQDN}"
printf "  ${BOLD}%-18s${NC} %s\n" "DC IP"        "${DC_IP}"
echo ""

printf "  ${BOLD}%-15s  %-22s  %s${NC}\n" "Account" "Password" "Purpose"
printf "  %-15s  %-22s  %s\n" "Administrator" "${ADMIN_PASS}"   "Domain admin"
printf "  %-15s  %-22s  %s\n" "jdoe"          "${JDOE_PASS}"    "Standard user — requesting account for Diamond/Sapphire tickets"
printf "  %-15s  %-22s  %s\n" "svc_sql"       "${SVC_SQL_PASS}" "SQL SPN account — Kerberoasting, Silver Ticket"
printf "  %-15s  %-22s  %s\n" "svc_iis"       "${SVC_IIS_PASS}" "IIS SPN account — Silver Ticket (HTTP)"
printf "  %-15s  %-22s  %s\n" "nopreauth"     "${NOPREAUTH_PASS}" "Pre-auth disabled — AS-REP Roasting"
echo ""

printf "  ${BOLD}%-18s${NC} %s\n" "SPNs registered" ""
printf "    MSSQLSvc/sqlserver.${DOMAIN}:1433  →  svc_sql\n"
printf "    MSSQLSvc/sqlserver.${DOMAIN}        →  svc_sql\n"
printf "    HTTP/webserver.${DOMAIN}           →  svc_iis\n"
echo ""

echo -e "  ${BOLD}Quick start${NC}"
echo   "    getTGT.py ${DOMAIN}/jdoe:'${JDOE_PASS}' -dc-ip ${DC_IP}"
echo   "    export KRB5CCNAME=jdoe.ccache"
echo   "    klist"
echo   ""
echo   "    GetNPUsers.py ${DOMAIN}/nopreauth -no-pass -dc-ip ${DC_IP}"
echo   "    GetUserSPNs.py ${DOMAIN}/jdoe:'${JDOE_PASS}' -dc-ip ${DC_IP} -request"
echo ""

if [[ "${VERIFY_PASS}" == "true" ]]; then
  echo -e "  ${GREEN}${BOLD}All verification checks passed. Lab is ready.${NC}"
else
  echo -e "  ${YELLOW}${BOLD}Some checks failed — see warnings above.${NC}"
  echo -e "  ${YELLOW}Samba sometimes needs an extra 30 seconds after first start."
  echo -e "  Wait a moment and retry the failed commands manually.${NC}"
fi

echo ""
