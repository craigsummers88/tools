#!/usr/bin/env bash
OUTDIR="${1:-/var/tmp/server-review}"
COLLECTOR_VERSION="1.0.0"
export LC_ALL=C
PATH="$PATH:/usr/sbin:/sbin"

js() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/ }"
  s="${s//$'\r'/}"
  s="${s//$'\n'/ }"
  printf '"%s"' "$s"
}

jarr() {
  local first=1 out="["
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if [ $first -eq 1 ]; then first=0; else out="$out,"; fi
    out="$out$(js "$line")"
  done
  printf '%s]' "$out"
}

num() {
  case "$1" in
    ''|*[!0-9]*) printf 'null' ;;
    *) printf '%s' "$1" ;;
  esac
}

have() { command -v "$1" >/dev/null 2>&1; }

svc_active() {
  if have systemctl; then systemctl is-active "$1" 2>/dev/null | head -n1; else echo "unknown"; fi
}

HOST="$(hostname 2>/dev/null)"
FQDN="$(hostname -f 2>/dev/null || echo "$HOST")"
. /etc/os-release 2>/dev/null
OS_ID="${ID:-unknown}"
OS_VER="${VERSION_ID:-}"
OS_NAME="${PRETTY_NAME:-$OS_ID $OS_VER}"
KERNEL="$(uname -r)"
ARCH="$(uname -m)"
UPTIME_S="$(cut -d. -f1 /proc/uptime 2>/dev/null)"
BOOT="$(uptime -s 2>/dev/null)"
VIRT="$(systemd-detect-virt 2>/dev/null || echo unknown)"
CPUS="$(nproc 2>/dev/null)"
MEM_KB="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null)"
IS_ROOT=false
[ "$(id -u)" = "0" ] && IS_ROOT=true

PKG="unknown"; UPG=""; SEC=""; LAST_UPDATE=""; AUTO=""
if have apt-get; then
  PKG="apt"
  UPG="$(apt list --upgradable 2>/dev/null | grep -c upgradable)"
  SEC="$(apt list --upgradable 2>/dev/null | grep -ci -- '-security')"
  for f in /var/lib/apt/periodic/update-success-stamp /var/lib/apt/lists/partial /var/cache/apt/pkgcache.bin; do
    if [ -e "$f" ]; then LAST_UPDATE="$(date -u -r "$f" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"; break; fi
  done
  if grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/50unattended-upgrades; then AUTO="unattended-upgrades"; fi
elif have dnf || have yum; then
  PM="$(have dnf && echo dnf || echo yum)"
  PKG="$PM"
  UPG="$(timeout 120 $PM -q check-update 2>/dev/null | grep -cE '^[A-Za-z0-9_.+-]+\.(x86_64|noarch|aarch64|i686)')"
  SEC="$(timeout 120 $PM -q updateinfo list security 2>/dev/null | grep -c -E 'Important|Critical|Moderate|Low|security')"
  LAST_UPDATE="$(rpm -qa --last 2>/dev/null | head -n1 | sed -E 's/^[^ ]+ +//')"
  if [ "$(svc_active dnf-automatic.timer)" = "active" ] || [ "$(svc_active yum-cron)" = "active" ] || [ "$(svc_active dnf-automatic-install.timer)" = "active" ]; then AUTO="dnf-automatic"; fi
elif have zypper; then
  PKG="zypper"
  UPG="$(timeout 120 zypper -q lu 2>/dev/null | grep -c '^v ')"
  SEC="$(timeout 120 zypper -q lp --category security 2>/dev/null | grep -c '|')"
fi
REBOOT=false
[ -f /var/run/reboot-required ] && REBOOT=true
if have needs-restarting; then needs-restarting -r >/dev/null 2>&1 || REBOOT=true; fi

SSHD=""
if have sshd; then SSHD="$(sshd -T 2>/dev/null)"; fi
sshv() {
  local v=""
  if [ -n "$SSHD" ]; then v="$(printf '%s\n' "$SSHD" | awk -v k="$1" 'tolower($1)==k {$1=""; sub(/^ /,""); print; exit}')"; fi
  if [ -z "$v" ] && [ -r /etc/ssh/sshd_config ]; then v="$(awk -v k="$1" 'tolower($1)==k {print $2; exit}' /etc/ssh/sshd_config)"; fi
  printf '%s' "$v"
}
SSH_ACTIVE="$(svc_active sshd)"
[ "$SSH_ACTIVE" != "active" ] && SSH_ACTIVE="$(svc_active ssh)"

UFW=""; FWD=""; NFT=""; IPT=""
have ufw && UFW="$(ufw status 2>/dev/null | head -n1 | awk '{print $2}')"
have firewall-cmd && FWD="$(firewall-cmd --state 2>/dev/null)"
have nft && NFT="$(nft list ruleset 2>/dev/null | grep -cE '^\s+(ip|tcp|udp|ct|iif|oif|meta|counter|accept|drop|reject)')"
have iptables && IPT="$(iptables -S 2>/dev/null | grep -c '^-A')"

SELINUX=""; APPARMOR=""
have getenforce && SELINUX="$(getenforce 2>/dev/null)"
if have aa-status; then aa-status --enabled 2>/dev/null && APPARMOR="enabled" || APPARMOR="disabled"; elif [ -d /sys/kernel/security/apparmor ]; then APPARMOR="enabled"; fi

NTP_SYNC=""
have timedatectl && NTP_SYNC="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"

UID0="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)"
LOGIN_USERS="$(awk -F: '$3>=1000 && $3<65534 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd 2>/dev/null)"
EMPTY_PW=""
[ -r /etc/shadow ] && EMPTY_PW="$(awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null)"
NOPASSWD="$(grep -rhsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null)"
PASS_MAX="$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs 2>/dev/null)"
PASS_MIN_LEN="$(awk '/^\s*minlen/{print $3}' /etc/security/pwquality.conf 2>/dev/null | head -n1)"

LISTEN=""
if have ss; then LISTEN="$(ss -H -tuln 2>/dev/null | awk '{print $1" "$5}' | grep -E ' (0\.0\.0\.0|\*|\[::\]|::):[0-9]+$' | sort -u)"; fi

DISKS="$(df -P -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | awk 'NR>1 {gsub("%","",$5); print $6"|"$2"|"$5}')"
CRYPT="$(lsblk -rno TYPE 2>/dev/null | grep -c crypt)"

EDR=""
if have mdatp; then
  H="$(mdatp health --field healthy 2>/dev/null | tr -d '"')"
  R="$(mdatp health --field real_time_protection_enabled 2>/dev/null | tr -d '"')"
  O="$(mdatp health --field licensed 2>/dev/null | tr -d '"')"
  EDR="Microsoft Defender for Endpoint (healthy $H, real-time $R, licensed $O)"
fi
for s in falcon-sensor sentinelone SentinelAgent sophos-spl cylancesvc ds_agent wazuh-agent elastic-agent clamav-daemon clamd@scan; do
  [ "$(svc_active $s)" = "active" ] && EDR="${EDR:+$EDR; }$s"
done
BACKUP=""
for s in veeamservice acronis_mms datto-agent dattobackup cdp-agent bacula-fd urbackupclientbackend; do
  [ "$(svc_active $s)" = "active" ] && BACKUP="${BACKUP:+$BACKUP; }$s"
done
for c in restic borg rsnapshot duplicity; do have $c && BACKUP="${BACKUP:+$BACKUP; }$c"; done

sc() { sysctl -n "$1" 2>/dev/null; }
RISKY="$( (dpkg -l 2>/dev/null | awk '/^ii/{print $2}'; rpm -qa --qf '%{NAME}\n' 2>/dev/null) | grep -E '^(telnetd|telnet-server|rsh-server|rsh|vsftpd|tftp-server|tftpd-hpa|xinetd|nis|ypserv|talkd|snmpd)$' | sort -u)"
RUNNING="$(have systemctl && systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}')"

STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  printf '{'
  printf '"SchemaVersion":1,"Collector":"linux","CollectorVersion":%s,"CollectedUtc":%s,"ComputerName":%s,"IsAdmin":%s,' "$(js "$COLLECTOR_VERSION")" "$(js "$STAMP")" "$(js "$HOST")" "$IS_ROOT"
  printf '"System":{"Name":%s,"Fqdn":%s,"OsId":%s,"OsVersion":%s,"OsName":%s,"Kernel":%s,"Arch":%s,"UptimeSeconds":%s,"LastBoot":%s,"Virtualisation":%s,"LogicalCpus":%s,"MemoryKB":%s},' \
    "$(js "$HOST")" "$(js "$FQDN")" "$(js "$OS_ID")" "$(js "$OS_VER")" "$(js "$OS_NAME")" "$(js "$KERNEL")" "$(js "$ARCH")" "$(num "$UPTIME_S")" "$(js "$BOOT")" "$(js "$VIRT")" "$(num "$CPUS")" "$(num "$MEM_KB")"
  printf '"Updates":{"PackageManager":%s,"Upgradable":%s,"Security":%s,"LastUpdate":%s,"Automatic":%s,"RebootRequired":%s},' "$(js "$PKG")" "$(num "$UPG")" "$(num "$SEC")" "$(js "$LAST_UPDATE")" "$(js "$AUTO")" "$REBOOT"
  printf '"Ssh":{"Active":%s,"PermitRootLogin":%s,"PasswordAuthentication":%s,"PermitEmptyPasswords":%s,"X11Forwarding":%s,"MaxAuthTries":%s,"Port":%s,"Ciphers":%s,"Macs":%s,"ClientAliveInterval":%s,"AllowUsers":%s,"AllowGroups":%s},' \
    "$(js "$SSH_ACTIVE")" "$(js "$(sshv permitrootlogin)")" "$(js "$(sshv passwordauthentication)")" "$(js "$(sshv permitemptypasswords)")" "$(js "$(sshv x11forwarding)")" "$(js "$(sshv maxauthtries)")" "$(js "$(sshv port)")" "$(js "$(sshv ciphers)")" "$(js "$(sshv macs)")" "$(js "$(sshv clientaliveinterval)")" "$(js "$(sshv allowusers)")" "$(js "$(sshv allowgroups)")"
  printf '"Firewall":{"Ufw":%s,"Firewalld":%s,"NftRules":%s,"IptablesRules":%s},' "$(js "$UFW")" "$(js "$FWD")" "$(num "$NFT")" "$(num "$IPT")"
  printf '"Security":{"SELinux":%s,"AppArmor":%s,"Auditd":%s,"Fail2ban":%s,"NtpSynchronized":%s,"Edr":%s,"Backup":%s,"EncryptedVolumes":%s},' "$(js "$SELINUX")" "$(js "$APPARMOR")" "$(js "$(svc_active auditd)")" "$(js "$(svc_active fail2ban)")" "$(js "$NTP_SYNC")" "$(js "$EDR")" "$(js "$BACKUP")" "$(num "$CRYPT")"
  printf '"Accounts":{"Uid0":%s,"LoginUsers":%s,"EmptyPasswords":%s,"SudoNoPassword":%s,"PassMaxDays":%s,"PassMinLength":%s,"ShadowReadable":%s},' "$(printf '%s\n' "$UID0" | jarr)" "$(printf '%s\n' "$LOGIN_USERS" | jarr)" "$(printf '%s\n' "$EMPTY_PW" | jarr)" "$(printf '%s\n' "$NOPASSWD" | jarr)" "$(num "$PASS_MAX")" "$(num "$PASS_MIN_LEN")" "$( [ -r /etc/shadow ] && echo true || echo false )"
  printf '"Kernel":{"IpForward":%s,"RandomizeVaSpace":%s,"AcceptRedirects":%s,"SendRedirects":%s,"TcpSyncookies":%s,"SuidDumpable":%s},' "$(num "$(sc net.ipv4.ip_forward)")" "$(num "$(sc kernel.randomize_va_space)")" "$(num "$(sc net.ipv4.conf.all.accept_redirects)")" "$(num "$(sc net.ipv4.conf.all.send_redirects)")" "$(num "$(sc net.ipv4.tcp_syncookies)")" "$(num "$(sc fs.suid_dumpable)")"
  printf '"Listening":%s,' "$(printf '%s\n' "$LISTEN" | jarr)"
  printf '"Disks":%s,' "$(printf '%s\n' "$DISKS" | jarr)"
  printf '"RiskyPackages":%s,' "$(printf '%s\n' "$RISKY" | jarr)"
  printf '"RunningServices":%s,' "$(printf '%s\n' "$RUNNING" | jarr)"
  printf '"Errors":[]'
  printf '}\n'
} > /tmp/server-review-$$.json

if [ "$OUTDIR" = "-" ]; then
  cat /tmp/server-review-$$.json
else
  mkdir -p "$OUTDIR" 2>/dev/null
  OUT="$OUTDIR/linux-${HOST}-$(date +%Y%m%d-%H%M).server-review.json"
  mv /tmp/server-review-$$.json "$OUT"
  echo "Server data written to $OUT"
fi
rm -f /tmp/server-review-$$.json
