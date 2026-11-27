#!/usr/bin/env bash
# CyberPatriot Guided Audit — Debian 12
# Read-only: does not install/remove packages or change system settings.
# Run: sudo bash goon.sh
# Findings are potential issues; compare them with the challenge instructions.

set -uo pipefail
export LC_ALL=C

NAME="${0##*/}"
STAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then REPORT_DIR=/root; else REPORT_DIR="${HOME:-/tmp}"; fi
REPORT="${REPORT_DIR}/cyberpatriot-audit-${STAMP}.txt"

if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'; RESET=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; RESET=''
fi

info()    { printf '%s[INFO]%s %s\n' "$BLUE" "$RESET" "$*"; }
ok()      { printf '%s[OK]%s %s\n' "$GREEN" "$RESET" "$*"; }
review()  { printf '%s[REVIEW]%s %s\n' "$YELLOW" "$RESET" "$*"; }
check()   { printf '%s[CHECK]%s %s\n' "$RED" "$RESET" "$*"; }
section() { printf '\n============================================================\n%s\n============================================================\n' "$1"; }
has()     { command -v "$1" >/dev/null 2>&1; }

case "${1:-}" in
    "")
        ;;
    -h|--help)
        cat <<EOF
$NAME — CyberPatriot guided, read-only audit

Usage:
  sudo bash $NAME
  bash $NAME

Checks common Linux security areas and writes a timestamped report.
It does NOT change settings, install software, delete accounts, or
decide which users/services/files are authorized. Run with sudo for
the most complete results.
EOF
        exit 0
        ;;
    *)
        printf 'Unknown argument: %s\nUse --help for usage.\n' "$1" >&2
        exit 2
        ;;
esac

if ! touch "$REPORT" 2>/dev/null; then
    REPORT="/tmp/cyberpatriot-audit-${STAMP}.txt"
    touch "$REPORT" || { echo "Cannot create report file." >&2; exit 1; }
fi
exec > >(tee -a "$REPORT") 2>&1

echo "CYBERPATRIOT GUIDED AUDIT"
echo "Started: $(date)"
echo "Report:  $REPORT"
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    review "Not running as root; some checks may be incomplete. Run: sudo bash $NAME"
else
    ok "Running with root privileges."
fi

# 1. System information
section "[1] SYSTEM INFORMATION"
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "Distribution: ${PRETTY_NAME:-unknown}"
    echo "ID: ${ID:-unknown} | Version: ${VERSION_ID:-unknown}"
else
    review "Cannot read /etc/os-release."
fi
echo "Hostname: $(hostname 2>/dev/null || echo unknown)"
echo "Kernel: $(uname -sr 2>/dev/null || echo unknown)"
echo "Architecture: $(uname -m 2>/dev/null || echo unknown)"
[[ -r /etc/debian_version ]] && { printf 'Debian version: '; cat /etc/debian_version; }
has apt-get && ok "APT detected." || review "APT not detected."

# 2. Accounts
section "[2] USER ACCOUNTS"
info "Local accounts (username, UID, GID, home, shell):"
if [[ -r /etc/passwd ]]; then
    awk -F: '{printf "  %-20s UID=%-6s GID=%-6s HOME=%-22s SHELL=%s\n",$1,$3,$4,$6,$7}' /etc/passwd
else
    review "Cannot read /etc/passwd."
fi

info "Accounts with UID 0:"
uid0_count=0
if [[ -r /etc/passwd ]]; then
    while IFS=: read -r user _ uid _; do
        if [[ "$uid" == 0 ]]; then echo "  $user (UID 0)"; ((uid0_count+=1)); fi
    done < /etc/passwd
fi
if (( uid0_count > 1 )); then
    check "Multiple UID 0 accounts found. Verify each is explicitly authorized."
elif (( uid0_count == 1 )); then
    ok "One UID 0 account found; confirm it is the expected root account."
else
    review "No UID 0 account found; investigate."
fi

info "Accounts with UID >= 1000 (review against authorized-user list):"
awk -F: '$3 >= 1000 && $1 != "nobody" {printf "  %-20s UID=%-6s HOME=%-22s SHELL=%s\n",$1,$3,$6,$7}' /etc/passwd 2>/dev/null || true
info "Accounts configured with nologin/false shells:"
awk -F: '$7 ~ /(nologin|false)$/ {print "  " $1 ": " $7}' /etc/passwd 2>/dev/null || true

info "Accounts with an empty password field:"
if [[ -r /etc/shadow ]]; then
    empty="$(awk -F: '$2 == "" {print $1}' /etc/shadow)"
    if [[ -n "$empty" ]]; then
        check "Empty password field found for:"
        while IFS= read -r user; do [[ -n "$user" ]] && echo "  $user"; done <<< "$empty"
        echo "  Investigate and verify account status; do not assume it is safe."
    else
        ok "No empty password fields found."
    fi
else
    review "Cannot read /etc/shadow; run with sudo for this check."
fi
echo "Human review: compare accounts with the challenge's authorized-user list. Do not delete unfamiliar accounts automatically."

# 3. Groups and sudo
section "[3] GROUPS AND ADMINISTRATIVE PRIVILEGES"
info "Sudo group:"
getent group sudo 2>/dev/null || echo "  No sudo group entry returned."
info "Other common administrative groups:"
for g in adm wheel; do getent group "$g" 2>/dev/null || true; done
info "Sudoers syntax:"
if has visudo; then visudo -c 2>&1 && ok "visudo validation passed." || check "visudo reported a configuration problem."
else review "visudo not installed."; fi
info "Potentially broad sudo rules (review each match):"
grep -nEi 'NOPASSWD|!authenticate|ALL[[:space:]]*=' /etc/sudoers 2>/dev/null || true
if [[ -d /etc/sudoers.d ]]; then
    grep -RniE 'NOPASSWD|!authenticate|ALL[[:space:]]*=' /etc/sudoers.d 2>/dev/null || true
fi
echo "A match is not automatically wrong; verify who is authorized to administer the system."

# 4. Password policy
section "[4] PASSWORD POLICY"
if [[ -r /etc/login.defs ]]; then
    info "Password-aging defaults:"
    grep -nE '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|ENCRYPT_METHOD)[[:space:]]' /etc/login.defs || true
fi
for f in /etc/pam.d/common-password /etc/pam.d/common-auth /etc/pam.d/common-account; do
    if [[ -r "$f" ]]; then
        info "$f (active, non-comment lines):"
        grep -nEv '^[[:space:]]*(#|$)' "$f" 2>/dev/null || true
    fi
done
echo "Review password-quality and lockout requirements. Do not edit PAM blindly; mistakes can prevent logins."
if has chage && [[ -r /etc/shadow ]]; then
    info "Password aging for UID >= 1000 accounts:"
    while IFS=: read -r user _ uid _; do
        if [[ "$uid" =~ ^[0-9]+$ ]] && (( uid >= 1000 )) && [[ "$user" != nobody ]]; then
            echo "  $user"
            chage -l "$user" 2>&1 | sed 's/^/    /'
        fi
    done < /etc/passwd
fi

# 5. SSH
section "[5] SSH CONFIGURATION"
if has sshd; then
    info "Effective SSH settings:"
    ssh_result="$(sshd -T 2>&1)"; ssh_rc=$?
    if (( ssh_rc == 0 )); then
        printf '%s\n' "$ssh_result" | grep -Ei '^(permitrootlogin|permitemptypasswords|passwordauthentication|pubkeyauthentication|maxauthtries|x11forwarding|allowusers|allowgroups|denyusers|denygroups)[[:space:]]' || true
    else
        review "Could not calculate effective SSH settings: $ssh_result"
    fi
    echo "If SSH is required, preserve the service; review its settings rather than disabling it."
elif has ssh; then
    review "SSH client found, but sshd was not found; SSH server may not be installed."
else
    info "OpenSSH tools not detected."
fi
if [[ -r /etc/ssh/sshd_config ]]; then
    info "Relevant explicit SSH settings and Include directives:"
    grep -RniE '^[[:space:]]*(Include|PermitRootLogin|PermitEmptyPasswords|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries|X11Forwarding|AllowUsers|AllowGroups|DenyUsers|DenyGroups)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true
fi

# 6. Firewall and network
section "[6] FIREWALL AND NETWORK"
if has ufw; then
    info "UFW status:"
    ufw status verbose 2>&1 || true
    ufw status 2>/dev/null | head -n 1 | grep -q 'Status: active' && ok "UFW reports active." || review "UFW does not report active; check challenge requirements."
else
    review "UFW is not installed. Do not install/enable a firewall until required ports are known."
fi
info "Listening TCP/UDP sockets:"
if has ss; then ss -tulpn 2>&1 || true; else review "ss command unavailable."; fi
info "Network interfaces:"
if has ip; then ip -brief address 2>&1 || true; else review "ip command unavailable."; fi
info "Selected network sysctl settings:"
if has sysctl; then
    sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.rp_filter 2>&1 || true
fi
echo "Identify each listening service and confirm which ports the challenge requires."

# 7. Services
section "[7] SERVICES"
if has systemctl; then
    info "Running services:"
    systemctl list-units --type=service --state=running --no-pager 2>&1 || true
    info "Enabled services:"
    systemctl list-unit-files --type=service --state=enabled --no-pager 2>&1 || true
    info "Failed services:"
    systemctl --failed --no-pager 2>&1 || true
else
    review "systemctl unavailable; system may not use systemd."
fi
echo "A running/enabled service is not automatically unnecessary. Identify it before changing anything."

# 8. Scheduled tasks
section "[8] SCHEDULED TASKS"
for p in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [[ -e "$p" ]]; then
        echo "$p"
        if [[ -f "$p" ]]; then sed -n '1,240p' "$p" | sed 's/^/  /'; else ls -la "$p" 2>/dev/null | sed 's/^/  /'; fi
    fi
done
if has crontab && [[ -r /etc/passwd ]]; then
    info "User crontabs:"
    while IFS=: read -r user _; do
        jobs="$(crontab -u "$user" -l 2>/dev/null || true)"
        if [[ -n "$jobs" ]]; then echo "  User: $user"; printf '%s\n' "$jobs" | sed 's/^/    /'; fi
    done < /etc/passwd
fi
if has systemctl; then
    info "Systemd timers:"
    systemctl list-timers --all --no-pager 2>&1 || true
fi
echo "Review unfamiliar jobs and timers; do not remove them before identifying their purpose."

# 9. Permissions
section "[9] IMPORTANT FILE PERMISSIONS"
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config; do
    if [[ -e "$f" ]]; then stat -c '  %A (%a) %U:%G %n' "$f" 2>&1 || true; else echo "  Not present: $f"; fi
done
stat -c '  %A (%a) %U:%G %n' /root 2>&1 || true
echo "Compare with expected Debian permissions and challenge requirements; avoid blanket chmod commands."

# 10. Host configuration
section "[10] HOSTS AND NAME RESOLUTION"
for f in /etc/hosts /etc/host.conf /etc/resolv.conf; do
    if [[ -r "$f" ]]; then echo "$f"; sed -n '1,200p' "$f" | sed 's/^/  /'; else echo "Cannot read/find $f"; fi
done
echo "Unexpected mappings/resolver settings deserve investigation but may be intentional."

# 11. Package state
section "[11] PACKAGE STATE AND INTEGRITY"
if has dpkg; then
    info "dpkg package audit:"
    dpkg --audit 2>&1 || true
    info "Package verification differences:"
    verify="$(dpkg --verify 2>&1)"; verify_rc=$?
    if [[ -n "$verify" ]]; then printf '%s\n' "$verify"; review "Review these differences; configuration changes may be expected."
    elif (( verify_rc == 0 )); then ok "No dpkg verification differences reported."
    else review "dpkg verification did not complete cleanly: $verify"; fi
    info "Common server packages installed (presence alone is not proof of a problem):"
    dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null | grep -Ei '^(openssh-server|apache2|nginx|vsftpd|proftpd|pure-ftpd|samba|telnetd|xinetd|inetutils-inetd|postfix|dovecot|mysql-server|mariadb-server|postgresql|isc-dhcp-server|bind9)[[:space:]]' || true
else
    review "dpkg unavailable."
fi

# 12. Home directory files
section "[12] FILES TO REVIEW IN HOME DIRECTORIES"
if [[ -d /home ]]; then
    info "Media/archive files found (review only):"
    find /home -type f \( \
        -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.wav' -o -iname '*.mov' -o \
        -iname '*.avi' -o -iname '*.mkv' -o -iname '*.jpg' -o -iname '*.jpeg' -o \
        -iname '*.png' -o -iname '*.gif' -o -iname '*.zip' -o -iname '*.7z' -o \
        -iname '*.tar' -o -iname '*.gz' \
    \) -print 2>/dev/null || true
else
    info "/home does not exist."
fi
echo "These files are not inherently prohibited. Remove nothing unless the challenge rules say so."

# 13. Kernel settings and updates
section "[13] KERNEL SECURITY AND UPDATES"
if has sysctl; then
    sysctl kernel.randomize_va_space kernel.dmesg_restrict kernel.kptr_restrict kernel.sysrq net.ipv4.tcp_syncookies 2>&1 || true
fi
info "Kernel command line:"
cat /proc/cmdline 2>/dev/null || true
info "Automatic-update related services/timers/packages:"
if has systemctl; then systemctl list-unit-files --no-pager 2>/dev/null | grep -Ei 'apt-daily|unattended|packagekit' || true; fi
if has dpkg-query; then dpkg-query -W -f='${binary:Package} ${Version}\n' 2>/dev/null | grep -Ei '^(unattended-upgrades|apt-listchanges|needrestart)[[:space:]]' || true; fi
echo "Check the challenge's update requirements before changing update services or settings."

# 14. Actionable findings from observed Debian 12 image patterns
section "[14] AUTOMATED FLAGS AND SUGGESTED HUMAN ACTIONS"
echo "These checks identify conditions worth reviewing; they do not prove a scoring requirement."

# /etc/shadow should not be readable by everyone or writable by its group.
if [[ -e /etc/shadow ]]; then
    shadow_mode="$(stat -c '%a' /etc/shadow 2>/dev/null || echo unknown)"
    shadow_owner="$(stat -c '%U:%G' /etc/shadow 2>/dev/null || echo unknown)"
    if [[ "$shadow_mode" =~ ^[0-7]{3,4}$ ]]; then
        # Evaluate permission bits without assuming a single distro-specific mode.
        shadow_num=$((8#$shadow_mode))
        if (( (shadow_num & 0004) != 0 || (shadow_num & 0020) != 0 || (shadow_num & 0002) != 0 )); then
            check "/etc/shadow has overly broad permissions ($shadow_mode, $shadow_owner)."
            echo "  Review the challenge requirements. Common Debian target: sudo chmod 640 /etc/shadow"
            echo "  Owner/group are currently: $shadow_owner; verify before changing ownership."
        else
            ok "/etc/shadow does not appear world-readable or group/world-writable ($shadow_mode, $shadow_owner)."
        fi
    else
        review "Could not parse /etc/shadow permissions: $shadow_mode"
    fi
fi

# Kernel settings: present candidate values, not automatic fixes.
if has sysctl; then
    kptr="$(sysctl -n kernel.kptr_restrict 2>/dev/null || true)"
    syncookies="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || true)"
    if [[ "$kptr" == "0" ]]; then
        review "kernel.kptr_restrict=0: kernel pointer restriction is disabled."
        echo "  If the challenge expects hardening, investigate: sudo sysctl -w kernel.kptr_restrict=1"
        echo "  Persist only after confirmation, e.g. a dedicated file in /etc/sysctl.d/."
    elif [[ -n "$kptr" ]]; then ok "kernel.kptr_restrict=$kptr"; fi
    if [[ "$syncookies" == "0" ]]; then
        review "net.ipv4.tcp_syncookies=0: TCP SYN cookies are disabled."
        echo "  If required by the challenge, investigate: sudo sysctl -w net.ipv4.tcp_syncookies=1"
        echo "  Persist only after confirmation, e.g. a dedicated file in /etc/sysctl.d/."
    elif [[ -n "$syncookies" ]]; then ok "net.ipv4.tcp_syncookies=$syncookies"; fi
fi

# FTP and web services need image-specific review; do not remove automatically.
for unit in vsftpd apache2 nginx; do
    if has systemctl && systemctl list-unit-files "${unit}.service" --no-legend 2>/dev/null | grep -q "${unit}.service"; then
        if systemctl is-active --quiet "$unit"; then
            review "$unit is installed and active. Confirm it is required by the challenge."
        else
            info "$unit is installed but not currently active; confirm whether it is required or prohibited."
        fi
    fi
done

# Flag MP3s separately, including items still in Trash.
if [[ -d /home ]]; then
    mp3s="$(find /home -type f -iname '*.mp3' -print 2>/dev/null || true)"
    if [[ -n "$mp3s" ]]; then
        review "MP3 files exist under /home; check whether the challenge explicitly prohibits them:"
        printf '%s\n' "$mp3s" | sed 's/^/  /'
        echo "  Trash is not the same as secure deletion; do not remove unless instructed."
    else
        ok "No MP3 files found under /home."
    fi
fi

# Explain dpkg verification's config-file marker.
if has dpkg; then
    verify_config="$(dpkg --verify 2>/dev/null | awk '$2 == "c" {print}')"
    if [[ -n "$verify_config" ]]; then
        review "Package-managed configuration files differ from package checksums:"
        printf '%s\n' "$verify_config" | sed 's/^/  /'
        echo "  This can be normal after configuration changes; inspect each file's contents and history."
    fi
fi

# 15. Human checklist
section "[15] HUMAN REVIEW CHECKLIST"
cat <<'EOF'
Use the challenge instructions, if available, to determine:

[ ] Which users are authorized, required, or prohibited?
[ ] Which groups must users belong to?
[ ] Which software must remain installed?
[ ] Which software is explicitly prohibited?
[ ] Which services must remain running?
[ ] Which ports must remain reachable?
[ ] Are there prohibited files or media types?
[ ] What password-aging, complexity, and lockout settings are required?
[ ] Are SSH, FTP, web, email, or other services required?
[ ] Are there forensic questions to answer rather than "fix"?

Generic security advice is not a substitute for the image's requirements.
EOF

section "AUDIT COMPLETE"
echo "Finished: $(date)"
echo "Report saved to: $REPORT"
ok "Read-only audit finished. No system settings were changed."
info "Review every [REVIEW] and [CHECK] item against the challenge requirements."
info "To read the saved report without terminal scrolling: sudo less '$REPORT'"
info "To search findings in the report: sudo grep -nE '\[(CHECK|REVIEW)\]' '$REPORT'"
