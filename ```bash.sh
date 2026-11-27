```bash
#!/bin/bash

# ==========================================
# Debian / Ubuntu / Linux Mint
# System Update & Security Setup
# ==========================================

set -Eeuo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check root
if [[ $EUID -ne 0 ]]; then
    error "Run this script with sudo."
    exit 1
fi

# Check distribution
if [[ ! -f /etc/os-release ]]; then
    error "Cannot identify Linux distribution."
    exit 1
fi

source /etc/os-release

# Check APT availability
if ! command -v apt-get &>/dev/null; then
    error "This script requires APT."
    exit 1
fi

echo "=========================================="
echo "       DEBIAN FAMILY SECURITY SETUP"
echo "=========================================="

info "Distribution: $PRETTY_NAME"

# 1. Update system
info "Updating package repositories..."

apt-get update

info "Upgrading installed packages..."

apt-get upgrade -y

apt-get autoremove -y

success "System updated!"

# 2. Install UFW
info "Installing UFW..."

apt-get install -y ufw

# Configure firewall
info "Configuring firewall..."

ufw default deny incoming
ufw default allow outgoing

# Enable firewall
ufw --force enable

success "Firewall configured!"

# 3. Install security tools
info "Installing security tools..."

TOOLS=(
    fail2ban
    clamav
    clamav-daemon
    rkhunter
    chkrootkit
    lynis
    auditd
    nmap
    wireshark
    tcpdump
    net-tools
    dnsutils
    whois
)

apt-get install -y "${TOOLS[@]}"

success "Security tools installed!"

# 4. Update ClamAV definitions
info "Updating ClamAV definitions..."

if command -v freshclam &>/dev/null; then
    freshclam || info "ClamAV definitions could not be updated automatically."
fi

# 5. Display results
echo ""
echo "=========================================="
echo "             SYSTEM STATUS"
echo "=========================================="

info "Firewall status:"
ufw status verbose

# ==========================================
# CYBERPATRIOT SYSTEM AUDIT
# ==========================================

REPORT="/root/cyberpatriot-audit-$(date +%F-%H%M%S).txt"

echo "Starting CyberPatriot audit..."

{
    echo "================================"
    echo "       SYSTEM AUDIT"
    echo "================================"

    # 1. USER ACCOUNTS
    echo ""
    echo "[1] USER ACCOUNTS"

    cat /etc/passwd

    echo ""
    echo "UID 0 ACCOUNTS:"
    awk -F: '$3 == 0 {print $1, $3}' /etc/passwd

    # 2. SUDO PRIVILEGES
    echo ""
    echo "[2] SUDO PRIVILEGES"

    getent group sudo || true

    echo ""
    echo "Checking sudoers configuration..."

    visudo -c 2>&1 || true

    grep -RniE 'NOPASSWD|!authenticate' \
        /etc/sudoers /etc/sudoers.d 2>/dev/null || true

    # 3. PASSWORD POLICY
    echo ""
    echo "[3] PASSWORD POLICY"

    grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' \
        /etc/login.defs || true

    echo ""
    echo "PAM PASSWORD CONFIGURATION:"

    grep -vE '^[[:space:]]*(#|$)' \
        /etc/pam.d/common-password || true

    # 4. NETWORK CONNECTIONS
    echo ""
    echo "[4] LISTENING PORTS"

    ss -tulpn || true

    echo ""
    echo "FIREWALL STATUS:"

    ufw status verbose || true

    # 5. SSH SECURITY
    echo ""
    echo "[5] SSH CONFIGURATION"

    if command -v sshd >/dev/null 2>&1; then
        sshd -T 2>/dev/null | grep -Ei \
            'permitrootlogin|permitemptypasswords|maxauthtries|passwordauthentication' \
            || true
    else
        echo "OpenSSH server not installed."
    fi

    # 6. RUNNING SERVICES
    echo ""
    echo "[6] RUNNING SERVICES"

    systemctl list-units --type=service --state=running \
        --no-pager || true

    # 7. CRON JOBS
    echo ""
    echo "[7] CRON CONFIGURATION"

    ls -la /etc/cron* 2>/dev/null || true

    cat /etc/crontab 2>/dev/null || true

    # 8. IMPORTANT FILE PERMISSIONS
    echo ""
    echo "[8] FILE PERMISSIONS"

    stat /etc/passwd /etc/shadow /etc/group \
        /etc/gshadow /root 2>/dev/null || true

    # 9. HOST CONFIGURATION
    echo ""
    echo "[9] HOST CONFIGURATION"

    cat /etc/hosts
    cat /etc/host.conf 2>/dev/null || true

    # 10. PACKAGE INTEGRITY
    echo ""
    echo "[10] PACKAGE INTEGRITY"

    dpkg --audit || true

    if command -v debsums >/dev/null 2>&1; then
        debsums -c || true
    else
        echo "debsums is not installed."
    fi

    # 11. SUSPICIOUS MEDIA
    echo ""
    echo "[11] MEDIA FILES IN HOME DIRECTORIES"

    find /home -type f \( \
        -iname "*.mp3" -o \
        -iname "*.mp4" -o \
        -iname "*.wav" -o \
        -iname "*.mov" -o \
        -iname "*.jpg" -o \
        -iname "*.png" \
    \) -print 2>/dev/null || true

    # 12. KERNEL SECURITY
    echo ""
    echo "[12] KERNEL SECURITY"

    sysctl kernel.randomize_va_space \
        kernel.dmesg_restrict \
        kernel.kptr_restrict \
        kernel.sysrq \
        net.ipv4.ip_forward 2>/dev/null || true

    echo ""
    echo "================================"
    echo "          AUDIT COMPLETE"
    echo "================================"

} | tee "$REPORT"

echo ""
echo "Audit saved to: $REPORT"

info "Installed security tools:"

for tool in nmap tcpdump lynis clamscan fail2ban-client; do
    if command -v "$tool" &>/dev/null; then
        echo "  [INSTALLED] $tool"
    else
        echo "  [MISSING] $tool"
    fi
done

echo ""
success "Security setup completed!"
echo "=========================================="
```