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