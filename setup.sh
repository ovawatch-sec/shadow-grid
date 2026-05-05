#!/usr/bin/env bash
# setup.sh — Install all Bug-Ovawatch dependencies
# Run as a normal user (not root). sudo is invoked only where needed.
set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
ORANGE='\033[1;33m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${ORANGE}[!]${RESET} $*"; }
error() { echo -e "${RED}[-]${RESET} $*"; }

# ── Go check ────────────────────────────────────────────
if ! command -v go &>/dev/null; then
    error "Go is not installed. Download from https://go.dev/dl/ and re-run."
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
info "Go detected: $GO_VERSION"

GOBIN=$(go env GOPATH)/bin
export PATH="$PATH:$GOBIN"

# ── Go tools ────────────────────────────────────────────
GO_TOOLS=(
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/owasp-amass/amass/v4/...@master"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
)

info "Installing Go tools into $GOBIN..."
for pkg in "${GO_TOOLS[@]}"; do
    name=$(basename "$(echo "$pkg" | cut -d@ -f1)")
    info "  $name"
    go install "$pkg" 2>/dev/null || warn "  Failed to install $name — check manually"
done

# ── System tools ────────────────────────────────────────
info "Installing system packages..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y dnsutils whois whatweb python3-pip 2>/dev/null
elif command -v brew &>/dev/null; then
    brew install bind whois whatweb python3 2>/dev/null
else
    warn "Unknown package manager — install dnsutils, whois, whatweb manually"
fi

# ── Python deps ─────────────────────────────────────────
info "Installing Python dependencies..."
pip3 install -r requirements.txt --quiet

# ── Update nuclei templates ──────────────────────────────
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true
fi

# ── PATH reminder ────────────────────────────────────────
echo ""
info "Setup complete!"
warn "Make sure Go binaries are in your PATH:"
warn "  export PATH=\$PATH:\$(go env GOPATH)/bin"
warn "Add that line to your ~/.bashrc or ~/.zshrc"
