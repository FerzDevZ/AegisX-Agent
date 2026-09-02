#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║          🛡️  Aegisx-Agent Installer v0.1.0                 ║
# ║     Autonomous AI-Powered Security Scanner                 ║
# ║     https://github.com/FerzDevZ/AegisX-Agent               ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

# ─── Colors & Symbols ──────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

CHECK="✅"
CROSS="❌"
WARN="⚠️"
INFO="ℹ️"
SHIELD="🛡️"
ROCKET="🚀"
GEAR="⚙️"
LOCK="🔒"
STAR="⭐"
BOLT="⚡"

# ─── Config ────────────────────────────────────────────────────
REPO_URL="https://github.com/FerzDevZ/AegisX-Agent.git"
INSTALL_DIR="${AEGISX_INSTALL_DIR:-$HOME/.aegisx}"
VENV_DIR="${INSTALL_DIR}/.venv"
BIN_DIR="${INSTALL_DIR}/bin"
PYTHON_MIN_VERSION="3.12"
AEGISX_VERSION="0.1.1"

# ─── Helpers ───────────────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'

    _          _ _ _   _   _____                     _
   / \   _ __ (_) | |_(_)_|__  /___ _ __ ___  _ __ (_)_ __   __ _
  / _ \ | '__| | | __| | |/ / / _ \ '__/ _ \| '_ \| | '_ \ / _` |
 / ___ \| |   | | |_| |   < /  __/ | | (_) | | | | | | | | | (_| |
/_/   \_\_|   |_|\__|_|_|_\\___|_|  \___/|_| |_|_|_| |_|\__, |
                                                          |___/
BANNER
    echo -e "${NC}"
    echo -e "  ${GRAY}v${AEGISX_VERSION} — Autonomous AI-Powered Security Scanner${NC}"
    echo -e "  ${GRAY}https://github.com/FerzDevZ/AegisX-Agent${NC}"
    echo ""
}

log_info()    { echo -e "  ${INFO}  ${CYAN}$1${NC}"; }
log_success() { echo -e "  ${CHECK}  ${GREEN}$1${NC}"; }
log_warn()    { echo -e "  ${WARN}  ${YELLOW}$1${NC}"; }
log_error()   { echo -e "  ${CROSS}  ${RED}$1${NC}"; }
log_step()    { echo -e "\n${MAGENTA}━━━ $1 ━━━${NC}"; }

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while kill -0 "$pid" 2>/dev/null; do
        for (( i=0; i<${#spinstr}; i++ )); do
            printf "\r  ${GRAY}  %s  Loading...${NC}" "${spinstr:$i:1}"
            sleep $delay
        done
    done
    printf "\r\033[K"
}

command_exists() {
    command -v "$1" &>/dev/null
}

# ─── System Detection ──────────────────────────────────────────
detect_system() {
    log_step "🔍 System Detection"

    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux*)   OS_NAME="Linux";;
        Darwin*)  OS_NAME="macOS";;
        MINGW*|MSYS*|CYGWIN*) OS_NAME="Windows";;
        *)        OS_NAME="Unknown";;
    esac

    log_info "OS:       ${WHITE}${OS_NAME}$(uname -r)${NC}"
    log_info "Arch:     ${WHITE}${ARCH}${NC}"
    log_info "Shell:    ${WHITE}${SHELL}${NC}"
    log_info "User:     ${WHITE}$(whoami)${NC}"
    echo ""
}

# ─── Dependency Checks ─────────────────────────────────────────
check_dependencies() {
    log_step "🔍 Checking Dependencies"

    local missing=()

    # Python 3.12+
    if command_exists python3; then
        PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 12 ]; then
            log_success "Python:   ${WHITE}${PY_VERSION}${NC}"
        else
            log_warn "Python:   ${WHITE}${PY_VERSION}${NC} (need 3.12+)"
            missing+=("python3.12")
        fi
    else
        log_error "Python:   ${RED}not found${NC}"
        missing+=("python3")
    fi

    # pip
    if command_exists pip3; then
        log_success "pip:      ${WHITE}$(pip3 --version 2>/dev/null | head -1)${NC}"
    elif command_exists pip; then
        log_success "pip:      ${WHITE}$(pip --version 2>/dev/null | head -1)${NC}"
    else
        log_error "pip:      ${RED}not found${NC}"
        missing+=("pip")
    fi

    # git
    if command_exists git; then
        log_success "git:      ${WHITE}$(git --version)${NC}"
    else
        log_error "git:      ${RED}not found${NC}"
        missing+=("git")
    fi

    # curl
    if command_exists curl; then
        log_success "curl:     ${WHITE}$(curl --version 2>/dev/null | head -1 | awk '{print $2}')${NC}"
    else
        log_warn "curl:     ${YELLOW}not found (optional)${NC}"
    fi

    # Docker (optional)
    if command_exists docker; then
        log_success "Docker:   ${WHITE}$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')${NC}"
        DOCKER_AVAILABLE=true
    else
        log_warn "Docker:   ${YELLOW}not found (optional, needed for sandbox)${NC}"
        DOCKER_AVAILABLE=false
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo ""
        log_error "Missing required dependencies: ${missing[*]}"
        echo ""
        install_dependencies "${missing[@]}"
    fi
}

install_dependencies() {
    log_step "📦 Installing Dependencies"

    for dep in "$@"; do
        case "$dep" in
            python3*|python3.12)
                if command_exists apt-get; then
                    log_info "Installing Python via apt..."
                    sudo apt-get update -qq
                    sudo apt-get install -y -qq python3.12 python3.12-venv python3-pip
                elif command_exists brew; then
                    log_info "Installing Python via Homebrew..."
                    brew install python@3.12
                elif command_exists pacman; then
                    log_info "Installing Python via pacman..."
                    sudo pacman -S --noconfirm python python-pip
                elif command_exists dnf; then
                    log_info "Installing Python via dnf..."
                    sudo dnf install -y python3.12
                else
                    log_error "Cannot auto-install Python. Please install Python 3.12+ manually."
                    exit 1
                fi
                ;;
            pip)
                log_info "Installing pip..."
                if command_exists apt-get; then
                    sudo apt-get install -y -qq python3-pip
                elif command_exists brew; then
                    log_info "pip usually comes with brew python"
                fi
                ;;
            git)
                if command_exists apt-get; then
                    sudo apt-get install -y -qq git
                elif command_exists brew; then
                    brew install git
                elif command_exists pacman; then
                    sudo pacman -S --noconfirm git
                fi
                ;;
        esac
    done
    log_success "Dependencies installed!"
}

# ─── Clone / Update Repository ─────────────────────────────────
setup_repository() {
    log_step "📥 Setting Up Repository"

    if [ -d "${INSTALL_DIR}/.git" ]; then
        log_info "Repository exists, pulling latest..."
        # Use subshell to avoid cd issues
        (cd "${INSTALL_DIR}" && git pull --ff-only origin main 2>/dev/null) || {
            log_warn "Pull failed, using existing version"
        }
    else
        log_info "Cloning Aegisx-Agent..."
        rm -rf "${INSTALL_DIR}"
        git clone --depth 1 "${REPO_URL}" "${INSTALL_DIR}" 2>/dev/null
    fi

    log_success "Repository ready at ${WHITE}${INSTALL_DIR}${NC}"
}

# ─── Python Virtual Environment ────────────────────────────────
setup_venv() {
    log_step "🐍 Setting Up Python Environment"

    if [ -d "${VENV_DIR}" ]; then
        log_info "Virtual environment exists, checking..."
        # Check if it's valid
        if [ -f "${VENV_DIR}/bin/activate" ]; then
            log_success "Virtual environment is valid"
        else
            log_warn "Virtual environment is broken, recreating..."
            rm -rf "${VENV_DIR}"
            python3 -m venv "${VENV_DIR}"
        fi
    else
        log_info "Creating virtual environment..."
        python3 -m venv "${VENV_DIR}"
    fi

    log_success "Virtual environment: ${WHITE}${VENV_DIR}${NC}"
}

# ─── Install Package ───────────────────────────────────────────
install_package() {
    log_step "📦 Installing Aegisx-Agent"

    source "${VENV_DIR}/bin/activate"

    log_info "Upgrading pip..."
    pip install --upgrade pip -q 2>/dev/null

    log_info "Installing Aegisx-Agent and dependencies..."
    pip install -e ".[dev]" -q 2>/dev/null

    # Create bin symlink for easy access
    mkdir -p "${BIN_DIR}"
    ln -sf "${VENV_DIR}/bin/aegisx" "${BIN_DIR}/aegisx"

    log_success "Aegisx-Agent ${WHITE}v${AEGISX_VERSION}${NC} installed!"
    deactivate 2>/dev/null || true
}

# ─── Setup Shell Profile ───────────────────────────────────────
setup_shell_profile() {
    log_step "🐚 Setting Up Shell"

    # Detect shell config file
    SHELL_CONFIG=""
    if [ -n "${BASH_VERSION:-}" ]; then
        SHELL_CONFIG="$HOME/.bashrc"
    elif [ -n "${ZSH_VERSION:-}" ]; then
        SHELL_CONFIG="$HOME/.zshrc"
    elif [ -f "$HOME/.profile" ]; then
        SHELL_CONFIG="$HOME/.profile"
    fi

    if [ -n "${SHELL_CONFIG}" ]; then
        ALIAS_LINE="alias aegisx='${VENV_DIR}/bin/aegisx'"
        VENV_ACTIVATE="source ${VENV_DIR}/bin/activate"

        # Remove old aliases first
        sed -i '/# ─── Aegisx-Agent/,/aegisx/d' "${SHELL_CONFIG}" 2>/dev/null || true

        # Check if alias already exists
        if ! grep -q "alias aegisx=" "${SHELL_CONFIG}" 2>/dev/null; then
            log_info "Adding alias to ${SHELL_CONFIG}..."
            cat >> "${SHELL_CONFIG}" << EOF

# ─── Aegisx-Agent ───
${ALIAS_LINE}
export PATH="${BIN_DIR}:\$PATH"
EOF
            log_success "Shell alias added!"
        else
            log_info "Alias already exists in ${SHELL_CONFIG}"
        fi

        echo ""
        log_info "Run this to use without restarting your shell:"
        echo -e "  ${WHITE}${ALIAS_LINE}${NC}"
    fi
}

# ─── Create Default Config ─────────────────────────────────────
setup_config() {
    log_step "⚙️  Setting Up Configuration"

    ENV_FILE="${INSTALL_DIR}/.env"

    if [ -f "${ENV_FILE}" ]; then
        log_info ".env file exists, skipping"
    else
        cat > "${ENV_FILE}" << 'ENVEOF'
# ╔══════════════════════════════════════════════════════════════╗
# ║          Aegisx-Agent Configuration                        ║
# ╚══════════════════════════════════════════════════════════════╝

# Scan Settings
AEGISX_SCAN_MODE=quick
AEGISX_MAX_DEPTH=3
AEGISX_TIMEOUT_SECONDS=30
AEGISX_MAX_REQUESTS_PER_SECOND=10.0

# User Agent
AEGISX_USER_AGENT=AegisxAgent/0.1.0 (Security Scanner)

# Scanners to enable
AEGISX_ENABLED_SCANNERS=["web_scanner","secret_scanner","config_scanner","dependency_scanner"]

# Exploit Verification (requires explicit consent)
AEGISX_EXPLOIT_VERIFICATION=false

# Sandbox (Docker-based exploit isolation)
AEGISX_SANDBOX_ENABLED=true
AEGISX_SANDBOX_IMAGE=aegisx-sandbox:latest

# Reporting
AEGISX_REPORT_FORMAT=markdown
AEGISX_REPORT_OUTPUT=reports/

# Logging
AEGISX_LOG_LEVEL=INFO
AEGISX_VERBOSE=false

# Target Authentication (optional)
# AEGISX_AUTH_TOKEN=your-token-here
# AEGISX_SCOPE=["example.com","api.example.com"]
ENVEOF
        log_success "Configuration created at ${WHITE}${ENV_FILE}${NC}"
    fi
}

# ─── Create Reports Directory ──────────────────────────────────
setup_directories() {
    log_step "📁 Creating Directories"

    mkdir -p "${INSTALL_DIR}/reports"
    mkdir -p "${INSTALL_DIR}/plugins"
    mkdir -p "${INSTALL_DIR}/docs"

    log_success "Directories ready"
}

# ─── Verify Installation ───────────────────────────────────────
verify_installation() {
    log_step "✅ Verifying Installation"

    source "${VENV_DIR}/bin/activate"

    # Test aegisx command
    if "${VENV_DIR}/bin/aegisx" info &>/dev/null; then
        log_success "CLI works!"
    else
        log_error "CLI failed verification"
        return 1
    fi

    # Show plugins
    log_info "Installed plugins:"
    "${VENV_DIR}/bin/aegisx" plugins 2>/dev/null | tail -n +2 | head -20

    deactivate 2>/dev/null || true
}

# ─── Print Summary ─────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         🛡️  Aegisx-Agent Installed Successfully!           ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLT} ${WHITE}Quick Start:${NC}"
    echo ""
    echo -e "  ${CYAN}# Quick scan${NC}"
    echo -e "  aegisx scan https://example.com"
    echo ""
    echo -e "  ${CYAN}# Full scan with all scanners${NC}"
    echo -e "  aegisx scan https://example.com --mode full --report all"
    echo ""
    echo -e "  ${CYAN}# Full pentest (with exploit verification)${NC}"
    echo -e "  aegisx pentest https://example.com"
    echo ""
    echo -e "  ${CYAN}# Recon only${NC}"
    echo -e "  aegisx recon https://example.com"
    echo ""
    echo -e "  ${CYAN}# List plugins${NC}"
    echo -e "  aegisx plugins"
    echo ""
    echo -e "  ${CYAN}# Version info${NC}"
    echo -e "  aegisx info"
    echo ""
    echo -e "  ${STAR} ${WHITE}Installation Path:${NC} ${GRAY}${INSTALL_DIR}${NC}"
    echo -e "  ${STAR} ${WHITE}Virtual Env:${NC}       ${GRAY}${VENV_DIR}${NC}"
    echo -e "  ${STAR} ${WHITE}Binary:${NC}            ${GRAY}${VENV_DIR}/bin/aegisx${NC}"
    echo -e "  ${STAR} ${WHITE}Config:${NC}            ${GRAY}${INSTALL_DIR}/.env${NC}"
    echo -e "  ${STAR} ${WHITE}Reports:${NC}           ${GRAY}${INSTALL_DIR}/reports/${NC}"
    echo -e "  ${STAR} ${WHITE}Plugins:${NC}           ${GRAY}${INSTALL_DIR}/plugins/${NC}"
    echo ""
    echo -e "  ${GRAY}Docs: https://github.com/FerzDevZ/AegisX-Agent${NC}"
    echo -e "  ${GRAY}License: MIT${NC}"
    echo ""
}

# ─── Uninstall ─────────────────────────────────────────────────
uninstall() {
    echo -e "${RED}"
    cat << 'EOF'
  ╔══════════════════════════════════════════════════════════╗
  ║        ⚠️  UNINSTALL Aegisx-Agent                       ║
  ╚══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    read -p "  Are you sure you want to uninstall? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Removing ${INSTALL_DIR}..."
        rm -rf "${INSTALL_DIR}"

        # Remove alias from shell config
        for config in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
            if [ -f "$config" ]; then
                sed -i '/# ─── Aegisx-Agent/,/aegisx/d' "$config" 2>/dev/null || true
            fi
        done

        log_success "Aegisx-Agent uninstalled."
    else
        log_info "Uninstall cancelled."
    fi
}

# ─── Main ──────────────────────────────────────────────────────
main() {
    print_banner

    # Handle arguments
    case "${1:-install}" in
        --uninstall|uninstall)
            uninstall
            exit 0
            ;;
        --help|-h|help)
            echo "  Usage: ./install.sh [command]"
            echo ""
            echo "  Commands:"
            echo "    install      Install Aegisx-Agent (default)"
            echo "    uninstall    Remove Aegisx-Agent"
            echo "    --help       Show this help"
            echo ""
            echo "  Environment Variables:"
            echo "    AEGISX_INSTALL_DIR    Custom install directory (default: ~/.aegisx)"
            echo ""
            exit 0
            ;;
        install|"")
            # Normal install flow
            ;;
        *)
            log_error "Unknown command: $1"
            echo "  Run './install.sh --help' for usage"
            exit 1
            ;;
    esac

    detect_system
    check_dependencies
    setup_repository
    setup_venv
    install_package
    setup_directories
    setup_config
    setup_shell_profile
    verify_installation
    print_summary
}

main "$@"
