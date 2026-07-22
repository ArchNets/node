#!/usr/bin/env bash
#
# ==============================================================================
#  archnets node installer
#
#  Usage:
#    install.sh [version] [--api-host URL] [--server-id ID] [--secret-key KEY]
#
#  Examples:
#    install.sh                          # install latest release, interactive config
#    install.sh v1.1.51                  # install a specific version
#    install.sh --api-host https://p.example.com --server-id 1 --secret-key abc
# ==============================================================================

set -o pipefail

# ------------------------------------------------------------------------------
#  Constants
# ------------------------------------------------------------------------------
readonly REPO="archnets/node"
readonly INSTALL_DIR="/usr/local/archnets"
readonly CONFIG_DIR="/etc/archnets"
readonly SERVICE_NAME="archnets"
readonly MGMT_SCRIPT_URL="https://raw.githubusercontent.com/archnets/node/master/scripts/node.sh"
readonly AWG_MODULE_REPO="https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git"
readonly AWG_TOOLS_REPO="https://github.com/amnezia-vpn/amneziawg-tools.git"
readonly AWG_PPA="ppa:amnezia/ppa"

CUR_DIR="$(pwd)"

# ------------------------------------------------------------------------------
#  UI helpers
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; PLAIN=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; DIM=""; PLAIN=""
fi

info() { echo "${CYAN}[i]${PLAIN} $*"; }
ok()   { echo "${GREEN}[+]${PLAIN} $*"; }
warn() { echo "${YELLOW}[!]${PLAIN} $*"; }
err()  { echo "${RED}[x]${PLAIN} $*" >&2; }
die()  { err "$*"; exit 1; }

STEP_NO=0
step() {
    STEP_NO=$((STEP_NO + 1))
    echo ""
    echo "${BOLD}${CYAN}── ${STEP_NO}. $* ──${PLAIN}"
}

banner() {
    echo "${BOLD}${GREEN}"
    cat <<'EOF'
  ┌──────────────────────────────────────────────┐
  │           archnets node installer            │
  └──────────────────────────────────────────────┘
EOF
    echo "${PLAIN}"
}

# ------------------------------------------------------------------------------
#  Argument parsing
# ------------------------------------------------------------------------------
VERSION_ARG=""
API_HOST_ARG=""
SERVER_ID_ARG=""
SECRET_KEY_ARG=""

usage() {
    cat <<EOF
Usage: $0 [version] [options]

Options:
  --api-host URL     Panel API address (e.g. https://example.com/)
  --server-id ID     Server unique identifier
  --secret-key KEY   Secret key used to verify request legitimacy
  -h, --help         Show this help

When all three options are provided, the config file is generated
non-interactively.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --api-host)   API_HOST_ARG="${2:-}";   shift 2 ;;
            --server-id)  SERVER_ID_ARG="${2:-}";  shift 2 ;;
            --secret-key) SECRET_KEY_ARG="${2:-}"; shift 2 ;;
            -h|--help)    usage; exit 0 ;;
            --*)          die "Unknown parameter: $1 (see --help)" ;;
            *)
                # First positional argument is treated as the version
                [[ -z "$VERSION_ARG" ]] && VERSION_ARG="$1"
                shift ;;
        esac
    done
}

# ------------------------------------------------------------------------------
#  Environment detection
# ------------------------------------------------------------------------------
RELEASE=""
OS_VERSION=""
OS_CODENAME=""
ARCH=""

require_root() {
    [[ $EUID -eq 0 ]] || die "You must run this script as root!"
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        local id="${ID,,}" like="${ID_LIKE,,}"
        case "$id" in
            ubuntu)                              RELEASE="ubuntu" ;;
            debian|raspbian)                     RELEASE="debian" ;;
            centos|rhel|rocky|almalinux|ol|fedora) RELEASE="centos" ;;
            alpine)                              RELEASE="alpine" ;;
            arch|archarm|manjaro)                RELEASE="arch" ;;
            *)
                case " $like " in
                    *ubuntu*)                RELEASE="ubuntu" ;;
                    *debian*)                RELEASE="debian" ;;
                    *rhel*|*fedora*|*centos*) RELEASE="centos" ;;
                    *arch*)                  RELEASE="arch" ;;
                esac ;;
        esac
        OS_VERSION="${VERSION_ID%%.*}"
        OS_CODENAME="${VERSION_CODENAME:-}"
    fi

    # Legacy fallbacks for systems without /etc/os-release
    if [[ -z "$RELEASE" ]]; then
        if [[ -f /etc/redhat-release ]]; then
            RELEASE="centos"
        elif grep -Eqi "alpine" /etc/issue 2>/dev/null; then
            RELEASE="alpine"
        elif grep -Eqi "debian" /etc/issue /proc/version 2>/dev/null; then
            RELEASE="debian"
        elif grep -Eqi "ubuntu" /etc/issue /proc/version 2>/dev/null; then
            RELEASE="ubuntu"
        elif grep -Eqi "centos|red hat|redhat|rocky|alma|oracle linux" /etc/issue /proc/version 2>/dev/null; then
            RELEASE="centos"
        elif grep -Eqi "arch" /proc/version 2>/dev/null; then
            RELEASE="arch"
        fi
    fi

    [[ -n "$RELEASE" ]] || die "System version not detected. Please contact the script author!"

    # Minimum version requirements
    case "$RELEASE" in
        centos)
            [[ -n "$OS_VERSION" && "$OS_VERSION" -le 6 ]] && die "Please use CentOS 7 or newer!"
            [[ "$OS_VERSION" == "7" ]] && warn "CentOS 7 cannot use the hysteria1/2 protocol!"
            ;;
        ubuntu)
            [[ -n "$OS_VERSION" && "$OS_VERSION" -lt 16 ]] && die "Please use Ubuntu 16 or newer!"
            ;;
        debian)
            [[ -n "$OS_VERSION" && "$OS_VERSION" -lt 8 ]] && die "Please use Debian 8 or newer!"
            ;;
    esac

    ok "Detected OS: ${RELEASE} ${OS_VERSION}${OS_CODENAME:+ (${OS_CODENAME})}"
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|x64|amd64)  ARCH="64" ;;
        aarch64|arm64)     ARCH="arm64-v8a" ;;
        s390x)             ARCH="s390x" ;;
        *)
            ARCH="64"
            warn "Failed to detect architecture, using default: ${ARCH}"
            ;;
    esac

    if [[ "$(getconf LONG_BIT)" != "64" ]]; then
        die "This software does not support 32-bit systems. Please use a 64-bit system (x86_64)."
    fi

    ok "Detected architecture: $(uname -m) -> ${ARCH}"
}

# ------------------------------------------------------------------------------
#  Package management helpers
# ------------------------------------------------------------------------------
wait_for_dpkg_lock() {
    local count=0 locked pid
    while true; do
        locked=false
        if pgrep -x "apt-get|dpkg|apt" >/dev/null 2>&1; then
            locked=true
        fi
        # unattended-upgrade (but not its shutdown daemon) also holds the lock
        for pid in $(pgrep -f "unattended-upgrade" 2>/dev/null); do
            if [[ -f "/proc/$pid/cmdline" ]] && ! grep -q "unattended-upgrade-shutdown" "/proc/$pid/cmdline"; then
                locked=true
                break
            fi
        done

        [[ "$locked" == false ]] && break

        [[ $count -eq 0 ]] && warn "Waiting for other package manager processes (apt/dpkg) to exit..."
        sleep 3
        count=$((count + 1))
        [[ $count -gt 100 ]] && die "Package manager lock timeout. Another package manager process is running."
    done
}

apt_install() {
    wait_for_dpkg_lock
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

need_install_apt() {
    local missing=() installed p
    installed=$(dpkg-query -W -f='${Package}\n' 2>/dev/null)
    for p in "$@"; do
        grep -qx "$p" <<<"$installed" || missing+=("$p")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        info "Installing missing packages: ${missing[*]}"
        wait_for_dpkg_lock
        apt-get update -y >/dev/null 2>&1 || warn "apt-get update reported errors (continuing)"
        apt_install "${missing[@]}" >/dev/null 2>&1 || warn "Some packages failed to install: ${missing[*]}"
    fi
}

need_install_yum() {
    local missing=() installed p
    installed=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null)
    for p in "$@"; do
        grep -qx "$p" <<<"$installed" || missing+=("$p")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        info "Installing missing packages: ${missing[*]}"
        yum install -y "${missing[@]}" >/dev/null 2>&1 || warn "Some packages failed to install: ${missing[*]}"
    fi
}

need_install_apk() {
    local missing=() installed p
    installed=$(apk info 2>/dev/null)
    for p in "$@"; do
        grep -qx "$p" <<<"$installed" || missing+=("$p")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        info "Installing missing packages: ${missing[*]}"
        apk add --no-cache "${missing[@]}" >/dev/null 2>&1 || warn "Some packages failed to install: ${missing[*]}"
    fi
}

install_base() {
    case "$RELEASE" in
        centos)
            if ! rpm -q epel-release >/dev/null 2>&1; then
                info "Installing EPEL repository..."
                yum install -y epel-release >/dev/null 2>&1
            fi
            need_install_yum wget curl unzip tar cronie socat ca-certificates pv \
                wireguard-tools kernel-devel kernel-headers strongswan xl2tpd git make openvpn
            update-ca-trust force-enable >/dev/null 2>&1 || true
            ;;
        alpine)
            need_install_apk wget curl unzip tar socat ca-certificates pv \
                wireguard-tools linux-headers strongswan xl2tpd git openvpn
            update-ca-certificates >/dev/null 2>&1 || true
            ;;
        debian|ubuntu)
            local extra=()
            [[ "$RELEASE" == "ubuntu" ]] && extra+=(software-properties-common)
            need_install_apt wget curl unzip tar cron socat ca-certificates pv \
                "${extra[@]}" "linux-headers-$(uname -r)" wireguard-tools \
                strongswan strongswan-swanctl xl2tpd git make build-essential openvpn
            update-ca-certificates >/dev/null 2>&1 || true
            install_amneziawg
            ;;
        arch)
            info "Updating package database..."
            pacman -Sy --noconfirm >/dev/null 2>&1
            info "Installing required packages..."
            pacman -S --noconfirm --needed wget curl unzip tar cronie socat \
                ca-certificates pv wireguard-tools linux-headers strongswan \
                xl2tpd git openvpn >/dev/null 2>&1
            ;;
    esac
    ok "Base packages ready"
}

# ------------------------------------------------------------------------------
#  AmneziaWG
#
#  Strategy:
#    1. If the module is already loaded and the userland tools exist -> done.
#    2. On Ubuntu, try the DKMS packages from the Amnezia PPA, but only when
#       the PPA actually publishes packages for this release (otherwise adding
#       it permanently breaks `apt-get update`).
#    3. Fall back to building both the kernel module and the userland tools
#       from source. Needed for Debian, unsupported Ubuntu releases, and
#       custom kernels (XanMod, Liquorix, ...) that DKMS can't build against.
# ------------------------------------------------------------------------------
awg_ready() {
    lsmod | grep -q '^amneziawg' && command -v awg >/dev/null 2>&1
}

ppa_supports_release() {
    [[ -n "$OS_CODENAME" ]] || return 1
    curl -fsI --max-time 15 \
        "https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/${OS_CODENAME}/Release" \
        >/dev/null 2>&1
}

remove_amnezia_ppa() {
    add-apt-repository -y --remove "$AWG_PPA" >/dev/null 2>&1 || true
    rm -f /etc/apt/sources.list.d/amnezia-ubuntu-ppa*.list \
          /etc/apt/sources.list.d/amnezia-ubuntu-ppa*.sources 2>/dev/null || true
}

install_awg_dkms() {
    info "Trying AmneziaWG DKMS packages from PPA..."
    add-apt-repository -y "$AWG_PPA" >/dev/null 2>&1 || true
    if ! apt-get update -y >/dev/null 2>&1; then
        warn "apt-get update failed after adding the Amnezia PPA"
    fi

    apt_install amneziawg-tools >/dev/null 2>&1 || true
    apt_install amneziawg-dkms 2>&1 | tee /tmp/awg-dkms-install.log
    local dkms_exit=${PIPESTATUS[0]}

    modprobe amneziawg 2>/dev/null || true
    if [[ $dkms_exit -eq 0 ]] && awg_ready; then
        return 0
    fi

    warn "DKMS install failed for kernel $(uname -r) (see /tmp/awg-dkms-install.log)"
    # Clean up broken DKMS state and the now-useless PPA so apt keeps working
    dpkg --remove --force-remove-reinstreq amneziawg amneziawg-dkms 2>/dev/null || true
    apt-get -f install -y >/dev/null 2>&1 || true
    remove_amnezia_ppa
    apt-get update -y >/dev/null 2>&1 || true
    return 1
}

install_awg_source() {
    info "Building AmneziaWG from source for kernel $(uname -r)..."

    apt_install git build-essential "linux-headers-$(uname -r)" >/dev/null 2>&1 || true

    # Kernels built with Clang/LLVM (common for XanMod/Liquorix) need LLVM=1
    local make_flags=""
    if grep -qi clang /proc/version 2>/dev/null ||
       { [[ -f "/lib/modules/$(uname -r)/build/.config" ]] &&
         grep -q 'CONFIG_CC_IS_CLANG=y' "/lib/modules/$(uname -r)/build/.config"; }; then
        info "Clang/LLVM-built kernel detected, installing clang toolchain..."
        apt_install clang llvm lld >/dev/null 2>&1 || true
        make_flags="LLVM=1"
    fi

    # --- kernel module ---
    local build_dir="/tmp/amneziawg-linux-kernel-module"
    rm -rf "$build_dir"
    if ! git clone --depth 1 "$AWG_MODULE_REPO" "$build_dir" >/dev/null 2>&1; then
        err "Failed to clone AmneziaWG source. Check network/GitHub access."
        return 1
    fi

    if ! make -C "$build_dir/src" -j"$(nproc)" KERNELDIR="/lib/modules/$(uname -r)/build" $make_flags; then
        err "AmneziaWG source build failed. Check ${build_dir}/src/ for details."
        return 1
    fi
    make -C "$build_dir/src" install KERNELDIR="/lib/modules/$(uname -r)/build" $make_flags 2>/dev/null || true
    depmod -a
    modprobe amneziawg 2>/dev/null || true

    if ! lsmod | grep -q '^amneziawg'; then
        err "Failed to load AmneziaWG module after source build"
        return 1
    fi
    # Persist across reboots
    echo "amneziawg" > /etc/modules-load.d/amneziawg.conf

    # --- userland tools (awg / awg-quick), if not already present ---
    if ! command -v awg >/dev/null 2>&1; then
        local tools_dir="/tmp/amneziawg-tools"
        rm -rf "$tools_dir"
        if git clone --depth 1 "$AWG_TOOLS_REPO" "$tools_dir" >/dev/null 2>&1 &&
           make -C "$tools_dir/src" -j"$(nproc)" >/dev/null 2>&1 &&
           make -C "$tools_dir/src" install >/dev/null 2>&1; then
            ok "amneziawg-tools built and installed from source"
        else
            warn "Failed to build amneziawg-tools; 'awg' CLI may be missing"
        fi
    fi

    rm -rf "$build_dir" /tmp/amneziawg-tools
    return 0
}

install_amneziawg() {
    info "Installing AmneziaWG..."

    modprobe amneziawg 2>/dev/null || true
    if awg_ready; then
        ok "AmneziaWG already installed and loaded"
        return 0
    fi

    if [[ "$RELEASE" == "ubuntu" ]] && ppa_supports_release; then
        if install_awg_dkms; then
            ok "AmneziaWG DKMS module installed and loaded"
            return 0
        fi
    elif [[ "$RELEASE" == "ubuntu" ]]; then
        warn "Amnezia PPA has no packages for Ubuntu '${OS_CODENAME:-unknown}', skipping DKMS"
    fi

    if install_awg_source; then
        ok "AmneziaWG built from source and loaded"
        return 0
    fi

    err "AmneziaWG installation failed; AWG-based protocols will be unavailable"
    return 1
}

# ------------------------------------------------------------------------------
#  strongSwan (required for IPsec/IKEv2/L2TP)
# ------------------------------------------------------------------------------
setup_strongswan() {
    if [[ "$RELEASE" == "alpine" ]]; then
        rc-update add strongswan default 2>/dev/null || true
        service strongswan start 2>/dev/null || true
        ok "strongSwan enabled (OpenRC)"
        return
    fi

    local svc
    for svc in strongswan-swanctl strongswan-starter strongswan; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
            systemctl enable "$svc" >/dev/null 2>&1 || true
            systemctl start "$svc" >/dev/null 2>&1 || true
            ok "strongSwan service '${svc}' enabled and started"
            return
        fi
    done
    warn "Could not find a strongSwan systemd service to enable"
}

# ------------------------------------------------------------------------------
#  archnets service
# ------------------------------------------------------------------------------
# 0: running, 1: not running, 2: not installed
check_status() {
    [[ -f "${INSTALL_DIR}/node" ]] || return 2
    if [[ "$RELEASE" == "alpine" ]]; then
        [[ "$(service ${SERVICE_NAME} status 2>/dev/null | awk '{print $3}')" == "started" ]]
    else
        systemctl is-active --quiet "$SERVICE_NAME"
    fi
}

service_ctl() {
    local action="$1"
    if [[ "$RELEASE" == "alpine" ]]; then
        service "$SERVICE_NAME" "$action" >/dev/null 2>&1
    else
        systemctl "$action" "$SERVICE_NAME" >/dev/null 2>&1
    fi
}

restart_and_report() {
    service_ctl restart
    sleep 2
    if check_status; then
        ok "${SERVICE_NAME} is running"
    else
        err "${SERVICE_NAME} may have failed to start. Run 'node log' to view logs."
    fi
}

generate_config() {
    local api_host="$1" server_id="$2" secret_key="$3"

    mkdir -p "$CONFIG_DIR"
    cat > "${CONFIG_DIR}/config.yml" <<EOF
Log:
  # Log level; options: debug, info, warn (warning), error
  Level: warn
  # Log output path; can be a file path. Leave empty to use "stdout" (standard output).
  Output:
  # Access log path, e.g. logs/access.log; set to "none" to disable access logs
  Access: none

Api:
  # Backend API address, e.g. "https://api.example.com"
  ApiHost: ${api_host}
  # Server unique identifier
  ServerID: ${server_id}
  # Secret key used to verify request legitimacy
  SecretKey: ${secret_key}
  # Request timeout (seconds)
  Timeout: 30
EOF
    ok "Configuration written to ${CONFIG_DIR}/config.yml, restarting service..."
    restart_and_report
}

install_systemd_unit() {
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=archnets Service
After=network.target nss-lookup.target strongswan-swanctl.service strongswan-starter.service strongswan.service
Wants=network.target

[Service]
User=root
Group=root
Type=simple
LimitAS=infinity
LimitRSS=infinity
LimitCORE=infinity
LimitNOFILE=999999
WorkingDirectory=${INSTALL_DIR}/
ExecStart=${INSTALL_DIR}/node server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
}

install_openrc_service() {
    rm -f /etc/init.d/${SERVICE_NAME}
    cat > /etc/init.d/${SERVICE_NAME} <<EOF
#!/sbin/openrc-run

name="${SERVICE_NAME}"
description="${SERVICE_NAME}"

command="${INSTALL_DIR}/node"
command_args="server"
command_user="root"

pidfile="/run/node.pid"
command_background="yes"

depend() {
        need net
}
EOF
    chmod +x /etc/init.d/${SERVICE_NAME}
    rc-update add "$SERVICE_NAME" default
}

resolve_version() {
    local version="$1"
    if [[ -n "$version" ]]; then
        echo "$version"
        return 0
    fi
    curl -fsSL --max-time 30 "https://api.github.com/repos/${REPO}/releases/latest" |
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p'
}

download_release() {
    local version="$1"
    local url="https://github.com/${REPO}/releases/download/${version}/archnets-node-linux-${ARCH}.zip"
    local dest="${INSTALL_DIR}/archnets-node-linux.zip"

    info "Downloading ${url}"
    if ! curl -fL --retry 3 --connect-timeout 15 --progress-bar -o "$dest" "$url" || [[ ! -s "$dest" ]]; then
        die "Failed to download archnets ${version}. Ensure the version exists and your server can access GitHub."
    fi
}

print_usage_summary() {
    echo ""
    echo "${BOLD}──────────────────────────────────────────────${PLAIN}"
    echo "${BOLD} archnets management script usage${PLAIN}"
    echo "${BOLD}──────────────────────────────────────────────${PLAIN}"
    printf ' %-18s %s\n' \
        "node"              "Show management menu (more features)" \
        "node start"        "Start archnets" \
        "node stop"         "Stop archnets" \
        "node restart"      "Restart archnets" \
        "node status"       "Show archnets status" \
        "node enable"       "Enable archnets at boot" \
        "node disable"      "Disable archnets at boot" \
        "node log"          "View archnets logs" \
        "node generate"     "Generate archnets config file" \
        "node update"       "Update archnets" \
        "node update x.x.x" "Install a specific archnets version" \
        "node install"      "Install archnets" \
        "node uninstall"    "Uninstall archnets" \
        "node version"      "Show archnets version"
    echo "${BOLD}──────────────────────────────────────────────${PLAIN}"
}

first_install_wizard() {
    local if_generate api_host server_id secret_key
    read -rp "Detected first-time installation of archnets. Generate ${CONFIG_DIR}/config.yml automatically? (y/n): " if_generate
    if [[ "$if_generate" =~ ^[Yy]$ ]]; then
        read -rp "Panel API address [format: https://example.com/]: " api_host
        api_host=${api_host:-https://example.com/}
        read -rp "Server ID: " server_id
        server_id=${server_id:-1}
        read -rp "Secret key: " secret_key
        generate_config "$api_host" "$server_id" "$secret_key"
    else
        info "Skipped automatic config generation. To generate later, run: node generate"
    fi
}

install_node() {
    local version
    version="$(resolve_version "$VERSION_ARG")"
    [[ -n "$version" ]] || die "Failed to detect archnets version (GitHub API limit?). Try again later or specify a version manually."
    info "Installing archnets ${version}"

    rm -rf "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR" || die "Cannot enter ${INSTALL_DIR}"

    download_release "$version"

    unzip -o -q archnets-node-linux.zip || die "Failed to unpack release archive"
    rm -f archnets-node-linux.zip
    chmod +x node

    mkdir -p "$CONFIG_DIR"
    cp geoip.dat geosite.dat "$CONFIG_DIR"/ 2>/dev/null || true
    cp geoip_iran.dat geosite_iran.dat "$CONFIG_DIR"/ 2>/dev/null || true

    if [[ "$RELEASE" == "alpine" ]]; then
        install_openrc_service
    else
        install_systemd_unit
    fi
    ok "archnets ${version} installed and enabled at boot"

    local first_install=false
    if [[ ! -f "${CONFIG_DIR}/config.yml" ]]; then
        if [[ -n "$API_HOST_ARG" && -n "$SERVER_ID_ARG" && -n "$SECRET_KEY_ARG" ]]; then
            # Full CLI parameters provided -> non-interactive config
            generate_config "$API_HOST_ARG" "$SERVER_ID_ARG" "$SECRET_KEY_ARG"
            ok "${CONFIG_DIR}/config.yml generated from parameters"
        else
            cp config.yml "$CONFIG_DIR"/ 2>/dev/null || true
            first_install=true
        fi
    else
        service_ctl start
        sleep 2
        if check_status; then
            ok "${SERVICE_NAME} restarted successfully"
        else
            err "${SERVICE_NAME} may have failed to start. Run 'node log' to view logs."
        fi
    fi

    # Management CLI
    if curl -fsL -o /usr/bin/node "$MGMT_SCRIPT_URL"; then
        chmod +x /usr/bin/node
    else
        warn "Failed to download management script from ${MGMT_SCRIPT_URL}"
    fi

    cd "$CUR_DIR" || true
    rm -f install.sh

    print_usage_summary

    [[ "$first_install" == true ]] && first_install_wizard
}

# ------------------------------------------------------------------------------
#  Main
# ------------------------------------------------------------------------------
main() {
    banner
    parse_args "$@"
    require_root

    step "Checking environment"
    detect_os
    detect_arch

    step "Installing base packages"
    install_base

    step "Configuring strongSwan"
    setup_strongswan

    step "Installing archnets node"
    install_node

    echo ""
    ok "${BOLD}Installation finished${PLAIN}"
}

main "$@"