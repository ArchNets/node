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
readonly AWG_TOOLS_TAG="v3.1.20260812"
readonly AWG_PPA_KEY_ID="75C9DD72C799870E310542E24166F2C257290828"
readonly AWG_PPA_KEYRING="/etc/apt/trusted.gpg.d/amnezia-ppa.gpg"
readonly AWG_PPA_LIST="/etc/apt/sources.list.d/amnezia-ppa.list"
readonly AWG_SWAP_FILE="/tmp/archnet-awg.swap"

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
UPDATE_MODE=false
WITH_AWG=false
INSTALL_AWG_ONLY=false

usage() {
    cat <<EOF
Usage: $0 [version] [options]

Options:
  --api-host URL     Panel API address (e.g. https://example.com/)
  --server-id ID     Server unique identifier
  --secret-key KEY   Secret key used to verify request legitimacy
  -u, --update       Fast update mode (skip base OS packages & strongSwan)
  --with-awg         Also install AmneziaWG kernel module & tools during install
  --install-awg      Install/repair AmneziaWG kernel module & tools only
  -h, --help         Show this help

When all three API options are provided, the config file is generated
non-interactively.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --api-host)    API_HOST_ARG="${2:-}";   shift 2 ;;
            --server-id)   SERVER_ID_ARG="${2:-}";  shift 2 ;;
            --secret-key)  SECRET_KEY_ARG="${2:-}"; shift 2 ;;
            -u|--update)   UPDATE_MODE=true;        shift ;;
            --with-awg)    WITH_AWG=true;           shift ;;
            --install-awg) INSTALL_AWG_ONLY=true;   shift ;;
            -h|--help)     usage; exit 0 ;;
            --*)           die "Unknown parameter: $1 (see --help)" ;;
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

# Clone a repo, falling back to a proxy mirror if github.com is unreachable
git_clone_with_fallback() {
    # $1 = repo url, $2 = destination dir
    git clone --depth 1 "$1" "$2" >/dev/null 2>&1 && return 0
    warn "Direct clone of $1 failed, retrying via ghproxy mirror..."
    rm -rf "$2"
    git clone --depth 1 "https://ghproxy.net/$1" "$2" >/dev/null 2>&1
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
        if ! apt_install "${missing[@]}" >/dev/null 2>&1; then
            warn "Batch install failed, retrying packages one by one..."
            local failed=()
            for p in "${missing[@]}"; do
                apt_install "$p" >/dev/null 2>&1 || failed+=("$p")
            done
            [[ ${#failed[@]} -gt 0 ]] && warn "Some packages failed to install: ${failed[*]}"
        fi
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
            need_install_apt wget curl unzip tar cron socat ca-certificates pv \
                wireguard-tools charon-systemd strongswan-swanctl strongswan-pki \
                libstrongswan-standard-plugins libstrongswan-extra-plugins \
                libcharon-extauth-plugins libcharon-extra-plugins xl2tpd openvpn
            update-ca-certificates >/dev/null 2>&1 || true
            if [[ "$WITH_AWG" == true ]]; then
                install_amneziawg || warn "Continuing without AmneziaWG kernel module (embedded userspace fallback will be used)"
            fi
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
#  AmneziaWG (Optional kernel module acceleration)
#
#  Note: archnets-node includes an embedded userspace amneziawg-go engine, so
#  AmneziaWG works out-of-the-box without kernel compilation. Installing the
#  kernel module is optional for maximum throughput on capable VPSs.
#
#  Strategy (when --with-awg / --install-awg is requested):
#    1. Skip cleanly in containers (OpenVZ/LXC/Docker) where kmods cannot load.
#    2. If kernel module already loads, install prebuilt `awg` tools if missing.
#    3. Pre-check kernel headers before attempting any DKMS/source build.
#    4. Create temporary 1GB swap on low-RAM servers (<1.5GB) to prevent OOM.
#    5. On Ubuntu, add PPA via HTTPS key import (avoiding port 11371 hang) and
#       targeted apt update on the PPA source file only.
#    6. Fall back to building kernel module from source (with low-RAM job cap).
# ------------------------------------------------------------------------------
TEMP_SWAP_ACTIVE=0

create_temp_swap() {
    local mem_kb swap_kb total_mb
    mem_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    swap_kb=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    total_mb=$(( (mem_kb + swap_kb) / 1024 ))
    if [[ $total_mb -lt 1500 && ! -f "$AWG_SWAP_FILE" ]]; then
        info "Low memory detected ($((mem_kb / 1024))MB RAM). Creating temporary 1GB swap for build..."
        if fallocate -l 1G "$AWG_SWAP_FILE" 2>/dev/null || \
           dd if=/dev/zero of="$AWG_SWAP_FILE" bs=1M count=1024 >/dev/null 2>&1; then
            chmod 600 "$AWG_SWAP_FILE"
            if mkswap "$AWG_SWAP_FILE" >/dev/null 2>&1 && swapon "$AWG_SWAP_FILE" >/dev/null 2>&1; then
                TEMP_SWAP_ACTIVE=1
            else
                rm -f "$AWG_SWAP_FILE"
            fi
        fi
    fi
}

remove_temp_swap() {
    if [[ "${TEMP_SWAP_ACTIVE:-0}" -eq 1 ]] || [[ -f "$AWG_SWAP_FILE" ]]; then
        swapoff "$AWG_SWAP_FILE" >/dev/null 2>&1 || true
        rm -f "$AWG_SWAP_FILE"
        TEMP_SWAP_ACTIVE=0
    fi
}

awg_build_jobs() {
    local mem_mb
    mem_mb=$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 1024)
    if [[ $mem_mb -lt 1024 ]]; then
        echo 1
    elif [[ $mem_mb -lt 2048 ]]; then
        echo 2
    else
        nproc 2>/dev/null || echo 1
    fi
}

is_container_env() {
    [[ -f /.dockerenv ]] && return 0
    [[ -d /proc/vz && ! -d /proc/bc ]] && return 0
    if [[ -r /proc/1/environ ]] && tr '\0' '\n' </proc/1/environ 2>/dev/null | grep -qE '^container=(lxc|docker|podman|openvz)$'; then
        return 0
    fi
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local virt
        virt=$(systemd-detect-virt -c 2>/dev/null || true)
        [[ -n "$virt" && "$virt" != "none" ]] && return 0
    fi
    return 1
}

awg_ready() {
    (lsmod | grep -q '^amneziawg' || modprobe amneziawg 2>/dev/null) && command -v awg >/dev/null 2>&1
}

install_awg_tools() {
    command -v awg >/dev/null 2>&1 && return 0

    local machine asset=""
    machine="$(uname -m)"
    if [[ "$machine" == "x86_64" || "$machine" == "amd64" ]]; then
        if [[ "$RELEASE" == "alpine" ]]; then
            asset="alpine-3.19-amneziawg-tools.zip"
        else
            asset="ubuntu-22.04-amneziawg-tools.zip"
        fi
    fi

    if [[ -n "$asset" ]]; then
        local url="https://github.com/amnezia-vpn/amneziawg-tools/releases/download/${AWG_TOOLS_TAG}/${asset}"
        local tmp_zip="/tmp/awg-tools.zip"
        local tmp_dir="/tmp/awg-tools-extract"
        rm -rf "$tmp_zip" "$tmp_dir"
        info "Downloading prebuilt amneziawg-tools (${asset})..."
        if curl -fSL --connect-timeout 8 --max-time 25 -o "$tmp_zip" "$url" || \
           curl -fSL --connect-timeout 8 --max-time 25 -o "$tmp_zip" "https://ghproxy.net/${url}"; then
            mkdir -p "$tmp_dir"
            if unzip -o -q "$tmp_zip" -d "$tmp_dir"; then
                local awg_bin awg_quick_bin
                awg_bin=$(find "$tmp_dir" -type f -name "awg" | head -n1)
                awg_quick_bin=$(find "$tmp_dir" -type f -name "awg-quick" | head -n1)
                if [[ -n "$awg_bin" ]]; then
                    install -m 755 "$awg_bin" /usr/local/bin/awg
                    [[ -n "$awg_quick_bin" ]] && install -m 755 "$awg_quick_bin" /usr/local/bin/awg-quick
                    rm -rf "$tmp_zip" "$tmp_dir"
                    if awg --version >/dev/null 2>&1; then
                        ok "Prebuilt amneziawg-tools installed"
                        return 0
                    fi
                    rm -f /usr/local/bin/awg /usr/local/bin/awg-quick
                fi
            fi
        fi
        rm -rf "$tmp_zip" "$tmp_dir"
    fi

    # Fallback: compile amneziawg-tools from source
    info "Building amneziawg-tools from source..."
    if [[ "$RELEASE" == "debian" || "$RELEASE" == "ubuntu" ]]; then
        need_install_apt git make gcc libc6-dev
    fi
    local tools_dir="/tmp/amneziawg-tools"
    rm -rf "$tools_dir"
    if git_clone_with_fallback "$AWG_TOOLS_REPO" "$tools_dir" && \
       make -C "$tools_dir/src" -j"$(awg_build_jobs)" >/dev/null 2>&1 && \
       make -C "$tools_dir/src" install >/dev/null 2>&1; then
        rm -rf "$tools_dir"
        ok "amneziawg-tools built and installed from source"
        return 0
    fi
    rm -rf "$tools_dir"
    warn "Failed to install amneziawg-tools"
    return 1
}

ensure_kernel_headers() {
    [[ -d "/lib/modules/$(uname -r)/build" ]] && return 0
    if [[ "$RELEASE" == "debian" || "$RELEASE" == "ubuntu" ]]; then
        info "Installing kernel headers for $(uname -r)..."
        wait_for_dpkg_lock
        apt-get update -y >/dev/null 2>&1 || true
        apt_install "linux-headers-$(uname -r)" >/dev/null 2>&1 || \
            apt_install linux-headers-generic >/dev/null 2>&1 || true
    fi
    [[ -d "/lib/modules/$(uname -r)/build" ]]
}

ppa_supports_release() {
    [[ -n "$OS_CODENAME" ]] || return 1
    curl -fsI --connect-timeout 6 --max-time 15 \
        "https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/${OS_CODENAME}/Release" \
        >/dev/null 2>&1
}

remove_amnezia_ppa() {
    rm -f "$AWG_PPA_LIST" "$AWG_PPA_KEYRING" \
          /etc/apt/sources.list.d/amnezia-ubuntu-ppa*.list \
          /etc/apt/sources.list.d/amnezia-ubuntu-ppa*.sources 2>/dev/null || true
}

install_awg_dkms() {
    info "Trying AmneziaWG DKMS packages from PPA..."
    need_install_apt dkms gnupg curl

    # Fetch PPA signing key over HTTPS (port 443) so HKP port 11371 firewalls never hang
    rm -f "$AWG_PPA_KEYRING"
    if ! curl -fsSL --connect-timeout 6 --max-time 15 \
        "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${AWG_PPA_KEY_ID}" \
        | gpg --dearmor -o "$AWG_PPA_KEYRING" 2>/dev/null; then
        warn "Failed to fetch Amnezia PPA signing key over HTTPS"
        return 1
    fi

    echo "deb [signed-by=${AWG_PPA_KEYRING}] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu ${OS_CODENAME} main" > "$AWG_PPA_LIST"

    # Targeted apt update on the PPA source list only (fast, avoids refreshing unrelated mirrors)
    wait_for_dpkg_lock
    if ! apt-get update -o Dir::Etc::sourcelist="sources.list.d/amnezia-ppa.list" \
        -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0" -y >/dev/null 2>&1; then
        warn "apt-get update failed for Amnezia PPA"
        remove_amnezia_ppa
        return 1
    fi

    install_awg_tools || apt_install amneziawg-tools >/dev/null 2>&1 || true

    create_temp_swap
    trap remove_temp_swap EXIT
    apt_install amneziawg-dkms 2>&1 | tee /tmp/awg-dkms-install.log
    local dkms_exit=${PIPESTATUS[0]}
    remove_temp_swap
    trap - EXIT

    modprobe amneziawg 2>/dev/null || true
    if [[ $dkms_exit -eq 0 ]] && awg_ready; then
        return 0
    fi

    warn "DKMS install failed for kernel $(uname -r) (see /tmp/awg-dkms-install.log)"
    # Clean up broken DKMS state and PPA so apt stays healthy
    dpkg --remove --force-remove-reinstreq amneziawg amneziawg-dkms 2>/dev/null || true
    apt-get -f install -y >/dev/null 2>&1 || true
    remove_amnezia_ppa
    return 1
}

install_awg_source() {
    info "Building AmneziaWG kernel module from source for kernel $(uname -r)..."

    need_install_apt git build-essential

    # Kernels built with Clang/LLVM (common for XanMod/Liquorix) need LLVM=1
    local make_flags=""
    if grep -qi clang /proc/version 2>/dev/null ||
       { [[ -f "/lib/modules/$(uname -r)/build/.config" ]] &&
         grep -q 'CONFIG_CC_IS_CLANG=y' "/lib/modules/$(uname -r)/build/.config"; }; then
        info "Clang/LLVM-built kernel detected, installing clang toolchain..."
        apt_install clang llvm lld >/dev/null 2>&1 || true
        make_flags="LLVM=1"
    fi

    local build_dir="/tmp/amneziawg-linux-kernel-module"
    rm -rf "$build_dir"
    if ! git_clone_with_fallback "$AWG_MODULE_REPO" "$build_dir"; then
        err "Failed to clone AmneziaWG source. Check network/GitHub access."
        return 1
    fi

    create_temp_swap
    trap remove_temp_swap EXIT
    local jobs
    jobs="$(awg_build_jobs)"
    if ! make -C "$build_dir/src" -j"$jobs" KERNELDIR="/lib/modules/$(uname -r)/build" $make_flags; then
        remove_temp_swap
        trap - EXIT
        rm -rf "$build_dir"
        err "AmneziaWG source build failed. Check ${build_dir}/src/ for details."
        return 1
    fi
    make -C "$build_dir/src" install KERNELDIR="/lib/modules/$(uname -r)/build" $make_flags 2>/dev/null || true
    remove_temp_swap
    trap - EXIT
    rm -rf "$build_dir"

    depmod -a
    modprobe amneziawg 2>/dev/null || true

    if ! lsmod | grep -q '^amneziawg'; then
        err "Failed to load AmneziaWG module after source build"
        return 1
    fi
    # Persist across reboots
    echo "amneziawg" > /etc/modules-load.d/amneziawg.conf

    install_awg_tools || warn "Failed to install 'awg' CLI"
    return 0
}

install_amneziawg() {
    info "Installing AmneziaWG kernel module & tools..."

    modprobe amneziawg 2>/dev/null || true
    if lsmod | grep -q '^amneziawg'; then
        install_awg_tools || true
        if awg_ready; then
            ok "AmneziaWG already installed and loaded"
            return 0
        fi
    fi

    if is_container_env; then
        warn "Container environment detected; kernel modules cannot be compiled or loaded."
        info "archnets-node will use its built-in userspace amneziawg-go engine automatically."
        return 0
    fi

    if ! ensure_kernel_headers; then
        warn "Kernel headers for $(uname -r) are unavailable; cannot build AmneziaWG kernel module."
        info "archnets-node will use its built-in userspace amneziawg-go engine automatically."
        return 1
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

    warn "AmneziaWG kernel module installation failed; archnets-node will fall back to embedded userspace amneziawg-go"
    return 1
}

# ------------------------------------------------------------------------------
#  strongSwan (required for IPsec/IKEv2/L2TP)
# ------------------------------------------------------------------------------
setup_strongswan() {
    if [[ "$RELEASE" == "alpine" ]]; then
        rc-update del strongswan default 2>/dev/null || true
        service strongswan stop 2>/dev/null || true
        ok "strongSwan ready (on-demand via archnets)"
        return
    fi

    # On Debian/Ubuntu 24.04+, strongswan-swanctl requires charon-systemd + extauth plugins for EAP-MSCHAPv2
    if [[ "$RELEASE" == "debian" || "$RELEASE" == "ubuntu" ]]; then
        if ! systemctl cat strongswan.service >/dev/null 2>&1 && \
           ! systemctl cat strongswan-swanctl.service >/dev/null 2>&1 && \
           ! systemctl cat strongswan-starter.service >/dev/null 2>&1; then
            need_install_apt charon-systemd strongswan-swanctl strongswan-pki \
                libstrongswan-standard-plugins libstrongswan-extra-plugins \
                libcharon-extauth-plugins libcharon-extra-plugins || true
            systemctl daemon-reload >/dev/null 2>&1 || true
        fi
    fi

    # Keep strongSwan/xl2tpd stopped & disabled unless archnets IPsecCore actually starts them
    # (prevents idle charon/xl2tpd from stealing UDP 500/4500/1701 on Entry relay servers).
    if ! ls /etc/swanctl/conf.d/ipsec-*.conf >/dev/null 2>&1 && \
       ! ls /etc/xl2tpd/ipsec-*.conf >/dev/null 2>&1; then
        for svc in strongswan strongswan-swanctl strongswan-starter xl2tpd; do
            systemctl disable --now "$svc" >/dev/null 2>&1 || true
        done
        pkill -x xl2tpd >/dev/null 2>&1 || true
        ok "strongSwan installed (on-demand; UDP 500/4500/1701 kept free for relay forwarders)"
        return
    fi

    local svc
    for svc in strongswan strongswan-swanctl strongswan-starter; do
        if systemctl cat "${svc}.service" >/dev/null 2>&1 || \
           systemctl list-unit-files 2>/dev/null | grep -qE "^${svc}\.service"; then
            systemctl unmask "$svc" >/dev/null 2>&1 || true
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
After=network.target nss-lookup.target strongswan.service strongswan-swanctl.service strongswan-starter.service
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
    # Do NOT call 'systemctl stop' here: if run inside archnets.service's cgroup (e.g. Reverse Terminal),
    # stopping the service kills this installer process mid-update with SIGTERM ("Terminated").
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
}

install_logrotate() {
    if [[ -d /etc/logrotate.d ]]; then
        cat > /etc/logrotate.d/archnet-node <<'EOF'
/var/log/archnet/*.log /etc/archnets/logs/*.log /etc/archnets/log/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
        chmod 644 /etc/logrotate.d/archnet-node
    fi
    if [[ -d /etc/systemd ]] && command -v systemctl >/dev/null 2>&1; then
        mkdir -p /etc/systemd/journald.conf.d
        cat > /etc/systemd/journald.conf.d/99-archnets-limits.conf <<'EOF'
[Journal]
SystemMaxUse=200M
SystemKeepFree=2G
SystemMaxFileSize=50M
RuntimeMaxUse=100M
MaxFileSec=3day
EOF
        systemctl restart systemd-journald >/dev/null 2>&1 || true
    fi
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
        echo "v${version#v}"
        return 0
    fi
    curl -fsSL --max-time 30 "https://api.github.com/repos/${REPO}/releases/latest" |
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p'
}

download_release() {
    local version="$1"
    local dest="${2:-${INSTALL_DIR}/archnets-node-linux.zip}"
    local url="https://github.com/${REPO}/releases/download/${version}/archnets-node-linux-${ARCH}.zip"

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
    local version tmp_stage running_in_service_cgroup=false
    version="$(resolve_version "$VERSION_ARG")"
    [[ -n "$version" ]] || die "Failed to detect archnets version (GitHub API limit?). Try again later or specify a version manually."
    info "Installing archnets ${version}"

    if grep -q "${SERVICE_NAME}\.service" /proc/self/cgroup 2>/dev/null; then
        running_in_service_cgroup=true
    fi

    tmp_stage=$(mktemp -d)
    download_release "$version" "${tmp_stage}/archnets-node-linux.zip"
    unzip -o -q "${tmp_stage}/archnets-node-linux.zip" -d "$tmp_stage" || {
        rm -rf "$tmp_stage"
        die "Failed to unpack release archive"
    }
    rm -f "${tmp_stage}/archnets-node-linux.zip"
    chmod +x "${tmp_stage}/node" 2>/dev/null || true

    mkdir -p "$INSTALL_DIR"
    # Replace node binary atomically (unlinking old inode avoids ETXTBSY while running)
    install -m 755 "${tmp_stage}/node" "${INSTALL_DIR}/node"
    cp -af "${tmp_stage}/." "$INSTALL_DIR"/
    rm -rf "$tmp_stage"
    cd "$INSTALL_DIR" || die "Cannot enter ${INSTALL_DIR}"

    mkdir -p "$CONFIG_DIR"
    cp geoip.dat geosite.dat "$CONFIG_DIR"/ 2>/dev/null || true
    cp geoip_iran.dat geosite_iran.dat "$CONFIG_DIR"/ 2>/dev/null || true

    if [[ "$RELEASE" == "alpine" ]]; then
        install_openrc_service
    else
        install_systemd_unit
    fi
    install_logrotate
    ok "archnets ${version} installed and enabled at boot"

    # Management CLI
    if curl -fsL -o /usr/bin/node "$MGMT_SCRIPT_URL"; then
        chmod +x /usr/bin/node
    else
        warn "Failed to download management script from ${MGMT_SCRIPT_URL}"
    fi

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
        if [[ "$running_in_service_cgroup" == true && "$RELEASE" != "alpine" ]]; then
            # Running inside archnets.service cgroup (e.g. Reverse Terminal): schedule detached restart
            # so this command finishes cleanly without killing itself mid-output.
            if command -v systemd-run >/dev/null 2>&1; then
                systemd-run --on-active=1s --unit="${SERVICE_NAME}-self-restart" systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
            else
                nohup setsid bash -c "sleep 1 && systemctl restart ${SERVICE_NAME}" >/dev/null 2>&1 </dev/null &
            fi
            ok "${SERVICE_NAME} binary updated; scheduled detached service restart in 1s"
        else
            service_ctl restart
            sleep 2
            if check_status; then
                ok "${SERVICE_NAME} restarted successfully"
            else
                err "${SERVICE_NAME} may have failed to start. Run 'node log' to view logs."
            fi
        fi
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

    if [[ "$INSTALL_AWG_ONLY" == true ]]; then
        step "Installing AmneziaWG kernel module"
        install_amneziawg
        exit $?
    fi

    if [[ "$UPDATE_MODE" == true ]]; then
        step "Ensuring strongSwan service"
        setup_strongswan
        step "Updating archnets node"
        install_node
        echo ""
        ok "${BOLD}Update finished${PLAIN}"
        return 0
    fi

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