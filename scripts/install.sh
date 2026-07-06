#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Error:${plain} You must run this script as root!\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "alpine"; then
    release="alpine"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat|rocky|alma|oracle linux"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat|rocky|alma|oracle linux"; then
    release="centos"
elif cat /proc/version | grep -Eqi "arch"; then
    release="arch"
else
    echo -e "${red}System version not detected. Please contact the script author!${plain}\n" && exit 1
fi

########################
# Argument parsing
########################
VERSION_ARG=""
API_HOST_ARG=""
SERVER_ID_ARG=""
SECRET_KEY_ARG=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --api-host)
                API_HOST_ARG="$2"; shift 2 ;;
            --server-id)
                SERVER_ID_ARG="$2"; shift 2 ;;
            --secret-key)
                SECRET_KEY_ARG="$2"; shift 2 ;;
            -h|--help)
                echo "Usage: $0 [version] [--api-host URL] [--server-id ID] [--secret-key KEY]"
                exit 0 ;;
            --*)
                echo "Unknown parameter: $1"; exit 1 ;;
            *)
                # Treat the first positional argument as the version number
                if [[ -z "$VERSION_ARG" ]]; then
                    VERSION_ARG="$1"; shift
                else
                    shift
                fi ;;
        esac
    done
}

arch=$(uname -m)

if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
    arch="64"
elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
    arch="arm64-v8a"
elif [[ $arch == "s390x" ]]; then
    arch="s390x"
else
    arch="64"
    echo -e "${red}Failed to detect architecture, using default: ${arch}${plain}"
fi

if [ "$(getconf WORD_BIT)" != '32' ] && [ "$(getconf LONG_BIT)" != '64' ] ; then
    echo "This software does not support 32-bit (x86). Please use a 64-bit system (x86_64). If this detection is wrong, contact the author."
    exit 2
fi

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}Please use CentOS 7 or newer!${plain}\n" && exit 1
    fi
    if [[ ${os_version} -eq 7 ]]; then
        echo -e "${red}Note: CentOS 7 cannot use the hysteria1/2 protocol!${plain}\n"
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}Please use Ubuntu 16 or newer!${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}Please use Debian 8 or newer!${plain}\n" && exit 1
    fi
fi

# Install AmneziaWG with DKMS fallback to source build
# DKMS fails on non-stock kernels (XanMod, Liquorix, etc.) because:
#   1. The PPA source doesn't support newer kernel APIs
#   2. Custom kernels are often built with Clang/LLVM, not GCC
install_amneziawg() {
    echo -e "${green}Installing AmneziaWG...${plain}"

    # Try DKMS install first
    if [[ x"${release}" == x"ubuntu" ]]; then
        add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
        apt-get update -y >/dev/null 2>&1
    fi

    DEBIAN_FRONTEND=noninteractive apt-get install -y amneziawg-tools >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y amneziawg-dkms 2>&1 | tee /tmp/awg-dkms-install.log
    local dkms_exit=${PIPESTATUS[0]}

    # Check if the module actually loaded
    modprobe amneziawg 2>/dev/null
    if lsmod | grep -q amneziawg; then
        echo -e "${green}AmneziaWG DKMS module loaded successfully${plain}"
        return 0
    fi

    echo -e "${yellow}DKMS build failed for kernel $(uname -r), building from source...${plain}"

    # Clean up broken DKMS state
    dpkg --remove --force-remove-reinstreq amneziawg amneziawg-dkms 2>/dev/null || true
    apt-get -f install -y >/dev/null 2>&1 || true
    # Reinstall tools only (no dkms)
    DEBIAN_FRONTEND=noninteractive apt-get install -y amneziawg-tools >/dev/null 2>&1 || true

    # Install build dependencies
    apt-get install -y git build-essential "linux-headers-$(uname -r)" >/dev/null 2>&1

    # Detect if kernel was built with Clang/LLVM
    local make_flags=""
    if grep -qi clang /proc/version 2>/dev/null || \
       ([ -f "/lib/modules/$(uname -r)/build/.config" ] && grep -q 'CONFIG_CC_IS_CLANG=y' "/lib/modules/$(uname -r)/build/.config"); then
        echo -e "${yellow}Kernel built with Clang/LLVM detected, installing clang...${plain}"
        apt-get install -y clang llvm lld >/dev/null 2>&1
        make_flags="LLVM=1"
    fi

    # Clone and build from source
    local build_dir="/tmp/amneziawg-linux-kernel-module"
    rm -rf "$build_dir"
    git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git "$build_dir"
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Failed to clone AmneziaWG source. Check network/GitHub access.${plain}"
        return 1
    fi

    cd "$build_dir/src"
    make -j$(nproc) KERNELDIR="/lib/modules/$(uname -r)/build" $make_flags
    if [[ $? -ne 0 ]]; then
        echo -e "${red}AmneziaWG source build failed. Check /tmp/amneziawg-linux-kernel-module/src/ for details.${plain}"
        cd /tmp
        return 1
    fi

    make install KERNELDIR="/lib/modules/$(uname -r)/build" $make_flags 2>/dev/null || true
    depmod -a
    modprobe amneziawg

    if lsmod | grep -q amneziawg; then
        echo -e "${green}AmneziaWG built from source and loaded successfully${plain}"
        # Persist across reboots
        echo "amneziawg" > /etc/modules-load.d/amneziawg.conf
    else
        echo -e "${red}Failed to load AmneziaWG module after source build${plain}"
        cd /tmp
        return 1
    fi

    # Cleanup
    cd /tmp
    rm -rf "$build_dir"
    return 0
}

install_base() {
    wait_for_dpkg_lock() {
        local count=0
        while true; do
            local locked=false
            if pgrep -x "apt-get|dpkg|apt" >/dev/null 2>&1; then
                locked=true
            fi
            
            # Check if unattended-upgrade is running (not the shutdown daemon)
            for pid in $(pgrep -f "unattended-upgrade" 2>/dev/null); do
                if [ -f "/proc/$pid/cmdline" ]; then
                    if ! grep -q "unattended-upgrade-shutdown" "/proc/$pid/cmdline"; then
                        locked=true
                        break
                    fi
                fi
            done

            if [ "$locked" = false ]; then
                break
            fi

            if [ $count -eq 0 ]; then
                echo -e "${yellow}Waiting for other package manager processes (apt/dpkg) to exit...${plain}"
            fi
            sleep 3
            count=$((count+1))
            if [ $count -gt 100 ]; then
                echo -e "${red}Error: Package manager lock timeout. Another package manager process is running.${plain}"
                exit 1
            fi
        done
    }

    need_install_apt() {
        local packages=("$@")
        local missing=()
        
        # Check installed packages in bulk
        local installed_list=$(dpkg-query -W -f='${Package}\n' 2>/dev/null | sort)
        
        for p in "${packages[@]}"; do
            if ! echo "$installed_list" | grep -q "^${p}$"; then
                missing+=("$p")
            fi
        done
        
        if [[ ${#missing[@]} -gt 0 ]]; then
            wait_for_dpkg_lock
            echo "Installing missing packages: ${missing[*]}"
            apt-get update -y >/dev/null 2>&1
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}" >/dev/null 2>&1
        fi
    }

    need_install_yum() {
        local packages=("$@")
        local missing=()
        
        # Check installed packages in bulk
        local installed_list=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort)
        
        for p in "${packages[@]}"; do
            if ! echo "$installed_list" | grep -q "^${p}$"; then
                missing+=("$p")
            fi
        done
        
        if [[ ${#missing[@]} -gt 0 ]]; then
            echo "Installing missing packages: ${missing[*]}"
            yum install -y "${missing[@]}" >/dev/null 2>&1
        fi
    }

    need_install_apk() {
        local packages=("$@")
        local missing=()
        
        # Check installed packages in bulk
        local installed_list=$(apk info 2>/dev/null | sort)
        
        for p in "${packages[@]}"; do
            if ! echo "$installed_list" | grep -q "^${p}$"; then
                missing+=("$p")
            fi
        done
        
        if [[ ${#missing[@]} -gt 0 ]]; then
            echo "Installing missing packages: ${missing[*]}"
            apk add --no-cache "${missing[@]}" >/dev/null 2>&1
        fi
    }

    # Install all required packages in one go
    if [[ x"${release}" == x"centos" ]]; then
        # Check and install epel-release
        if ! rpm -q epel-release >/dev/null 2>&1; then
            echo "Installing EPEL repository..."
            yum install -y epel-release >/dev/null 2>&1
        fi
        need_install_yum wget curl unzip tar cronie socat ca-certificates pv wireguard-tools kernel-devel kernel-headers strongswan xl2tpd git make openvpn
        update-ca-trust force-enable >/dev/null 2>&1 || true
    elif [[ x"${release}" == x"alpine" ]]; then
        need_install_apk wget curl unzip tar socat ca-certificates pv wireguard-tools linux-headers strongswan xl2tpd git openvpn
        update-ca-certificates >/dev/null 2>&1 || true
    elif [[ x"${release}" == x"debian" ]]; then
        need_install_apt wget curl unzip tar cron socat ca-certificates pv wireguard-tools strongswan strongswan-swanctl xl2tpd "linux-headers-$(uname -r)" git make build-essential openvpn
        update-ca-certificates >/dev/null 2>&1 || true
        install_amneziawg
    elif [[ x"${release}" == x"ubuntu" ]]; then
        need_install_apt wget curl unzip tar cron socat ca-certificates pv software-properties-common "linux-headers-$(uname -r)" wireguard-tools strongswan strongswan-swanctl xl2tpd git make build-essential openvpn
        update-ca-certificates >/dev/null 2>&1 || true
        install_amneziawg
    elif [[ x"${release}" == x"arch" ]]; then
        echo "Updating package database..."
        pacman -Sy --noconfirm >/dev/null 2>&1
        # --needed skips already installed packages; very efficient
        echo "Installing required packages..."
        pacman -S --noconfirm --needed wget curl unzip tar cronie socat ca-certificates pv wireguard-tools linux-headers strongswan xl2tpd git openvpn >/dev/null 2>&1
    fi
}

# Enable and start strongSwan charon daemon (required for IPsec/IKEv2/L2TP)
setup_strongswan() {
    if [[ x"${release}" == x"alpine" ]]; then
        rc-update add strongswan default 2>/dev/null || true
        service strongswan start 2>/dev/null || true
        return
    fi

    # Try known systemd service names in order of preference
    for svc in strongswan-swanctl strongswan-starter strongswan; do
        if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1; then
            systemctl enable "$svc" >/dev/null 2>&1 || true
            systemctl start "$svc" >/dev/null 2>&1 || true
            echo -e "${green}strongSwan service '${svc}' enabled and started${plain}"
            return
        fi
    done
    echo -e "${yellow}Warning: Could not find strongSwan systemd service to enable${plain}"
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /usr/local/archnets/node ]]; then
        return 2
    fi
    if [[ x"${release}" == x"alpine" ]]; then
        temp=$(service archnets status | awk '{print $3}')
        if [[ x"${temp}" == x"started" ]]; then
            return 0
        else
            return 1
        fi
    else
        temp=$(systemctl status archnets | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
        if [[ x"${temp}" == x"running" ]]; then
            return 0
        else
            return 1
        fi
    fi
}

generate_ppnode_config() {
        local api_host="$1"
        local server_id="$2"
        local secret_key="$3"

        mkdir -p /etc/archnets >/dev/null 2>&1
        cat > /etc/archnets/config.yml <<EOF
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
        echo -e "${green}archnets configuration generated, restarting service...${plain}"
        if [[ x"${release}" == x"alpine" ]]; then
            service archnets restart
        else
            systemctl restart archnets
        fi
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo -e "${green}archnets restarted successfully${plain}"
        else
            echo -e "${red}archnets may have failed to start. Please run 'node log' to view logs.${plain}"
        fi
}

install_ppnode() {
    local version_param="$1"
    if [[ -e /usr/local/archnets/ ]]; then
        rm -rf /usr/local/archnets/
    fi

    mkdir /usr/local/archnets/ -p
    cd /usr/local/archnets/

    if  [[ -z "$version_param" ]] ; then
        last_version=$(curl -Ls "https://api.github.com/repos/archnets/node/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}Failed to detect archnets version (GitHub API limit?). Try again later or specify a version manually.${plain}"
            exit 1
        fi
        echo -e "${green}Detected latest version: ${last_version}. Starting installation...${plain}"
        url="https://github.com/archnets/node/releases/download/${last_version}/archnets-node-linux-${arch}.zip"
        curl -sL "$url" | pv -s 30M -W -N "Download progress" > /usr/local/archnets/archnets-node-linux.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Failed to download archnets. Please ensure your server can access GitHub files.${plain}"
            exit 1
        fi
    else
        last_version=$version_param
        url="https://github.com/archnets/node/releases/download/${last_version}/archnets-node-linux-${arch}.zip"
        curl -sL "$url" | pv -s 30M -W -N "Download progress" > /usr/local/archnets/archnets-node-linux.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Failed to download archnets $1. Please ensure this version exists.${plain}"
            exit 1
        fi
    fi

    unzip archnets-node-linux.zip
    rm archnets-node-linux.zip -f
    chmod +x node
    mkdir /etc/archnets/ -p
    cp geoip.dat /etc/archnets/
    cp geosite.dat /etc/archnets/
    cp geoip_iran.dat /etc/archnets/ 2>/dev/null || true
    cp geosite_iran.dat /etc/archnets/ 2>/dev/null || true
    if [[ x"${release}" == x"alpine" ]]; then
        rm /etc/init.d/archnets -f
        cat <<EOF > /etc/init.d/archnets
#!/sbin/openrc-run

name="archnets"
description="archnets"

command="/usr/local/archnets/node"
command_args="server"
command_user="root"

pidfile="/run/node.pid"
command_background="yes"

depend() {
        need net
}
EOF
        chmod +x /etc/init.d/archnets
        rc-update add archnets default
        echo -e "${green}archnets ${last_version}${plain} installed and enabled at boot"
    else
        rm /etc/systemd/system/archnets.service -f
        cat <<EOF > /etc/systemd/system/archnets.service
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
WorkingDirectory=/usr/local/archnets/
ExecStart=/usr/local/archnets/node server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl stop archnets
        systemctl enable archnets
        echo -e "${green}archnets ${last_version}${plain} installed and enabled at boot"
    fi

    if [[ ! -f /etc/archnets/config.yml ]]; then
        # If full CLI parameters were provided, generate config and skip interactive prompts
        if [[ -n "$API_HOST_ARG" && -n "$SERVER_ID_ARG" && -n "$SECRET_KEY_ARG" ]]; then
            generate_ppnode_config "$API_HOST_ARG" "$SERVER_ID_ARG" "$SECRET_KEY_ARG"
            echo -e "${green}/etc/archnets/config.yml generated from parameters${plain}"
            first_install=false
        else
            cp config.yml /etc/archnets/
            first_install=true
        fi
    else
        if [[ x"${release}" == x"alpine" ]]; then
            service archnets start
        else
            systemctl start archnets
        fi
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo -e "${green}archnets restarted successfully${plain}"
        else
            echo -e "${red}archnets may have failed to start. Please run 'node log' to view logs.${plain}"
        fi
        first_install=false
    fi

    curl -o /usr/bin/node -Ls https://raw.githubusercontent.com/archnets/node/master/scripts/node.sh
    chmod +x /usr/bin/node

    cd $cur_dir
    rm -f install.sh
    echo "------------------------------------------"
    echo "archnets management script usage:"
    echo "------------------------------------------"
    echo "node              - Show management menu (more features)"
    echo "node start        - Start archnets"
    echo "node stop         - Stop archnets"
    echo "node restart      - Restart archnets"
    echo "node status       - Show archnets status"
    echo "node enable       - Enable archnets at boot"
    echo "node disable      - Disable archnets at boot"
    echo "node log          - View archnets logs"
    echo "node generate     - Generate archnets config file"
    echo "node update       - Update archnets"
    echo "node update x.x.x - Install a specific archnets version"
    echo "node install      - Install archnets"
    echo "node uninstall    - Uninstall archnets"
    echo "node version      - Show archnets version"
    echo "------------------------------------------"

    if [[ $first_install == true ]]; then
        read -rp "Detected first-time installation of archnets. Generate /etc/archnets/config.yml automatically? (y/n): " if_generate
        if [[ "$if_generate" =~ ^[Yy]$ ]]; then
            # Interactive prompts with example defaults
            read -rp "Panel API address [format: https://example.com/]: " api_host
            api_host=${api_host:-https://example.com/}
            read -rp "Server ID: " server_id
            server_id=${server_id:-1}
            read -rp "Secret key: " secret_key

            # Generate the config file (overwrites any template that may have been copied from the package)
            generate_ppnode_config "$api_host" "$server_id" "$secret_key"
        else
            echo "${green}Skipped automatic config generation. To generate later, run: node generate${plain}"
        fi
    fi
}

parse_args "$@"
echo -e "${green}Starting installation${plain}"
install_base
setup_strongswan
install_ppnode "$VERSION_ARG"
