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
    echo "This software does not support 32-bit systems (x86). Please use a 64-bit system (x86_64). If detection is wrong, contact the author."
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
        echo -e "${red}Note: CentOS 7 cannot use hysteria1/2 protocol!${plain}\n"
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

confirm() {
    if [[ $# > 1 ]]; then
        echo && read -rp "$1 [default $2]: " temp
        if [[ x"${temp}" == x"" ]]; then
            temp=$2
        fi
    else
        read -rp "$1 [y/n]: " temp
    fi
    if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart() {
    confirm "Restart archnets?" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "${yellow}Press Enter to return to the main menu: ${plain}" && read temp
    show_menu
}

install() {
    bash <(curl -Ls https://raw.githubusercontent.com/archnets/node/master/scripts/install.sh)
    if [[ $? == 0 ]]; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
}

update() {
    if [[ $# == 0 ]]; then
        echo && echo -n -e "Enter specific version (default: latest): " && read version
    else
        version=$2
    fi
    bash <(curl -Ls https://raw.githubusercontent.com/archnets/node/master/scripts/install.sh) $version
    if [[ $? == 0 ]]; then
        echo -e "${green}Update complete. archnets has been restarted automatically. Use 'node log' to view logs.${plain}"
        exit
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

config() {
    echo "archnets will automatically attempt to restart after configuration changes."
    vi /etc/archnets/config.yml
    sleep 2
    restart
    check_status
    case $? in
        0)
            echo -e "archnets status: ${green}running${plain}"
            ;;
        1)
            echo -e "Detected that archnets is not running or auto-restart failed. View logs? [Y/n]" && echo
            read -e -rp "(default: y):" yn
            [[ -z ${yn} ]] && yn="y"
            if [[ ${yn} == [Yy] ]]; then
               show_log
            fi
            ;;
        2)
            echo -e "archnets status: ${red}not installed${plain}"
    esac
}

uninstall() {
    confirm "Are you sure you want to uninstall archnets?" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    if [[ x"${release}" == x"alpine" ]]; then
        service archnets stop
        rc-update del archnets
        rm /etc/init.d/archnets -f
    else
        systemctl stop archnets
        systemctl disable archnets
        rm /etc/systemd/system/archnets.service -f
        systemctl daemon-reload
        systemctl reset-failed
    fi
    rm /etc/archnets/ -rf
    rm /usr/local/archnets/ -rf

    echo ""
    echo -e "Uninstalled successfully. If you want to remove this script, exit and run ${green}rm /usr/bin/node -f${plain}"
    echo ""

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        echo ""
        echo -e "${green}archnets is already running. If you need to restart, choose Restart.${plain}"
    else
        if [[ x"${release}" == x"alpine" ]]; then
            service archnets start
        else
            systemctl start archnets
        fi
        sleep 2
        check_status
        if [[ $? == 0 ]]; then
            echo -e "${green}archnets started successfully. Use 'node log' to view logs.${plain}"
        else
            echo -e "${red}archnets may have failed to start. Please use 'node log' later to view log information.${plain}"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
    if [[ x"${release}" == x"alpine" ]]; then
        service archnets stop
    else
        systemctl stop archnets
    fi
    sleep 2
    check_status
    if [[ $? == 1 ]]; then
        echo -e "${green}archnets stopped successfully${plain}"
    else
        echo -e "${red}Failed to stop archnets. It may have taken longer than two seconds; please check logs later.${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
    if [[ x"${release}" == x"alpine" ]]; then
        service archnets restart
    else
        systemctl restart archnets
    fi
    sleep 2
    check_status
    if [[ $? == 0 ]]; then
        echo -e "${green}archnets restarted successfully. Use 'node log' to view logs.${plain}"
    else
        echo -e "${red}archnets may have failed to start. Please use 'node log' later to view logs.${plain}"
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
    if [[ x"${release}" == x"alpine" ]]; then
        service archnets status
    else
        systemctl status archnets --no-pager -l
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
    if [[ x"${release}" == x"alpine" ]]; then
        rc-update add archnets
    else
        systemctl enable archnets
    fi
    if [[ $? == 0 ]]; then
        echo -e "${green}archnets set to start at boot successfully${plain}"
    else
        echo -e "${red}Failed to set archnets to start at boot${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
    if [[ x"${release}" == x"alpine" ]]; then
        rc-update del archnets
    else
        systemctl disable archnets
    fi
    if [[ $? == 0 ]]; then
        echo -e "${green}archnets disabled from starting at boot successfully${plain}"
    else
        echo -e "${red}Failed to disable archnets from starting at boot${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    if [[ x"${release}" == x"alpine" ]]; then   
        echo -e "${red}Log viewing is not supported on Alpine systems for now.${plain}\n" && exit 1
    else
        journalctl -u archnets -e --no-pager -f
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

update_shell() {
    wget -O /usr/bin/node -N --no-check-certificate https://raw.githubusercontent.com/archnets/node/master/scripts/node.sh
    if [[ $? != 0 ]]; then
        echo ""
        echo -e "${red}Failed to download script. Please check if this machine can connect to GitHub.${plain}"
        before_show_menu
    else
        chmod +x /usr/bin/node
        echo -e "${green}Script upgraded successfully. Please rerun the script.${plain}" && exit 0
    fi
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

check_enabled() {
    if [[ x"${release}" == x"alpine" ]]; then
        temp=$(rc-update show | grep archnets)
        if [[ x"${temp}" == x"" ]]; then
            return 1
        else
            return 0
        fi
    else
        temp=$(systemctl is-enabled archnets)
        if [[ x"${temp}" == x"enabled" ]]; then
            return 0
        else
            return 1;
        fi
    fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        echo -e "${red}archnets is already installed. Please do not install again.${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        echo -e "${red}Please install archnets first.${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
        0)
            echo -e "archnets status: ${green}running${plain}"
            show_enable_status
            ;;
        1)
            echo -e "archnets status: ${yellow}not running${plain}"
            show_enable_status
            ;;
        2)
            echo -e "archnets status: ${red}not installed${plain}"
    esac
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "Start at boot: ${green}yes${plain}"
    else
        echo -e "Start at boot: ${red}no${plain}"
    fi
}

show_archnets_version() {
    echo -n "archnets version: "
    /usr/local/archnets/node version
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
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
  # Access log path, e.g., logs/access.log; set to "none" to disable access logs
  Access: none

Api:
  # Backend API address, e.g., "https://api.example.com"
  ApiHost: ${api_host}
  # Server unique identifier
  ServerID: ${server_id}
  # Secret key used to verify request legitimacy
  SecretKey: ${secret_key}
  # Request timeout (seconds)
  Timeout: 30
EOF
        echo -e "${green}archnets configuration file generated, restarting service...${plain}"
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
            echo -e "${red}archnets may have failed to start; use 'node log' to view logs.${plain}"
        fi
}

generate_config_file() {
    # Collect parameters interactively, with example defaults
    read -rp "Panel API address [format: https://example.com/]: " api_host
    api_host=${api_host:-https://example.com/}
    read -rp "Server ID: " server_id
    server_id=${server_id:-1}
    read -rp "Secret key: " secret_key

    # Generate the config file (overwrites any template copied from the package)
    generate_ppnode_config "$api_host" "$server_id" "$secret_key"
}

# Open firewall ports (effectively disables common firewalls)
open_ports() {
    systemctl stop firewalld.service 2>/dev/null
    systemctl disable firewalld.service 2>/dev/null
    setenforce 0 2>/dev/null
    ufw disable 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t mangle -F 2>/dev/null
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    netfilter-persistent save 2>/dev/null
    echo -e "${green}Successfully opened firewall ports!${plain}"
}

show_usage() {
    echo "archnets management script usage:"
    echo "------------------------------------------"
    echo "node              - Show management menu (more features)"
    echo "node start        - Start archnets"
    echo "node stop         - Stop archnets"
    echo "node restart      - Restart archnets"
    echo "node status       - View archnets status"
    echo "node enable       - Enable start at boot"
    echo "node disable      - Disable start at boot"
    echo "node log          - View archnets logs"
    echo "node generate     - Generate archnets config file"
    echo "node update       - Update archnets"
    echo "node update x.x.x - Install specific archnets version"
    echo "node install      - Install archnets"
    echo "node uninstall    - Uninstall archnets"
    echo "node version      - Show archnets version"
    echo "------------------------------------------"
}

show_menu() {
    echo -e "
  ${green}archnets backend management script,${plain}${red} not for Docker${plain}
--- https://github.com/archnets/node ---
  ${green}0.${plain} Edit configuration
————————————————
  ${green}1.${plain} Install archnets
  ${green}2.${plain} Update archnets
  ${green}3.${plain} Uninstall archnets
————————————————
  ${green}4.${plain} Start archnets
  ${green}5.${plain} Stop archnets
  ${green}6.${plain} Restart archnets
  ${green}7.${plain} View archnets status
  ${green}8.${plain} View archnets logs
————————————————
  ${green}9.${plain} Enable start at boot
  ${green}10.${plain} Disable start at boot
————————————————
  ${green}11.${plain} Show archnets version
  ${green}12.${plain} Upgrade maintenance script
  ${green}13.${plain} Generate archnets config file
  ${green}14.${plain} Open all VPS network ports
  ${green}15.${plain} Exit
 "
 # Future updates can be added to the above string
    show_status
    echo && read -rp "Please choose [0-15]: " num

    case "${num}" in
        0) config ;;
        1) check_uninstall && install ;;
        2) check_install && update ;;
        3) check_install && uninstall ;;
        4) check_install && start ;;
        5) check_install && stop ;;
        6) check_install && restart ;;
        7) check_install && status ;;
        8) check_install && show_log ;;
        9) check_install && enable ;;
        10) check_install && disable ;;
        11) check_install && show_archnets_version ;;
        12) update_shell ;;
        13) generate_config_file ;;
        14) open_ports ;;
        15) exit ;;
        *) echo -e "${red}Please enter a valid number [0-15]${plain}" ;;
    esac
}

if [[ $# > 0 ]]; then
    case $1 in
        "start") check_install 0 && start 0 ;;
        "stop") check_install 0 && stop 0 ;;
        "restart") check_install 0 && restart 0 ;;
        "status") check_install 0 && status 0 ;;
        "enable") check_install 0 && enable 0 ;;
        "disable") check_install 0 && disable 0 ;;
        "log") check_install 0 && show_log 0 ;;
        "update") check_install 0 && update 0 $2 ;;
        "config") config $* ;;
        "generate") generate_config_file ;;
        "install") check_uninstall 0 && install 0 ;;
        "uninstall") check_install 0 && uninstall 0 ;;
        "version") check_install 0 && show_archnets_version 0 ;;
        "update_shell") update_shell ;;
        *) show_usage
    esac
else
    show_menu
fi
