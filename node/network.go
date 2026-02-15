package node

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Network variables for mocking in tests
var (
	GetDefaultInterface = getDefaultInterfaceImpl
	GetLocalIP          = getLocalIPImpl
	GetGatewayMAC       = getGatewayMACImpl
)

// getDefaultInterfaceImpl returns the default network interface name
func getDefaultInterfaceImpl() (string, error) {
	// ip route show default | awk '{print $5}'
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run ip route: %v", err)
	}

	// Output format: default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.2 metric 100
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "default") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "dev" && i+1 < len(fields) {
					return fields[i+1], nil
				}
			}
		}
	}

	return "", fmt.Errorf("default interface not found")
}

// getLocalIPImpl returns the IPv4 address of the specified interface
func getLocalIPImpl(interfaceName string) (string, error) {
	if interfaceName == "" {
		return "", fmt.Errorf("interface name cannot be empty")
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get addresses for interface %s: %v", interfaceName, err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no IPv4 address found for interface %s", interfaceName)
}

// getGatewayMACImpl returns the MAC address of the default gateway
func getGatewayMACImpl() (string, error) {
	// First get the default gateway IP
	gatewayIP, err := getDefaultGatewayIP()
	if err != nil {
		return "", err
	}

	// Try ip neigh show first
	mac, err := getMacFromIpNeigh(gatewayIP)
	if err == nil && mac != "" {
		return mac, nil
	}

	// Fallback to /proc/net/arp
	return getMacFromProcNetArp(gatewayIP)
}

func getDefaultGatewayIP() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run ip route: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "default") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "via" && i+1 < len(fields) {
					return fields[i+1], nil
				}
			}
		}
	}
	return "", fmt.Errorf("default gateway IP not found")
}

func getMacFromIpNeigh(ip string) (string, error) {
	cmd := exec.Command("ip", "neigh", "show", "to", ip)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// 192.168.1.1 dev eth0 lladdr 00:1c:73:0b:4b:de REACHABLE
	outStr := string(output)
	if strings.Contains(outStr, "lladdr") {
		fields := strings.Fields(outStr)
		for i, field := range fields {
			if field == "lladdr" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("mac not found in ip neigh output")
}

func getMacFromProcNetArp(ipAddr string) (string, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		// IP address       HW type     Flags       HW address            Mask     Device
		// 192.168.1.1      0x1         0x2         00:1c:73:0b:4b:de     *        eth0
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == ipAddr {
			return fields[3], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("mac not found in /proc/net/arp for ip %s", ipAddr)
}
