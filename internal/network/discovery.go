package network

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/models"
)

func GetLocalSubnet() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			ip := ipNet.IP.Mask(ipNet.Mask)
			return fmt.Sprintf("%s/%d", ip.String(), maskBits(ipNet.Mask)), nil
		}
	}

	return "", fmt.Errorf("no active IPv4 interface found")
}

func DiscoverDevices(
	cidr string,
	probePorts []int,
	workerCount int,
	timeout time.Duration,
) ([]models.Device, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	ips := allHostIPs(ipNet)

	ipsCh := make(chan string, len(ips))
	devsCh := make(chan models.Device, len(ips))

	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipsCh {
				if isAlive(ip, probePorts, timeout) {
					devsCh <- models.Device{
						IP:       ip,
						Hostname: lookupHostname(ip),
						Active:   true,
					}
				}
			}
		}()
	}

	for _, ip := range ips {
		ipsCh <- ip
	}
	close(ipsCh)

	go func() {
		wg.Wait()
		close(devsCh)
	}()

	var devices []models.Device
	for d := range devsCh {
		devices = append(devices, d)
	}
	return devices, nil
}

func allHostIPs(ipNet *net.IPNet) []string {
	var ips []string

	ip := make(net.IP, 4)
	copy(ip, ipNet.IP.To4().Mask(ipNet.Mask))

	for {
		incrementIP(ip)

		if !ipNet.Contains(ip) {
			break
		}
		if isBroadcast(ip, ipNet) {
			break
		}

		clone := make(net.IP, 4)
		copy(clone, ip)
		ips = append(ips, clone.String())
	}
	return ips
}

func isAlive(ip string, ports []int, timeout time.Duration) bool {
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func lookupHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func isBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	broadcast := make(net.IP, 4)
	for i := range broadcast {
		broadcast[i] = ipNet.IP.To4()[i] | ^ipNet.Mask[i]
	}
	return ip.Equal(broadcast)
}

func maskBits(mask net.IPMask) int {
	bits, _ := mask.Size()
	return bits
}

// Device represents an active device on the network
type Device struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	MAC      string `json:"mac"`
	Active   bool   `json:"active"`
}

// SubnetInfo contains information about the local subnet
type SubnetInfo struct {
	CIDR      string   `json:"cidr"`
	Network   string   `json:"network"`
	Broadcast string   `json:"broadcast"`
	FirstIP   string   `json:"first_ip"`
	LastIP    string   `json:"last_ip"`
}

// GetLocalSubnet detects the local subnet of the machine
func GetLocalSubnet() (*SubnetInfo, error) {
	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Look for the first active, non-loopback interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}

			// Calculate subnet info
			network := ipNet.Network()
			mask := ipNet.Mask

			// Calculate broadcast address
			broadcastIP := make(net.IP, 4)
			for i := range broadcastIP {
				broadcastIP[i] = ipNet.IP[i] | ^mask[i]
			}

			// Calculate first usable IP
			firstIP := make(net.IP, 4)
			copy(firstIP, ipNet.IP)
			firstIP[3] = firstIP[3] + 1

			// Calculate last usable IP
			lastIP := make(net.IP, 4)
			copy(lastIP, broadcastIP)
			lastIP[3] = lastIP[3] - 1

			return &SubnetInfo{
				CIDR:      ipNet.String(),
				Network:   network,
				Broadcast: broadcastIP.String(),
				FirstIP:   firstIP.String(),
				LastIP:    lastIP.String(),
			}, nil
		}
	}

	return nil, fmt.Errorf("no active network interface found")
}

// PingHost checks if a host is reachable using TCP connection attempt
func PingHost(ip string, ports []int, timeout time.Duration) bool {
	if len(ports) == 0 {
		ports = []int{22, 80, 443}
	}

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// DiscoverActiveDevices scans a subnet and returns all active devices
func DiscoverActiveDevices(cidr string, timeout time.Duration, workerCount int) ([]Device, error) {
	// Parse the CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var devices []Device
	devicesChan := make(chan Device, workerCount)
	ipsChan := make(chan string, workerCount)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipsChan {
				if PingHost(ip, []int{22, 80, 443, 445, 3306}, timeout) {
					hostname := getHostname(ip)
					devices := Device{
						IP:       ip,
						Hostname: hostname,
						Active:   true,
					}
					devicesChan <- devices
				}
			}
		}()
	}

	// Send IPs to workers
	go func() {
		for _, ip := range IPRange(ipNet) {
			ipsChan <- ip
		}
		close(ipsChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(devicesChan)
	}()

	for device := range devicesChan {
		devices = append(devices, device)
	}

	return devices, nil
}

// IPRange generates all IP addresses in a subnet
func IPRange(ipNet *net.IPNet) []string {
	var ips []string
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)
	ip = ip.Mask(ipNet.Mask)
	
	for ipNet.Contains(ip) {
		// Skip network and broadcast addresses
		if ip[3] > 0 && ip[3] < 255 {
			ips = append(ips, ip.String())
		}
		incrementIP(ip)
	}
	return ips
}

// incrementIP increments the last octet of an IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// getHostname attempts to get the hostname of an IP address
func getHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// ParseIPRange parses IP range inputs like "192.168.1.1-10" or "192.168.1.0/24"
func ParseIPRange(input string) ([]string, error) {
	// Check if it's a CIDR notation
	if strings.Contains(input, "/") {
		_, ipNet, err := net.ParseCIDR(input)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %w", err)
		}
		return IPRange(ipNet), nil
	}

	// Check if it's a range like "192.168.1.1-10"
	if strings.Contains(input, "-") {
		parts := strings.Split(input, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid range format")
		}

		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		if startIP == nil {
			return nil, fmt.Errorf("invalid start IP")
		}

		endPart := strings.TrimSpace(parts[1])
		endOctet := 0
		if _, err := fmt.Sscanf(endPart, "%d", &endOctet); err != nil {
			// Assume it's a full IP
			endIP := net.ParseIP(endPart)
			if endIP == nil {
				return nil, fmt.Errorf("invalid end IP")
			}
			return rangeIPs(startIP, endIP), nil
		}

		// Build end IP by replacing last octet
		endIP := make(net.IP, len(startIP))
		copy(endIP, startIP)
		endIP[3] = byte(endOctet)

		return rangeIPs(startIP, endIP), nil
	}

	// Single IP
	if net.ParseIP(input) != nil {
		return []string{input}, nil
	}

	return nil, fmt.Errorf("invalid IP or range format")
}

// rangeIPs generates all IPs between two IP addresses (inclusive)
func rangeIPs(startIP, endIP net.IP) []string {
	var ips []string
	for {
		ips = append(ips, startIP.String())
		if startIP.Equal(endIP) {
			break
		}
		incrementIP(startIP)
	}
	return ips
}
