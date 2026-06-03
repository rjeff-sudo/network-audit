// Package network handles local subnet detection and active host discovery.
package network

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/models"
)

// GetLocalSubnet returns the CIDR string (e.g. "192.168.1.0/24") of the first
// active, non-loopback IPv4 interface found on this machine.
func GetLocalSubnet() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		// Skip down interfaces and loopback.
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
			// Return the network address in CIDR form.
			// e.g. if the machine is 192.168.1.42/24, return "192.168.1.0/24".
			ip := ipNet.IP.Mask(ipNet.Mask)
			return fmt.Sprintf("%s/%d", ip.String(), maskBits(ipNet.Mask)), nil
		}
	}

	return "", fmt.Errorf("no active IPv4 interface found")
}

// DiscoverDevices sweeps every host address in cidr and returns those that
// respond on at least one of the probe ports. workerCount goroutines run
// concurrently to keep the sweep fast.
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

// allHostIPs returns all usable host addresses in ipNet, excluding the
// network address (all host bits 0) and broadcast (all host bits 1).
func allHostIPs(ipNet *net.IPNet) []string {
	var ips []string

	// Start from the network address and increment.
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

// isAlive tries each probe port and returns true on the first successful dial.
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