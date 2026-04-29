package main

import (
	"fmt"
	"time"

	"github.com/rjeff-sudo/network-audit/internals/audit"
	"github.com/rjeff-sudo/network-audit/internals/scanner"
	"github.com/rjeff-sudo/network-audit/platform/nvd"
)

func main() {
	target := "127.0.0.1"
	ports := []int{22, 80, 443, 8080}
	nvdClient := nvd.NewClient()

	fmt.Printf("🛡️ Starting Security Audit for %s...\n\n", target)

	openPorts := scanner.WorkerPoolScan(target, ports, 5)

	for _, p := range openPorts {
		fmt.Printf("Found Open Port: %d\n", p)
		
		// 1. Grab Banner
		rawBanner := scanner.GrabBanner(target, p, 2*time.Second)
		fmt.Printf("  └─ Raw Banner: %s\n", rawBanner)

		// 2. Parse Banner
		info := audit.ParseBanner(rawBanner)
		fmt.Printf("  └─ Identified: %s (Version: %s)\n", info.Product, info.Version)

		// 3. Fetch CVEs
		cves, err := nvdClient.FetchCVEs(info.Product, info.Version)
		if err != nil {
			fmt.Printf("  └─ ⚠️ NVD Error: %v\n", err)
			continue
		}

		fmt.Printf("  └─ Vulnerabilities Found: %d\n", len(cves))
		for i, cve := range cves {
			if i >= 3 { break } // Only show top 3 for the test
			fmt.Printf("     - [%s] Score: %.1f\n", cve.ID, cve.Score)
		}
		fmt.Println()
	}
}