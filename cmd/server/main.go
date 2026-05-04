package main

import (
	"fmt"
	"log"
	"time"

	"github.com/rjeff-sudo/network-audit/internals/audit"
	"github.com/rjeff-sudo/network-audit/internals/models"
	"github.com/rjeff-sudo/network-audit/internals/scanner"
	"github.com/rjeff-sudo/network-audit/platform/db"
	"github.com/rjeff-sudo/network-audit/platform/nvd"
)

func main() {
	// 1. Setup Phase
	target := "127.0.0.1"
	ports := []int{22, 80, 443, 8080, 3306} // Added some common SME ports
	
	// Initialize SQLite Database
	database, err := db.InitDB("./audit.db")
	if err != nil {
		log.Fatalf("❌ Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Initialize NVD Client with DB for caching
	nvdClient := nvd.NewClient()
	nvdClient.DB = database

	fmt.Printf("🛡️  Starting SME Security Audit for %s...\n", target)
	fmt.Println("--------------------------------------------------")

	// 2. Scanning Phase
	start := time.Now()
	openPorts := scanner.WorkerPoolScan(target, ports, 10)
	
	var allFoundCVEs []models.CVE

	// 3. Audit Phase
	for _, p := range openPorts {
		fmt.Printf("🔍 Found Open Port: %d\n", p)
		
		rawBanner := scanner.GrabBanner(target, p, 2*time.Second)
		info := audit.ParseBanner(rawBanner)
		fmt.Printf("   └─ Service: %s (%s)\n", info.Product, info.Version)

		cves, err := nvdClient.FetchCVEs(info.Product, info.Version)
		if err != nil {
			fmt.Printf("   └─ ⚠️  NVD Error: %v\n", err)
			continue
		}

		if len(cves) > 0 {
			fmt.Printf("   └─ 🚨 Vulnerabilities: %d found\n", len(cves))
			allFoundCVEs = append(allFoundCVEs, cves...)
		} else {
			fmt.Printf("   └─ ✅ No vulnerabilities found for this version.\n")
		}
	}

	// 4. Scoring & Results Phase
	finalScore := audit.CalculateRiskScore(allFoundCVEs)
	duration := time.Since(start)

	fmt.Println("--------------------------------------------------")
	fmt.Printf("📊 AUDIT COMPLETE in %v\n", duration)
	fmt.Printf("🏆 Final Security Score: %d/100\n", finalScore)
	
	if finalScore < 50 {
		fmt.Println("⚠️  CRITICAL: This network is highly vulnerable. Immediate remediation required.")
	} else if finalScore < 80 {
		fmt.Println("📢 WARNING: Several security issues detected.")
	} else {
		fmt.Println("✅ SUCCESS: Network security posture is strong.")
	}

	// 5. Persistence Phase
	_, err = database.Exec("INSERT INTO scans (ip, risk_score) VALUES (?, ?)", target, finalScore)
	if err != nil {
		log.Printf("❌ Failed to save scan results: %v", err)
	} else {
		fmt.Println("💾 Scan results saved to SQLite database.")
	}
}