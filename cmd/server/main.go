package main

import (
	"fmt"
	"time"

	"github.com/rjeff-sudo/network-audit/internals/scanner"
)

func main() {
	target := "127.0.0.1" // Scanning localhost for safety
	// Common ports to test
	portsToScan := []int{21, 22, 23, 25, 53, 80, 443, 3306, 5432, 8080}

	fmt.Printf("🚀 Starting audit on %s...\n", target)
	start := time.Now()

	// Use 10 workers to scan the ports
	openPorts := scanner.WorkerPoolScan(target, portsToScan, 10)

	duration := time.Since(start)

	fmt.Printf("\n--- Scan Results ---\n")
	fmt.Printf("Target:     %s\n", target)
	fmt.Printf("Duration:   %v\n", duration)
	fmt.Printf("Open Ports: %v\n", openPorts)
	fmt.Printf("--------------------\n")
}