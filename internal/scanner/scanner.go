// Package scanner handles concurrent TCP port scanning and service identification.
package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// RunWorkerPool scans all ports against ip using workerCount goroutines.
// Returns a slice of open port numbers (order is non-deterministic).
func RunWorkerPool(ip string, ports []int, workerCount int, timeout time.Duration) []int {
	portsCh := make(chan int, len(ports))
	resultsCh := make(chan int, len(ports))

	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsCh {
				if isOpen(ip, port, timeout) {
					resultsCh <- port
				}
			}
		}()
	}

	// Feed all ports into the work channel then close so workers exit cleanly.
	for _, p := range ports {
		portsCh <- p
	}
	close(portsCh)

	// Close results once every worker has finished.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var open []int
	for p := range resultsCh {
		open = append(open, p)
	}
	return open
}

// isOpen dials a single TCP port and returns true if the connection succeeds.
func isOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// WorkerPoolScan manages concurrent scanning
func WorkerPoolScan(ip string, ports []int, workerCount int) []int {
	var openPorts []int
	portsChan := make(chan int, workerCount)
	resultsChan := make(chan int)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				if ScanPort(ip, port, 500*time.Millisecond) {
					resultsChan <- port
				}
			}
		}()
	}

	// Send ports to workers
	go func() {
		for _, p := range ports {
			portsChan <- p
		}
		close(portsChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for p := range resultsChan {
		openPorts = append(openPorts, p)
	}

	return openPorts
}

// GrabBanner attempts to read the service banner from an open port
func GrabBanner(ip string, port int, timeout time.Duration) string {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set a deadline for reading so we don't hang forever
	conn.SetReadDeadline(time.Now().Add(timeout))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "Unknown Service"
	}

	return string(buffer[:n])
}