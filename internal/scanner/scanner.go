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
