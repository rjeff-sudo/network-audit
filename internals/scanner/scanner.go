package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ScanPort attempts to open a connection to a specific port
func ScanPort(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
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