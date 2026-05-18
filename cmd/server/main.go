package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/rjeff-sudo/network-audit/internals/audit"
	"github.com/rjeff-sudo/network-audit/internals/models"
	"github.com/rjeff-sudo/network-audit/internals/scanner"
	"github.com/rjeff-sudo/network-audit/platform/db"
	"github.com/rjeff-sudo/network-audit/platform/network"
	"github.com/rjeff-sudo/network-audit/platform/nvd"
)

// ScanHistory matches the structure of our 'scans' table for JSON output
type ScanHistory struct {
	ID        int       `json:"id"`
	IP        string    `json:"ip"`
	Score     int       `json:"score"`
	Timestamp time.Time `json:"timestamp"`
}

// Global cache for discovered devices
var (
	discoveredDevicesMutex sync.RWMutex
	discoveredDevices      []network.Device
)

func main() {
	// 1. Setup Phase
	database, err := db.InitDB("./audit.db")
	if err != nil {
		log.Fatalf("❌ Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Initialize NVD Client
	nvdClient := nvd.NewClient()
	nvdClient.DB = database

	// 2. API Endpoint: Fetch Scan History
	http.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		rows, err := database.Query("SELECT id, ip, risk_score, timestamp FROM scans ORDER BY timestamp DESC")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var history []ScanHistory
		for rows.Next() {
			var h ScanHistory
			err := rows.Scan(&h.ID, &h.IP, &h.Score, &h.Timestamp)
			if err != nil {
				continue
			}
			history = append(history, h)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(history)
	})

	// 3. API Endpoint: Get Local Subnet Information
	http.HandleFunc("/api/subnet", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		subnet, err := network.GetLocalSubnet()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to detect subnet: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(subnet)
	})

	// 4. API Endpoint: Discover Active Devices on a Subnet
	http.HandleFunc("/api/discover", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			CIDR   string `json:"cidr"`
			Subnet string `json:"subnet"`
		}

		json.NewDecoder(r.Body).Decode(&req)
		
		cidr := req.CIDR
		if cidr == "" {
			cidr = req.Subnet
		}
		
		if cidr == "" {
			http.Error(w, "CIDR or subnet required", http.StatusBadRequest)
			return
		}

		devices, err := network.DiscoverActiveDevices(cidr, 1*time.Second, 20)
		if err != nil {
			http.Error(w, fmt.Sprintf("Discovery failed: %v", err), http.StatusInternalServerError)
			return
		}

		// Cache discovered devices
		discoveredDevicesMutex.Lock()
		discoveredDevices = devices
		discoveredDevicesMutex.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if devices == nil {
			devices = []network.Device{}
		}
		json.NewEncoder(w).Encode(devices)
	})

	// 4b. API Endpoint: Get cached discovered devices
	http.HandleFunc("/api/cached-devices", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		discoveredDevicesMutex.RLock()
		devices := discoveredDevices
		discoveredDevicesMutex.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		if devices == nil {
			devices = []network.Device{}
		}
		json.NewEncoder(w).Encode(devices)
	})

	// 5. API Endpoint: Trigger a New Scan
	http.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Target   string   `json:"target"`
			Targets  []string `json:"targets"`
			IPRange  string   `json:"ip_range"`
		}

		json.NewDecoder(r.Body).Decode(&req)

		var targets []string

		// Determine targets from request
		if len(req.Targets) > 0 {
			targets = req.Targets
		} else if req.Target != "" {
			targets = []string{req.Target}
		} else if req.IPRange != "" {
			// Parse IP range
			parsed, err := network.ParseIPRange(req.IPRange)
			if err != nil {
				http.Error(w, fmt.Sprintf("Invalid IP range: %v", err), http.StatusBadRequest)
				return
			}
			targets = parsed
		} else {
			// Default to localhost
			targets = []string{"127.0.0.1"}
		}

		ports := []int{22, 80, 443, 8080, 3306}

		// Scan each target
		var allResults []map[string]interface{}
		for _, target := range targets {
			// Execute Scanner Logic
			openPorts := scanner.WorkerPoolScan(target, ports, 10)
			
			var allCVEs []models.CVE
			
			// Temporary storage for individual port findings to save after we get Scan ID
			type resultEntry struct {
				port    int
				info    models.ServiceInfo
				cveJSON []byte
			}
			var findings []resultEntry

			for _, p := range openPorts {
				raw := scanner.GrabBanner(target, p, 2*time.Second)
				info := audit.ParseBanner(raw)
				cves, _ := nvdClient.FetchCVEs(info.Product, info.Version)
				
				allCVEs = append(allCVEs, cves...)

				// Prepare data for scan_results table
				cveData, _ := json.Marshal(cves)
				findings = append(findings, resultEntry{
					port:    p,
					info:    info,
					cveJSON: cveData,
				})
			}

			// Calculate Score
			finalScore := audit.CalculateRiskScore(allCVEs)

			// Persist Main Scan Header
			res, err := database.Exec("INSERT INTO scans (ip, risk_score) VALUES (?, ?)", target, finalScore)
			if err != nil {
				log.Printf("❌ Error saving scan header for %s: %v", target, err)
				continue
			}

			// Get the ID to link our results
			scanID, _ := res.LastInsertId()

			// Persist Individual Port Findings
			for _, f := range findings {
				_, err = database.Exec(`
					INSERT INTO scan_results (scan_id, port, service, version, vulnerabilities) 
					VALUES (?, ?, ?, ?, ?)`,
					scanID, f.port, f.info.Product, f.info.Version, string(f.cveJSON))
				if err != nil {
					log.Printf("⚠️ Error saving port %d for %s: %v", f.port, target, err)
				}
			}

			allResults = append(allResults, map[string]interface{}{
				"ip":      target,
				"score":   finalScore,
				"scan_id": scanID,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"results": allResults,
		})
	})

	// 6. API Endpoint: Fetch Scan Details
	http.HandleFunc("/api/details", func(w http.ResponseWriter, r *http.Request) {
		scanID := r.URL.Query().Get("id")
		if scanID == "" {
			http.Error(w, "Missing scan ID", http.StatusBadRequest)
			return
		}

		rows, err := database.Query(`
			SELECT port, service, version, vulnerabilities 
			FROM scan_results 
			WHERE scan_id = ?`, scanID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var details []map[string]interface{}
		for rows.Next() {
			var port int
			var service, version, vuls string
			rows.Scan(&port, &service, &version, &vuls)

			details = append(details, map[string]interface{}{
				"port":            port,
				"service":         service,
				"version":         version,
				"vulnerabilities": json.RawMessage(vuls),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(details)
	})

	// 7. Static File Server
	fs := http.FileServer(http.Dir("./ui"))
	http.Handle("/", fs)

	// 8. Start Server
	port := ":8080"
	log.Printf("🚀 SME-Shield Dashboard running at http://localhost%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}