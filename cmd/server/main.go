package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/rjeff-sudo/network-audit/internals/audit"
	"github.com/rjeff-sudo/network-audit/internals/models"
	"github.com/rjeff-sudo/network-audit/internals/scanner"
	"github.com/rjeff-sudo/network-audit/platform/db"
	"github.com/rjeff-sudo/network-audit/platform/nvd"
)

// ScanHistory matches the structure of our 'scans' table for JSON output
type ScanHistory struct {
	ID        int       `json:"id"`
	IP        string    `json:"ip"`
	Score     int       `json:"score"`
	Timestamp time.Time `json:"timestamp"`
}

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

	// 3. API Endpoint: Trigger a New Scan
	http.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		target := "127.0.0.1"
		ports := []int{22, 80, 443, 8080, 3306}

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
			info := audit.ParseBanner(raw) // audit.ParseBanner now returns models.ServiceInfo
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
			log.Printf("❌ Error saving scan header: %v", err)
			http.Error(w, "Failed to save scan header", http.StatusInternalServerError)
			return
		}

		// Get the ID to link our results
		scanID, _ := res.LastInsertId()

		// Persist Individual Port Findings
		for _, f := range findings {

			fmt.Printf("🛠️ DEBUG: Found Port %d, saving to Scan ID %d\n", f.port, scanID)
			
			_, err = database.Exec(`
				INSERT INTO scan_results (scan_id, port, service, version, vulnerabilities) 
				VALUES (?, ?, ?, ?, ?)`,
				scanID, f.port, f.info.Product, f.info.Version, string(f.cveJSON))
			if err != nil {
				log.Printf("⚠️ Error saving port %d: %v", f.port, err)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "success", "score": %d, "scan_id": %d}`, finalScore, scanID)
	})

	// 4. API Endpoint: Fetch Scan Details (The one the "View Details" button calls)
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
				"vulnerabilities": json.RawMessage(vuls), // Use json.RawMessage to avoid double-encoding
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(details)
	})

	// 5. Static File Server
	fs := http.FileServer(http.Dir("./ui"))
	http.Handle("/", fs)

	// 6. Start Server
	port := ":8080"
	log.Printf("🚀 SME-Shield Dashboard running at http://localhost%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}