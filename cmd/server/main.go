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

	// Initialize NVD Client for the scanner logic
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
	// This connects the 'Start Scan' button to your Phase 1 engine logic
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
		for _, p := range openPorts {
			raw := scanner.GrabBanner(target, p, 2*time.Second)
			info := audit.ParseBanner(raw)
			cves, _ := nvdClient.FetchCVEs(info.Product, info.Version)
			allCVEs = append(allCVEs, cves...)
		}

		// Calculate Score
		finalScore := audit.CalculateRiskScore(allCVEs)

		// Persist to Database
		_, err = database.Exec("INSERT INTO scans (ip, risk_score) VALUES (?, ?)", target, finalScore)
		if err != nil {
			http.Error(w, "Failed to save scan", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "success", "score": %d}`, finalScore)
	})

	// 4. Static File Server
	fs := http.FileServer(http.Dir("./ui"))
	http.Handle("/", fs)

	// 5. Start Server
	port := ":8080"
	log.Printf("🚀 SME-Shield Dashboard running at http://localhost%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}