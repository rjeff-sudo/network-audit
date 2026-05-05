package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/rjeff-sudo/network-audit/platform/db"
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
	// Initialize SQLite Database
	database, err := db.InitDB("./audit.db")
	if err != nil {
		log.Fatalf("❌ Failed to initialize database: %v", err)
	}
	defer database.Close()

	// 2. API Endpoint: Fetch Scan History
	// This replaces our console print with a JSON response for the browser
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

	// 3. Static File Server
	// This tells Go to serve our index.html and assets from the /ui folder
	fs := http.FileServer(http.Dir("./ui"))
	http.Handle("/", fs)

	// 4. Start Server
	port := ":8080"
	log.Printf("🚀 SME-Shield Dashboard running at http://localhost%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}