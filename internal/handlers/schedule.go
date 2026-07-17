// Package scheduler runs security audits automatically on a configurable
// interval. Each schedule is stored in SQLite and survives restarts.
package scheduler

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/audit"
	"github.com/rjeff-sudo/sme-shield/internal/hub"
	"github.com/rjeff-sudo/sme-shield/internal/models"
)

// Schedule represents one recurring scan job.
type Schedule struct {
	ID          int64      `json:"id"`
	IP          string     `json:"ip"`
	Label       string     `json:"label"`
	IntervalHrs int        `json:"interval_hrs"`
	Enabled     bool       `json:"enabled"`
	LastRun     *time.Time `json:"last_run"`
	NextRun     time.Time  `json:"next_run"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Scheduler polls the database every minute and fires any overdue scans.
type Scheduler struct {
	db     *sql.DB
	engine *audit.Engine
	hub    *hub.Hub
}

// New creates a Scheduler.
func New(db *sql.DB, engine *audit.Engine, hub *hub.Hub) *Scheduler {
	return &Scheduler{db: db, engine: engine, hub: hub}
}

// Start begins the polling loop in a background goroutine.
func (s *Scheduler) Start() {
	go s.loop()
	log.Println("[scheduler] started — polling every 60s")
}

func (s *Scheduler) loop() {
	s.tick() // run once immediately on startup
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.tick()
	}
}

// tick checks for any enabled schedules whose next_run is in the past.
func (s *Scheduler) tick() {
	now := time.Now().UTC().Format(time.RFC3339)

	rows, err := s.db.Query(`
		SELECT id, ip, label, interval_hrs
		FROM schedules
		WHERE enabled = 1 AND next_run <= ?
		ORDER BY next_run ASC`, now)
	if err != nil {
		log.Printf("[scheduler] query error: %v", err)
		return
	}
	defer rows.Close()

	type due struct {
		id          int64
		ip          string
		label       string
		intervalHrs int
	}
	var jobs []due
	for rows.Next() {
		var j due
		if err := rows.Scan(&j.id, &j.ip, &j.label, &j.intervalHrs); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	rows.Close()

	for _, j := range jobs {
		log.Printf("[scheduler] firing — %s (%s)", j.ip, j.label)
		go s.runScan(j.id, j.ip, j.intervalHrs)
	}
}

// runScan executes an audit and updates last_run and next_run.
func (s *Scheduler) runScan(scheduleID int64, ip string, intervalHrs int) {
	now     := time.Now()
	nextRun := now.Add(time.Duration(intervalHrs) * time.Hour).UTC().Format(time.RFC3339)

	// Update times immediately so a second tick doesn't double-fire.
	_, err := s.db.Exec(`
		UPDATE schedules SET last_run = ?, next_run = ? WHERE id = ?`,
		now.UTC().Format(time.RFC3339), nextRun, scheduleID)
	if err != nil {
		log.Printf("[scheduler] update schedule %d: %v", scheduleID, err)
		return
	}

	onProgress := func(pct int, msg string) {
		s.hub.SendProgress(pct, fmt.Sprintf("[Scheduled] %s — %s", ip, msg))
	}
	onPortFound := func(port models.Port) {
		s.hub.SendPortFound(ip, port)
	}

	result, err := s.engine.Run(ip, onProgress, onPortFound)
	if err != nil {
		log.Printf("[scheduler] audit failed for %s: %v", ip, err)
		s.hub.SendError(fmt.Sprintf("Scheduled scan of %s failed: %s", ip, err.Error()))
		return
	}

	s.hub.SendComplete(result)
	log.Printf("[scheduler] complete — %s score: %d", ip, result.RiskScore)
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

// Create adds a new schedule.
func (s *Scheduler) Create(ip, label string, intervalHrs int) (Schedule, error) {
	if ip == "" {
		return Schedule{}, fmt.Errorf("ip is required")
	}
	if intervalHrs < 1 {
		intervalHrs = 24
	}
	now     := time.Now().UTC()
	nextRun := now.Add(time.Duration(intervalHrs) * time.Hour)

	res, err := s.db.Exec(`
		INSERT INTO schedules (ip, label, interval_hrs, enabled, next_run, created_at)
		VALUES (?, ?, ?, 1, ?, ?)`,
		ip, label, intervalHrs,
		nextRun.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)
	if err != nil {
		return Schedule{}, fmt.Errorf("insert schedule: %w", err)
	}
	id, _ := res.LastInsertId()
	return Schedule{
		ID: id, IP: ip, Label: label,
		IntervalHrs: intervalHrs, Enabled: true,
		NextRun: nextRun, CreatedAt: now,
	}, nil
}

// List returns all schedules ordered by next_run.
func (s *Scheduler) List() ([]Schedule, error) {
	rows, err := s.db.Query(`
		SELECT id, ip, label, interval_hrs, enabled, last_run, next_run, created_at
		FROM schedules ORDER BY next_run ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Schedule
	for rows.Next() {
		var sc Schedule
		var lastRunStr *string
		var nextRunStr, createdAtStr string
		var enabled int
		if err := rows.Scan(
			&sc.ID, &sc.IP, &sc.Label, &sc.IntervalHrs,
			&enabled, &lastRunStr, &nextRunStr, &createdAtStr,
		); err != nil {
			continue
		}
		sc.Enabled   = enabled == 1
		sc.NextRun, _ = time.Parse(time.RFC3339, nextRunStr)
		sc.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
		if lastRunStr != nil {
			t, _ := time.Parse(time.RFC3339, *lastRunStr)
			sc.LastRun = &t
		}
		out = append(out, sc)
	}
	if out == nil {
		out = []Schedule{}
	}
	return out, nil
}

// Toggle enables or disables a schedule.
func (s *Scheduler) Toggle(id int64, enabled bool) error {
	val := 0
	if enabled { val = 1 }
	res, err := s.db.Exec(`UPDATE schedules SET enabled = ? WHERE id = ?`, val, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("schedule %d not found", id)
	}
	return nil
}

// Delete removes a schedule permanently.
func (s *Scheduler) Delete(id int64) error {
	res, err := s.db.Exec(`DELETE FROM schedules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("schedule %d not found", id)
	}
	return nil
}

// RunNow fires an immediate scan for a schedule regardless of next_run.
func (s *Scheduler) RunNow(id int64) error {
	var ip string
	var intervalHrs int
	err := s.db.QueryRow(
		`SELECT ip, interval_hrs FROM schedules WHERE id = ?`, id).
		Scan(&ip, &intervalHrs)
	if err == sql.ErrNoRows {
		return fmt.Errorf("schedule %d not found", id)
	}
	if err != nil {
		return err
	}
	go s.runScan(id, ip, intervalHrs)
	return nil
}