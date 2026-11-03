// Package scheduler runs security audits automatically on a configurable
// interval. Each schedule is stored in SQLite and survives restarts.
package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/audit"
	"github.com/rjeff-sudo/sme-shield/internal/auth"
	"github.com/rjeff-sudo/sme-shield/internal/hub"
	"github.com/rjeff-sudo/sme-shield/internal/models"
	"github.com/rjeff-sudo/sme-shield/platform/email"
	"github.com/rjeff-sudo/sme-shield/platform/report"
)

// Schedule represents one recurring scan job.
type Schedule struct {
	ID           int64      `json:"id"`
	UserID       int64      `json:"user_id"`
	IP           string     `json:"ip"`
	Label        string     `json:"label"`
	IntervalHrs  int        `json:"interval_hrs"`
	Enabled      bool       `json:"enabled"`
	EmailReport  bool       `json:"email_report"`
	LastRun      *time.Time `json:"last_run"`
	NextRun      time.Time  `json:"next_run"`
	CreatedAt    time.Time  `json:"created_at"`
	EmailSent    bool       `json:"email_sent"`
	EmailSentAt  *time.Time `json:"email_sent_at"`
}

// Scheduler polls the database every minute and fires any overdue scans.
type Scheduler struct {
	db      *sql.DB
	engine  *audit.Engine
	hub     *hub.Hub
	emailCli *email.Client
	auth    *auth.Auth
}

// New creates a Scheduler.
func New(db *sql.DB, engine *audit.Engine, hub *hub.Hub, emailCli *email.Client, authSvc *auth.Auth) *Scheduler {
	return &Scheduler{db: db, engine: engine, hub: hub, emailCli: emailCli, auth: authSvc}
}

// Start begins the polling loop in a background goroutine.
func (s *Scheduler) Start() {
	go s.loop()
	log.Println("[scheduler] started - polling every 60s")
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
		SELECT id, user_id, ip, label, interval_hrs, email_report
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
		userID      int64
		ip          string
		label       string
		intervalHrs int
		emailReport int
	}
	var jobs []due
	for rows.Next() {
		var j due
		if err := rows.Scan(&j.id, &j.userID, &j.ip, &j.label, &j.intervalHrs, &j.emailReport); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	rows.Close()

	for _, j := range jobs {
		log.Printf("[scheduler] firing - %s (%s)", j.ip, j.label)
		go s.runScan(j.id, j.userID, j.ip, j.intervalHrs, j.emailReport == 1)
	}
}

// runScan executes an audit and updates last_run and next_run.
// Results are attributed to the schedule's owner. If email_report is enabled and
// the owner has a verified email, the PDF report is emailed on completion.
func (s *Scheduler) runScan(scheduleID, userID int64, ip string, intervalHrs int, emailReport bool) {
	now     := time.Now()
	nextRun := now.Add(time.Duration(intervalHrs) * time.Hour).UTC().Format(time.RFC3339)

	// Update times immediately so a second tick doesn't double-fire.
	_, err := s.db.Exec(`
		UPDATE schedules SET last_run = ?, next_run = ?, email_sent = 0, email_sent_at = '' WHERE id = ?`,
		now.UTC().Format(time.RFC3339), nextRun, scheduleID)
	if err != nil {
		log.Printf("[scheduler] update schedule %d: %v", scheduleID, err)
		return
	}

	onProgress := func(pct int, msg string) {
		s.hub.SendProgress(pct, fmt.Sprintf("[Scheduled] %s - %s", ip, msg))
	}
	onPortFound := func(port models.Port) {
		s.hub.SendPortFound(ip, port)
	}

	result, err := s.engine.RunAs(context.Background(), userID, ip, onProgress, onPortFound)
	if err != nil {
		log.Printf("[scheduler] audit failed for %s: %v", ip, err)
		s.hub.SendError(fmt.Sprintf("Scheduled scan of %s failed: %s", ip, err.Error()))
		return
	}

	s.hub.SendComplete(result)
	log.Printf("[scheduler] complete - %s score: %d", ip, result.RiskScore)

	if emailReport && s.emailCli != nil && s.emailCli.IsConfigured() {
		go s.sendReportEmail(scheduleID, userID, result)
	}
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

// Create adds a new schedule owned by the given user.
func (s *Scheduler) Create(userID int64, ip, label string, intervalHrs int, emailReport bool) (Schedule, error) {
	if ip == "" {
		return Schedule{}, fmt.Errorf("ip is required")
	}
	if intervalHrs < 1 {
		intervalHrs = 24
	}
	now     := time.Now().UTC()
	nextRun := now.Add(time.Duration(intervalHrs) * time.Hour)

	res, err := s.db.Exec(`
		INSERT INTO schedules (user_id, ip, label, interval_hrs, enabled, next_run, created_at, email_report, email_sent, email_sent_at)
		VALUES (?, ?, ?, ?, 1, ?, ?, ?, 0, '')`,
		userID, ip, label, intervalHrs,
		nextRun.Format(time.RFC3339),
		now.Format(time.RFC3339),
		0,
	)
	if err != nil {
		return Schedule{}, fmt.Errorf("insert schedule: %w", err)
	}
	id, _ := res.LastInsertId()
	return Schedule{
		ID: id, UserID: userID, IP: ip, Label: label,
		IntervalHrs: intervalHrs, Enabled: true, EmailReport: emailReport,
		NextRun: nextRun, CreatedAt: now,
	}, nil
}

// List returns the user's schedules ordered by next_run.
func (s *Scheduler) List(userID int64) ([]Schedule, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, ip, label, interval_hrs, enabled, last_run, next_run, created_at, email_report, email_sent, email_sent_at
		FROM schedules WHERE user_id = ? ORDER BY next_run ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Schedule
	for rows.Next() {
		var sc Schedule
		var lastRunStr *string
		var nextRunStr, createdAtStr, emailSentAtStr string
		var enabled, emailReport, emailSent int
		if err := rows.Scan(
			&sc.ID, &sc.UserID, &sc.IP, &sc.Label, &sc.IntervalHrs,
			&enabled, &lastRunStr, &nextRunStr, &createdAtStr,
			&emailReport, &emailSent, &emailSentAtStr,
		); err != nil {
			continue
		}
		sc.Enabled     = enabled == 1
		sc.EmailReport = emailReport == 1
		sc.EmailSent   = emailSent == 1
		sc.NextRun, _  = time.Parse(time.RFC3339, nextRunStr)
		sc.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
		if lastRunStr != nil {
			t, _ := time.Parse(time.RFC3339, *lastRunStr)
			sc.LastRun = &t
		}
		if emailSentAtStr != "" {
			t, _ := time.Parse(time.RFC3339, emailSentAtStr)
			sc.EmailSentAt = &t
		}
		out = append(out, sc)
	}
	if out == nil {
		out = []Schedule{}
	}
	return out, nil
}

// Toggle enables or disables a schedule owned by the given user.
func (s *Scheduler) Toggle(userID, id int64, enabled bool) error {
	val := 0
	if enabled { val = 1 }
	res, err := s.db.Exec(`UPDATE schedules SET enabled = ? WHERE id = ? AND user_id = ?`, val, id, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("schedule %d not found", id)
	}
	return nil
}

// Delete removes a schedule permanently (owner check applied).
func (s *Scheduler) Delete(userID, id int64) error {
	res, err := s.db.Exec(`DELETE FROM schedules WHERE id = ? AND user_id = ?`, id, userID)
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
// Only the owning user may trigger it.
func (s *Scheduler) RunNow(userID, id int64) error {
	var ip string
	var intervalHrs int
	var emailReport int
	err := s.db.QueryRow(
		`SELECT ip, interval_hrs, email_report FROM schedules WHERE id = ? AND user_id = ?`, id, userID).
		Scan(&ip, &intervalHrs, &emailReport)
	if err == sql.ErrNoRows {
		return fmt.Errorf("schedule %d not found", id)
	}
	if err != nil {
		return err
	}
	go s.runScan(id, userID, ip, intervalHrs, emailReport == 1)
	return nil
}

// sendReportEmail generates a PDF report for a completed scan and emails it to
// the owning user's verified address. It is best-effort: failures are logged and
// do not affect the scan result.
func (s *Scheduler) sendReportEmail(scheduleID, userID int64, result models.ScanResult) {
	if s.emailCli == nil || !s.emailCli.IsConfigured() {
		return
	}

	userEmail := s.auth.EmailForID(userID)
	if userEmail == "" || !s.auth.IsEmailVerifiedForID(userID) {
		log.Printf("[scheduler] skipping report email for scan %d - no verified email for user %d", result.ID, userID)
		return
	}

	data, err := report.LoadReportData(s.db, result.ID, userID)
	if err != nil {
		log.Printf("[scheduler] load report data for scan %d: %v", result.ID, err)
		return
	}

	pdf, err := report.Generate(data)
	if err != nil {
		log.Printf("[scheduler] pdf generation for scan %d: %v", result.ID, err)
		return
	}

	if err := s.emailCli.SendReport(userEmail, pdf, result.IP, result.ScanTime); err != nil {
		log.Printf("[scheduler] send report email for scan %d: %v", result.ID, err)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	s.db.Exec(`UPDATE schedules SET email_sent = 1, email_sent_at = ? WHERE id = ?`, now, scheduleID)
	log.Printf("[scheduler] report emailed for scan %d to %s", result.ID, userEmail)
}

// SetEmailReport toggles the email_report flag on a schedule.
func (s *Scheduler) SetEmailReport(userID, id int64, enabled bool) error {
	val := 0
	if enabled { val = 1 }
	res, err := s.db.Exec(`UPDATE schedules SET email_report = ? WHERE id = ? AND user_id = ?`, val, id, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("schedule %d not found", id)
	}
	return nil
}