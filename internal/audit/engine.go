package audit

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/models"
	"github.com/rjeff-sudo/sme-shield/internal/network"
	"github.com/rjeff-sudo/sme-shield/internal/scanner"
	"github.com/rjeff-sudo/sme-shield/platform/nvd"
)

type ProgressFunc func(percent int, message string)

type PortFoundFunc func(port models.Port)

type Engine struct {
	cfg    models.Config
	db     *sql.DB
	nvdCli *nvd.Client
}

func NewEngine(cfg models.Config, db *sql.DB, nvdCli *nvd.Client) *Engine {
	return &Engine{cfg: cfg, db: db, nvdCli: nvdCli}
}

func (e *Engine) Run(
	ctx context.Context,
	ip string,
	onProgress ProgressFunc,
	onPortFound PortFoundFunc,
) (models.ScanResult, error) {
	return e.RunAs(ctx, 0, ip, onProgress, onPortFound)
}

// RunAs runs a scan and attributes the persisted result to userID
// (0 = unattributed/legacy). All HTTP-triggered scans pass the session user.
func (e *Engine) RunAs(
	ctx context.Context,
	userID int64,
	ip string,
	onProgress ProgressFunc,
	onPortFound PortFoundFunc,
) (models.ScanResult, error) {

	result := models.ScanResult{
		IP:       ip,
		ScanTime: time.Now(),
	}

	onProgress(2, fmt.Sprintf("Resolving hostname for %s", ip))
	result.Hostname = resolveHostname(ip)

	onProgress(5, fmt.Sprintf("Scanning %d ports on %s ...", len(e.cfg.Scanner.Ports), ip))

	timeout := time.Duration(e.cfg.Scanner.TimeoutMs) * time.Millisecond
	openPorts := scanner.RunWorkerPool(
		ip,
		e.cfg.Scanner.Ports,
		e.cfg.Scanner.WorkerCount,
		timeout,
	)
	sort.Ints(openPorts)

	total := len(openPorts)
	onProgress(10, fmt.Sprintf("Found %d open port(s) on %s", total, ip))

	if total == 0 {
		result.RiskScore = 100
		result.Summary = BuildSummary(nil)
		onProgress(100, "No open ports found — host appears clean")
		e.persist(userID, result)
		return result, nil
	}

	bannerTimeout := time.Duration(e.cfg.Scanner.BannerTimeoutMs) * time.Millisecond
	var allCVEs []models.CVE

	for i, portNum := range openPorts {
		// Check for cancellation before each port analysis.
		if ctx.Err() != nil {
			return result, ctx.Err()
		}

		pct := 10 + int(float64(i)/float64(total)*80)
		onProgress(pct, fmt.Sprintf("Analysing port %d (%d of %d)", portNum, i+1, total))

		raw := scanner.GrabBanner(ip, portNum, bannerTimeout)
		svcInfo := scanner.ParseBanner(raw, portNum)
		svcName := scanner.ServiceName(portNum)

		port := models.Port{
			Number:      portNum,
			Protocol:    "tcp",
			Service:     svcName,
			ServiceInfo: svcInfo,
		}

		if svcInfo.Product != "Unknown" && svcInfo.Version != "Unknown" {
			cves, err := e.nvdCli.Lookup(svcInfo.Product, svcInfo.Version)
			if err != nil {
				log.Printf("[audit] NVD lookup %s %s: %v", svcInfo.Product, svcInfo.Version, err)
			} else {
				for idx := range cves {
					cves[idx].Fix = Remediation(cves[idx].ID, svcInfo.Product)
				}
				port.Vulnerabilities = cves
				allCVEs = append(allCVEs, cves...)
			}
		}

		result.OpenPorts = append(result.OpenPorts, port)
		onPortFound(port)
	}

	onProgress(92, "Calculating risk score")
	result.RiskScore = CalculateScore(allCVEs)
	result.Summary = BuildSummary(allCVEs)

	onProgress(97, "Saving results to database")
	id, err := e.persist(userID, result)
	if err == nil {
		result.ID = id
	}

	onProgress(100, "Audit complete")
	return result, nil
}

func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// RunSubnet discovers all devices on cidr and audits each one sequentially.
// Results are attributed to userID. It sends progress updates via onProgress
// and results via onDeviceComplete.
func (e *Engine) RunSubnet(
	ctx context.Context,
	userID int64,
	cidr string,
	onProgress ProgressFunc,
	onDeviceComplete func(models.ScanResult),
) ([]models.ScanResult, error) {

	onProgress(0, "Discovering devices on "+cidr)

	timeout := time.Duration(e.cfg.Discovery.TimeoutMs) * time.Millisecond
	devices, err := network.DiscoverDevices(
		cidr, e.cfg.Discovery.ProbePorts, e.cfg.Discovery.WorkerCount, timeout)
	if err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	if len(devices) == 0 {
		onProgress(100, "No devices found")
		return nil, nil
	}

	onProgress(5, fmt.Sprintf("Found %d device(s) — starting audits", len(devices)))

	var results []models.ScanResult
	for i, dev := range devices {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		pct := 5 + int(float64(i)/float64(len(devices))*95)
		onProgress(pct, fmt.Sprintf("Auditing %s (%d of %d)", dev.IP, i+1, len(devices)))

		onPortFound := func(port models.Port) {}
		onProg := func(pct int, msg string) {
			onProgress(pct, fmt.Sprintf("[%s] %s", dev.IP, msg))
		}

		result, err := e.RunAs(ctx, userID, dev.IP, onProg, onPortFound)
		if err != nil {
			if ctx.Err() != nil {
				return results, ctx.Err()
			}
			log.Printf("[audit] subnet scan: %s failed: %v", dev.IP, err)
			continue
		}
		result.Hostname = dev.Hostname
		results = append(results, result)
		onDeviceComplete(result)
	}

	onProgress(100, fmt.Sprintf("Subnet audit complete — %d device(s) scanned", len(results)))
	return results, nil
}

func (e *Engine) persist(userID int64, r models.ScanResult) (int64, error) {
	if e.db == nil {
		return 0, fmt.Errorf("no database connection")
	}

	res, err := e.db.Exec(
		`INSERT INTO scans (ip, hostname, risk_score, scan_time, user_id) VALUES (?, ?, ?, ?, ?)`,
		r.IP, r.Hostname, r.RiskScore, r.ScanTime, userID,
	)
	if err != nil {
		log.Printf("[db] insert scan: %v", err)
		return 0, err
	}

	scanID, _ := res.LastInsertId()

	for _, p := range r.OpenPorts {
		_, err := e.db.Exec(
			`INSERT INTO scan_results
			   (scan_id, port, service, product, version, cve_count)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			scanID,
			p.Number,
			p.Service,
			p.ServiceInfo.Product,
			p.ServiceInfo.Version,
			len(p.Vulnerabilities),
		)
		if err != nil {
			log.Printf("[db] insert port %d: %v", p.Number, err)
		}
	}

	return scanID, nil
}
