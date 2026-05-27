package audit

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/models"
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
		e.persist(result)
		return result, nil
	}

	bannerTimeout := time.Duration(e.cfg.Scanner.BannerTimeoutMs) * time.Millisecond
	var allCVEs []models.CVE

	for i, portNum := range openPorts {
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
	id, err := e.persist(result)
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

func (e *Engine) persist(r models.ScanResult) (int64, error) {
	if e.db == nil {
		return 0, fmt.Errorf("no database connection")
	}

	res, err := e.db.Exec(
		`INSERT INTO scans (ip, hostname, risk_score, scan_time) VALUES (?, ?, ?, ?)`,
		r.IP, r.Hostname, r.RiskScore, r.ScanTime,
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