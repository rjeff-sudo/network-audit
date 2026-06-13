# SME-Shield

**Network security auditing for small and medium-sized businesses.**

SME-Shield scans your local network, discovers active devices, identifies
vulnerable services, and delivers a plain-English PDF report — so any
business owner can understand and act on the findings. No IT degree required.

Built by [Ronnie Jeff](https://github.com/rjeff-sudo) · Kenya

---

## What it does

- Detects all active devices on your local network
- Scans 23 common ports per device
- Grabs service banners to identify exact software versions
- Queries the NIST National Vulnerability Database for known CVEs
- Calculates a 0-100 security score with logarithmic risk weighting
- Generates a downloadable PDF report with plain-English remediation advice
- Streams live audit progress over WebSocket

---

## Running SME-Shield

### Option A — Docker (no Go required)

Requires Docker on a Linux machine.

```bash
git clone https://github.com/rjeff-sudo/sme-shield.git
cd sme-shield
mkdir -p data
docker build -t sme-shield:latest .
docker run -d -p 8080:8080 -v $(pwd)/data:/app/data --name sme-shield sme-shield:latest
```

Open `http://localhost:8080` in your browser.

To access from other devices on the same network, find your machine IP first:

```bash
hostname -I | awk '{print $1}'
```

Then on any device on the same network open:

```
http://<your-machine-ip>:8080
```

> **Note on device discovery:** For the network scanner to detect devices
> on your local network, the app must run directly on a machine inside that
> network. Docker with `-p` port mapping limits discovery to the container
> network. If you need full device discovery, use Option B below.

---

### Option B — Run directly (recommended for network scanning)

Requires Go 1.22+ and GCC installed.

```bash
git clone https://github.com/rjeff-sudo/sme-shield.git
cd sme-shield

# Set Go paths (add these to ~/.bashrc to make permanent)
export GOPATH=$HOME/go
export GOMODCACHE=$HOME/go/pkg/mod

# Install dependencies
go mod tidy

# Build and run
make run
```

Open `http://localhost:8080` in your browser.

---

### Stopping the app

```bash
# If running with Docker
docker stop sme-shield

# If running with make
Ctrl+C
```

---

### Restarting after a reboot

```bash
# Docker — starts automatically if you used --restart unless-stopped
docker start sme-shield

# Or rebuild and run
make run
```

---

## Configuration

All settings live in `config.yaml` — no code changes needed.

```yaml
server:
  port: 8080          # change the port here

nvd:
  api_key: ""         # add a free NVD API key for faster CVE lookups
                      # get one at: https://nvd.nist.gov/developers/request-an-api-key
```

An NVD API key raises the CVE lookup rate limit from 5 requests/30s to
50 requests/30s. Free and instant to get — strongly recommended.

---

## Project structure

```
sme-shield/
├── cmd/server/         entry point
├── internal/
│   ├── audit/          scan engine, risk scoring, remediation advice
│   ├── handlers/       HTTP handlers (scan, discovery, history, reports)
│   ├── hub/            WebSocket pub/sub
│   ├── models/         shared types
│   ├── network/        subnet detection, device discovery
│   └── scanner/        port scanning, banner grabbing
├── platform/
│   ├── db/             SQLite connection, versioned migrations
│   ├── nvd/            NVD API client, 7-day CVE cache
│   └── report/         PDF generation
├── ui/                 frontend (HTML, CSS, JS)
├── config.yaml
├── Dockerfile
└── docker-compose.yml
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Go 1.22 |
| Database | SQLite (go-sqlite3) |
| Real-time | WebSocket (gorilla/websocket) |
| CVE data | NIST NVD API 2.0 |
| PDF | gofpdf |
| Frontend | Vanilla HTML / CSS / JS |
| Container | Docker multi-stage build |

---

## Contact

Interested in this project or want to discuss network security tools
for East African businesses?

- **GitHub** — [github.com/rjeff-sudo](https://github.com/rjeff-sudo)
- **Email** — *fitchcharles989@gmail.com*
- **LinkedIn** — *https://linkedin.com/rjeff-sudo*

---

## License

MIT — free to use, modify, and distribute.