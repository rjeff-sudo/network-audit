# Sentry

**Network security auditing for small and medium-sized businesses.**
Built for Kenyan businesses — self-hosted, free, and no IT degree required.

[![CI](https://github.com/rjeff-sudo/sme-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/rjeff-sudo/sme-shield/actions/workflows/ci.yml)

> Sentry scans your local network, discovers active devices, identifies
> vulnerable services, and delivers plain-English PDF reports with actionable
> fix advice — so any business owner can understand and act on findings.

Built by [Ronnie Jeff](https://github.com/rjeff-sudo) · Kenya

---

## What it does

| Feature | Description |
|---------|-------------|
| Device discovery | Sweeps local subnet, finds all active devices in ~1-2s |
| Port scanning | 23 common ports per device with banner grabbing |
| Service identification | Regex parser extracts product + version from service banners |
| CVE lookup | Queries NIST NVD for known vulnerabilities per software version |
| Risk scoring | 0–100 logarithmic score with severity breakdown |
| PDF reports | Branded, plain-English reports with prioritised remediation advice |
| Live progress | WebSocket streaming of scan progress in real time |
| Scheduled scans | Run automatically every 6h/12h/24h/48h/7d |
| Subnet scan | Audit every discovered device in one click |
| Scan cancellation | Cancel a running audit (context-based cancellation) |
| Network Topology | SVG visual map of devices, colour-coded by risk |
| Device fingerprinting | Infers device type + OS from open ports and banners |
| Trend tracking | Charts score history per device over time |
| Multi-user auth | First-run setup, bcrypt hashing, session cookies |
| Email verification | Verify admin email before report delivery |
| Change password | Self-service password update in the dashboard |

---

## How it operates

```
Browser (ui/)
   │  HTTP + WebSocket
   ▼
Auth middleware (internal/auth)
   │  session cookie check
   ▼
HTTP handlers (internal/handlers)
   │  /api/scan · /api/discover · /api/history · /api/topology · ...
   ▼
Audit engine (internal/audit)  ←────  Scheduler (internal/scheduler)
   │                                   │  polls DB every 60s
   ▼                                   ▼
Scanner (internal/scanner) + NVD client (platform/nvd)
   │  TCP probes + CVE cache         │  SQLite CVE cache (7-day TTL)
   ▼
Risk scoring (internal/audit/scoring)
   │
   ▼
Results → SQLite (platform/db)  →  PDF report (platform/report)
   │                                 │
   ▼                                 ▼
WebSocket hub (internal/hub)      Email (platform/email)
```

### Scan lifecycle step-by-step

1. **Detect subnet** — the server reads your machine's active network
   interface to infer the local subnet (e.g. `192.168.1.0/24`).
2. **Discover devices** — every IP in the subnet gets probed on 5 quick
   ports (22, 80, 443, 445, 3306) with a 200 ms connection timeout across a
   50-worker pool. Anything answering is "alive".
3. **Audit each device** — for each device, all 23 configured ports are
   probed. Open ports get a banner grab; web ports get an HTTP probe to
   provoke a `Server:` header.
4. **Parse banners** — a 4-pattern regex parser extracts product + version
   (e.g. `OpenSSH_7.4`, `nginx/1.18.0`). Falls back to well-known port names.
5. **CVE lookup** — product + version are cached first (SQLite, 7-day TTL);
   cache misses hit the NVD API 2.0 respecting a rate limit (5 req/30 s,
   50 with a free API key).
6. **Score** — a logarithmic algorithm computes 0–100 (higher = safer) so
   the 20th critical CVE doesn't overwhelm the first.
7. **Persist + report** — results go to SQLite; a PDF report is generated
   on demand via `/api/report/<scan-id>`.
8. **Stream** — every step streams progress, port findings and completion
   events to the browser over WebSocket.

---

## API reference

All endpoints except the auth ones require a valid session cookie.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/setup` | GET | First-run setup page |
| `/api/setup` | POST | Create admin user (once) |
| `/login` | GET/POST | Login page + form |
| `/logout` | GET | Clear session |
| `/api/verify-email?token=` | GET | Email verification link |
| `/ws` | GET | WebSocket stream (progress events) |
| `/api/scan` | POST | Audit a single IP |
| `/api/scan/cancel` | POST | Cancel the running audit |
| `/api/scan/subnet` | POST | Audit the whole subnet |
| `/api/subnet` | GET | Detect local subnet |
| `/api/discover` | POST | Discover devices on subnet |
| `/api/history?limit=&offset=` | GET | Paginated scan history |
| `/api/history/{id}` | GET/DELETE | Scan detail / delete |
| `/api/report/{id}` | GET | Download PDF report |
| `/api/schedules` | GET/POST | List / create schedules |
| `/api/schedules/{id}` | PATCH/DELETE | Pause / resume / delete / run-now |
| `/api/settings/password` | POST | Change password |
| `/api/settings/email-status` | GET/POST | Email status / save email |
| `/api/settings/resend-verification` | POST | Resend verification email |
| `/api/topology` | GET | Topology map data |
| `/api/trends` | GET | Score history (all devices or one IP) |
| `/api/trends/devices` | GET | Per-device scan summary |

---

## Running Sentry

### Option A — Docker (quick)

```bash
git clone https://github.com/rjeff-sudo/sme-shield.git
cd sentry
docker compose up --build -d
```

Open `http://localhost:8080`. First visit redirects you to the /setup page.

> Docker's port mapping limits device discovery to the container network.
> For full LAN scanning use Option B.

### Option B — Run directly (recommended)

Requires Go 1.22+ and GCC (`sudo apt install gcc`).

```bash
make run          # builds bin/sentry and starts the server
```

Other targets:

```bash
make build        # build only
make test         # unit tests with coverage
make lint         # golangci-lint (install separately)
make clean        # remove binary + database
```

### First-time setup

1. Open `http://localhost:8080`
2. You're redirected to `/setup` — create the admin account
   (username, password, optional email)
3. Log in on `/login`
4. Done. Setup is permanently closed after the first account.

---

## Configuration

Everything lives in `config.yaml` — no code changes needed.

```yaml
server:
  port: 8080
  ui_dir: "./ui"
  db_path: "./data/audit.db"
  cors_origin: ""          # "" = same-origin only (most secure)

auth:
  session_secret: "<openssl rand -hex 32>"   # CHANGE THIS
  session_ttl_hours: 168                    # 7 days

scanner:
  worker_count: 100
  timeout_ms: 500
  ports: [21, 22, 23, 25, 53, 80, ...]      # 23 ports by default

discovery:
  worker_count: 50
  timeout_ms: 200                           # 200ms → /24 sweep in ~1-2s

nvd:
  api_key: ""      # free key raises limit 5→50 req/30s — strongly recommended
  cache_ttl_hours: 168

smtp:              # fill in to enable email verification + report delivery
  host: "smtp.gmail.com"
  port: 587
  username: ""
  password: ""     # Gmail: use an App Password, not your login password
  from_address: ""
```

### Email deliverability tips

- **Gmail**: use an [App Password](https://myaccount.google.com/apppasswords)
  (requires 2FA) — regular passwords fail.
- Set `from_address` to the same domain as your `username` — mismatched
  sender domains are a common spam trigger.
- The generated email includes `Reply-To`, `List-Unsubscribe`,
  `X-Mailer` and a multipart/alternative body to minimise spam score.
- For production, a transactional provider (SendGrid, Resend, AWS SES)
  beats SMTP and gives you domain authentication (SPF/DKIM/DMARC).

---

## Project structure

```
sentry/
├── cmd/server/         entry point, routes, middleware chain
├── internal/
│   ├── audit/          scan engine, risk scoring, remediation, tests
│   ├── auth/           sessions, bcrypt, setup flow
│   ├── handlers/       HTTP + WebSocket handlers
│   ├── hub/            WebSocket pub/sub (ping keepalives, write pump)
│   ├── models/         shared types
│   ├── network/        subnet detection, device discovery
│   ├── scanner/        port scanning, banner parsing, tests
│   ├── scheduler/      scheduled scans (SQLite-backed)
│   └── util/           shared helpers
├── platform/
│   ├── db/             SQLite, versioned migrations
│   ├── email/          SMTP client (TLS/STARTTLS)
│   ├── nvd/            NVD API client + cache
│   └── report/         gofpdf PDF generation
├── ui/                 dashboard, landing, login, setup pages
│   └── assets/         app.js, theme.css
├── .github/workflows/  CI + Docker publish
├── config.yaml
├── Dockerfile          multi-stage build (golang → alpine)
├── Makefile
└── docker-compose.yml
```

---

## DevOps

| What | How |
|------|-----|
| CI | GitHub Actions — builds + tests every push and PR |
| Container image | Published to GHCR on every push to `main` |
| Releases | Tag `v*` → Docker image tagged with the version |
| Tests | `go test ./internal/... -v -cover` |

---

## Contact

- **GitHub** — [github.com/rjeff-sudo](https://github.com/rjeff-sudo)
- **Email** — odhiambojeffronnie@gmail.com
- **LinkedIn** — linkedin.com/rjeff-sudo

---

## License

MIT — free to use, modify, and distribute.
