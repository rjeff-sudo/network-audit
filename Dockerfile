# ── Stage 1: Builder ─────────────────────────────────────────────────────────
# Full Go image with GCC — needed because go-sqlite3 uses CGO (C bindings).
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Download dependencies first — this layer is cached unless go.mod changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and compile a statically-linked binary.
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-w -s" \
    -o bin/sme-shield \
    ./cmd/server

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Minimal Alpine image — no Go toolchain, no GCC, just what's needed to run.
FROM alpine:3.19

# sqlite-libs  — runtime library for go-sqlite3
# ca-certificates — needed for NVD HTTPS API calls
# tzdata        — needed for Africa/Nairobi timezone
RUN apk add --no-cache sqlite-libs ca-certificates tzdata

WORKDIR /app

# Copy only the compiled binary and static assets.
COPY --from=builder /app/bin/sme-shield ./sme-shield
COPY --from=builder /app/ui             ./ui
COPY --from=builder /app/config.yaml    ./config.yaml

# /app/data holds audit.db — mount a volume here to persist scan history.
RUN mkdir -p /app/data

EXPOSE 8080

CMD ["./sme-shield"]
