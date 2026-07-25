#!/usr/bin/env bash
# build.sh — Production rebuild script for AutoAR
# Usage:
#   ./build.sh          # Smart rebuild (recompile Go source only, fast ~3-4 min)
#   ./build.sh --full   # Full rebuild from scratch (slow ~15-20 min)
#   ./build.sh --restart  # Rebuild + restart container

set -euo pipefail
cd "$(dirname "$0")"

FULL_BUILD=0
RESTART=0
for arg in "$@"; do
  case $arg in
    --full)    FULL_BUILD=1 ;;
    --restart) RESTART=1 ;;
  esac
done

echo "[build] AutoAR production build started at $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

if [ "$FULL_BUILD" -eq 1 ]; then
  echo "[build] Full rebuild (--no-cache)..."
  docker build --no-cache --progress=plain -t autoar:latest .
else
  echo "[build] Smart rebuild (source layers only)..."
  # Minimal Dockerfile: reuses golang:1.25-bookworm cached layers,
  # only recompiles cmd/ + internal/ — takes ~3-4 minutes vs 15-20 for full.
  cat > /tmp/Dockerfile.autoar.rebuild << 'EOF'
FROM autoar:latest AS runtime_base
FROM golang:1.25-bookworm AS recompiler
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /app/autoar ./cmd/autoar && \
    cd /app/internal/scanner/entrypoint && \
    CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /app/autoar-entrypoint .
FROM runtime_base
COPY --from=recompiler /app/autoar /usr/local/bin/autoar
COPY --from=recompiler /app/autoar-entrypoint /usr/local/bin/autoar-entrypoint
EOF
  docker build -f /tmp/Dockerfile.autoar.rebuild --progress=plain -t autoar:latest .
fi

echo "[build] Image built successfully:"
docker images autoar:latest --format "  ID={{.ID}}  Size={{.Size}}  Created={{.CreatedAt}}"

if [ "$RESTART" -eq 1 ]; then
  echo "[build] Restarting autoar-api container..."
  docker compose up -d --force-recreate autoar-api
  echo "[build] Waiting for health check..."
  for i in $(seq 1 12); do
    sleep 5
    STATUS=$(docker inspect autoar-api --format '{{.State.Health.Status}}' 2>/dev/null || echo "unknown")
    echo "  [$i] Health: $STATUS"
    if [ "$STATUS" = "healthy" ]; then
      echo "[build] Container is healthy!"
      break
    fi
  done
fi

echo "[build] Done at $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
