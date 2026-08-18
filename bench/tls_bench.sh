#!/usr/bin/env bash
#
# tls_bench.sh — HTTPS (TLS) throughput for rproxy.
# Backend is nginx (multi-threaded). Run under sudo with the memlock raised:
#   sudo bash -c 'ulimit -l unlimited && cd /path/to/rproxy && ./bench/tls_bench.sh'
#
# Usage:   ./bench/tls_bench.sh [wrk_args]
#          WRK_ARGS="-t4 -c100 -d10s" ./bench/tls_bench.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WRK_ARGS="${WRK_ARGS:--t4 -c100 -d10s --timeout 5s}"
BACKEND_PORT=8081
TLS_PORT=8443

command -v wrk >/dev/null || { echo "!! wrk is required" >&2; exit 1; }
command -v nginx >/dev/null || { echo "!! nginx is required for the raw-backend ceiling" >&2; exit 1; }
command -v openssl >/dev/null || { echo "!! openssl is required" >&2; exit 1; }
[ -x "$ROOT/target/release/rproxy" ] || {
    echo "!! rproxy release binary missing. Build it FIRST as your user (NOT under sudo," >&2
    echo "   otherwise target/ becomes root-owned):  cd $ROOT && cargo build --release" >&2
    exit 1
}

WORK="$(mktemp -d)"
trap 'kill $NGINX_PID $RPROXY_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "==> clearing stale processes from aborted runs"
pkill -f 'target/release/rproxy' 2>/dev/null || true
pkill -x nginx 2>/dev/null || true
sleep 0.5

echo "==> generating self-signed cert"
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

cat > "$WORK/tls.yml" <<EOF
listen:
  - "127.0.0.1:0"
tls_listen:
  - "127.0.0.1:$TLS_PORT"
tls_cert: "$WORK/cert.pem"
tls_key: "$WORK/key.pem"
workers: "2"
default:
  - "127.0.0.1:$BACKEND_PORT"
EOF

# nginx as raw backend.
cat > "$WORK/nginx.conf" <<EOF
worker_processes 4;
error_log /dev/null;
pid $WORK/nginx.pid;
events { worker_connections 8192; }
http {
    access_log off;
    server {
        listen 127.0.0.1:$BACKEND_PORT;
        location / { default_type text/plain; return 200 "OK"; }
    }
}
EOF
nginx -c "$WORK/nginx.conf" -p "$WORK/"
NGINX_PID=$(cat "$WORK/nginx.pid")
echo "==> nginx raw backend on :$BACKEND_PORT (pid $NGINX_PID)"

sleep 0.5
echo "==> starting rproxy (TLS) on :$TLS_PORT"
"$ROOT/target/release/rproxy" -c "$WORK/tls.yml" >/dev/null 2>&1 &
RPROXY_PID=$!
sleep 1

run_wrk() {
    local name="$1" url="$2" extra="$3"
    local best=0
    for i in 1 2 3; do
        local out
        out=$(wrk $extra $WRK_ARGS "$url" 2>/dev/null | awk '/Requests\/sec/{print $2}')
        [ -n "$out" ] && awk -v a="$best" -v b="$out" 'BEGIN{print (b>a)?b:a}' >/tmp/wrk_best
        best=$(cat /tmp/wrk_best)
    done
    printf "  %-16s %s req/s (best of 3)\n" "$name" "$best"
}

echo
echo "==> $WRK_ARGS"
run_wrk "raw backend"   "http://127.0.0.1:$BACKEND_PORT/"   ""
run_wrk "rproxy TLS"    "https://127.0.0.1:$TLS_PORT/"      ""

echo "==> done (TLS proxy shut down)"
