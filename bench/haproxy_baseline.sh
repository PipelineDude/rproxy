#!/usr/bin/env bash
#
# haproxy_baseline.sh — rproxy vs HAProxy vs nginx vs raw backend on the SAME
# bench. All three proxies are measured back-to-back on one stand so the
# comparison is apples-to-apples.
#
# Backend is nginx (multi-threaded). Run under sudo with the memlock raised:
#   sudo bash -c 'ulimit -l unlimited && cd /path/to/rproxy && ./bench/haproxy_baseline.sh'
#
# Usage:   ./bench/haproxy_baseline.sh [wrk_args]
#          WRK_ARGS="-t4 -c100 -d10s" ./bench/haproxy_baseline.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WRK_ARGS="${WRK_ARGS:--t4 -c100 -d10s}"
BACKEND_PORT=8081
RPROXY_PORT=8080
HAPROXY_PORT=8082
NGINX_PROXY_PORT=8083

command -v wrk >/dev/null || { echo "!! wrk is required (apt install wrk)" >&2; exit 1; }
command -v nginx >/dev/null || { echo "!! nginx is required for the raw-backend ceiling" >&2; exit 1; }
[ -x "$ROOT/haproxy-2.8.5/haproxy" ] || { echo "!! vendored haproxy not built: $ROOT/haproxy-2.8.5/haproxy" >&2; exit 1; }
[ -f "$ROOT/bench_config.yml" ] || { echo "!! bench_config.yml missing" >&2; exit 1; }
[ -x "$ROOT/target/release/rproxy" ] || {
    echo "!! rproxy release binary missing. Build it FIRST as your user (NOT under sudo," >&2
    echo "   otherwise target/ becomes root-owned):  cd $ROOT && cargo build --release" >&2
    exit 1
}

echo "==> clearing stale processes from aborted runs"
pkill -f 'target/release/rproxy' 2>/dev/null || true
pkill -f 'haproxy-2.8.5/haproxy' 2>/dev/null || true
pkill -x nginx 2>/dev/null || true
sleep 0.5

# nginx as raw backend on BACKEND_PORT (return "OK", no disk I/O).
WORK="$(mktemp -d)"
trap 'kill $NGINX_PID $RPROXY_PID $HAPROXY_PID $NGINX_PROXY_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT
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
echo "==> starting rproxy on :$RPROXY_PORT"
"$ROOT/target/release/rproxy" -c "$ROOT/bench_config.yml" >/dev/null 2>&1 &
RPROXY_PID=$!

echo "==> starting haproxy on :$HAPROXY_PORT"
"$ROOT/haproxy-2.8.5/haproxy" -f "$ROOT/haproxy.cfg" >/dev/null 2>&1 &
HAPROXY_PID=$!

echo "==> starting nginx reverse proxy on :$NGINX_PROXY_PORT"
cat > "$WORK/nginx_proxy.conf" <<EOF
worker_processes 4;
error_log /dev/null;
pid $WORK/nginx_proxy.pid;
events { worker_connections 8192; }
http {
    access_log off;
    upstream bench { server 127.0.0.1:$BACKEND_PORT; keepalive 128; }
    server {
        listen 127.0.0.1:$NGINX_PROXY_PORT;
        location / {
            proxy_pass http://bench;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
    }
}
EOF
nginx -c "$WORK/nginx_proxy.conf" -p "$WORK/"
NGINX_PROXY_PID=$(cat "$WORK/nginx_proxy.pid")
sleep 1

run_wrk() {
    local name="$1" url="$2"
    local best_rps=0 best_lat="n/a"
    for i in 1 2 3; do
        local out rps lat
        out=$(wrk $WRK_ARGS "$url" 2>/dev/null)
        rps=$(echo "$out" | awk '/Requests\/sec/{print $2}')
        lat=$(echo "$out" | awk '/Latency/{print $2}')
        [ -n "$rps" ] && awk -v a="$best_rps" -v b="$rps" 'BEGIN{exit !(b>a)}' && {
            best_rps="$rps"
            best_lat="${lat:-n/a}"
        }
    done
    printf "  %-14s %10s req/s   avg lat %s\n" "$name" "$best_rps" "$best_lat"
}

echo
echo "==> $WRK_ARGS"
echo "==> median-of-3 best req/s"
run_wrk "raw backend"   "http://127.0.0.1:$BACKEND_PORT/"
run_wrk "rproxy"        "http://127.0.0.1:$RPROXY_PORT/"
run_wrk "haproxy"       "http://127.0.0.1:$HAPROXY_PORT/"
run_wrk "nginx proxy"   "http://127.0.0.1:$NGINX_PROXY_PORT/"

echo "==> done (proxies shut down)"
