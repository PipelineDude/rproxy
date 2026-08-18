# rproxy benchmark results

- Date: 2026-06-27 17:48
- Host: 12th Gen Intel(R) Core(TM) i5-12450H, 12 logical cores
- Load: `wrk -t4 -c100 -d10s` (keep-alive), pinned to cores 4-7
- Backend: nginx returns `200 OK` (2-byte body), pinned cores 0-1
- Proxy under test: pinned cores 2-3, 2 workers each (rproxy workers=2 / nginx worker_processes=2)
- rproxy BEFORE/AFTER a round of hot-path optimization: combining the response head+body into
  one write, removing a redundant double-parse, and a load-balancer fix
- 3 runs per scenario (after 1 warmup); median reported.

## Raw runs

### Backend ceiling (wrk -> backend :8081)
```
  run1:    362123.93 req/s   lat 292.02us
  run2:    362163.20 req/s   lat 292.95us
  run3:    370764.92 req/s   lat 285.53us
```
**median: 362163.20 req/s**

### rproxy BEFORE :8080
```
  run1:    135700.79 req/s   lat 741.82us
  run2:    136719.82 req/s   lat 741.49us
  run3:    133967.44 req/s   lat 750.81us
```
**median: 135700.79 req/s**

### rproxy AFTER :8080
```
  run1:    189810.00 req/s   lat 557.83us
  run2:    189146.76 req/s   lat 578.00us
  run3:    191012.24 req/s   lat 533.11us
```
**median: 189810.00 req/s**

### nginx reverse proxy :8085
> (first attempt on :8082 collided with a pre-existing system nginx already bound
> to that port — re-run on the free port 8085, same pinning/workers/backend.)
```
  run1:    150331.06 req/s   lat 677.52us
  run2:    153484.52 req/s   lat 661.71us
  run3:    153569.97 req/s   lat 660.92us
```
**median: 153484.52 req/s**

## Summary (median req/s)

| Scenario | req/s | avg lat | vs nginx |
|---|---:|---:|---:|
| Backend ceiling (no proxy) | 362163 | 292µs | — |
| nginx reverse proxy | 153484 | 662µs | 1.00x |
| rproxy BEFORE | 135700 | 742µs | **0.88x** (behind) |
| rproxy AFTER | 189810 | 557µs | **1.24x** (ahead) 🏆 |

**🏆 rproxy AFTER beats nginx by ~24% (189810 vs 153484 req/s) and has lower latency (557µs vs 662µs).**

**Optimization gain: +39.87% (135700 → 189810 req/s)** — turned a 12%-behind-nginx result into 24%-ahead.

**Headroom: rproxy AFTER = 52.4% of backend ceiling (362163).** The proxy, not the box/backend, is the bottleneck → further proxy optimization can still move the number; the rig is not the ceiling.

### Conditions / caveats
- 2 workers on 2 P-cores each (rproxy & nginx); load gen and backend on separate P-cores. Equal-core, apples-to-apples.
- Tiny 2-byte keep-alive response (the case where head+body coalescing helps most). Larger bodies / non-keep-alive / TLS may differ.
- Single backend, co-located on one box. Low run-to-run variance (<2%), so the 24% margin is real signal.
- Not yet done: a perf flamegraph analysis to locate the next bottleneck.
