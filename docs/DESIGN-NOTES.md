# DESIGN NOTES — решения, вынесенные из кода

2026-08-16. Длинные «почему»-комментарии перенесены сюда из кода (см.
`COMMENTING.md`). В коде остаётся 1-3 строки + ссылка на секцию.

---

## 1. Методология cycle_profile (src/cycles.rs)

Полное изложение. Кратко: см. модульный docstring `cycles.rs`.

**Архитектура.** Каждая инструментированная точка владеет `Site`: точный счётчик
вызовов, две бегущие суммы — **total** (инклюзивно: весь wall-clock вызова, включая
вложенные профилируемые функции) и **self** (total минус то, что измерили
вложенные профилируемые дети) — log2-бинированная гистограмма total (дешёвые
аппроксимированные перцентили за весь прогон) и ring-buffer последних сырых
значений. `self` отвечает на «где оптимизировать собственный код функции» без
двойного счёта вложенного профилируемого ребёнка.

**Self-time.** Через thread-local стек: `push_frame` перед замером, любой вложенный
`profile_cycles!` накапливает своё значение через `add_to_parent` во фрейм, который
возвращает `pop_frame`; внешний вызов вычитает его из своего total. Это точная
арифметика на реальных TSC-таймстампах, не оценка. Что НЕ учитывается — фиксированная
стоимость служебных операций `push_frame`/`pop_frame`/`record` (несколько атомиков,
обновление бакета гистограммы, ring-write), которая выполняется ВНЕ скобок каждого
ребёнка и поэтому не вычитается из родителя. Вложение `SITE_BUF_PUT` в
`build_upstream_head` пробовали и откатили (~28x инфляция reported min) — даже голый
атомарный счётчик без тайминга (~4.6x от 46 вызовов/запрос) был слишком дорог на
этой частоте вызовов. Сейчас ни одна точка не вложена в другую; `self`==`total` для
всех четырёх. Механизм сохранён — он корректен и бесплатен, пока не используется, на
случай будущей редкой/дорогой точки.

**RDTSCP, а не RDTSC.** RDTSCP почти сериализует и возвращает id ядра. Если вход и
выход на разных ядрах (миграция потока — rproxy не пинит потоки без
`cpu_affinity`) — дельта TSC бессмысленна для статистики ЭТОЙ точки, поэтому
сэмпл отбрасывается. Его (шумные, но реальные) такты всё равно передаются родителю
через `add_to_parent` — не приписать ничего значило бы тихо раздуть *self*-время
родителя на всю стоимость ребёнка.

**«Циклы» = TSC-тики, не литеральные циклы ядра.** На всех CPU проекта TSC
инвариантен (`constant_tsc`+`nonstop_tsc`). [`tsc_hz`] калибрует частоту
эмпирически (замер короткого сна), чтобы отчёт мог показать и реальное время.

**Только синхронные не-йолдинговые функции.** `async fn` с внутренним `.await`
может быть вытеснен single-threaded monoio-исполнителем между чтениями входа и
выхода — дельта включила бы время ДРУГИХ задач (стена, а не CPU). Воркеры rproxy
однопоточны (tasks на одном io_uring event-loop на prefork-процесс, без
`std::thread::spawn` на пути запроса). Нет сайтов для `check_filters`/`route`/
`contains_ci`/`find_ci`/`buf_put`: до первых двух реалистично добираться только
через полный async-путь, остальные слишком дёшевы/частотны — их частоту считают
аналитически, читая call sites.

**Measurement floor.** Сама последовательность read-call-read стоит несколько
тиков. [`calibrate`] замеряет этот пол раз в момент отчёта, и [`report`] печатает
его над таблицей — число, близкое к полу, читается как «шум», а не реальная цена.

---

## 2. `TestBackend`'s header-read fix (tests/e2e_scenarios.rs)

The original fixture called `read_to_end`, which blocks until the peer shuts
down the write side. rproxy pools/reuses backend connections (keep-alive) and
the health checker doesn't necessarily close either, so `read_to_end` never
returned — every e2e scenario hitting a live backend either hung ("did not
start serving") or the health checker's own probe timed out and marked the
backend DOWN before any client request landed. Fixed 2026-08-16 by reading
only up to the end of headers (`\r\n\r\n`), then draining exactly
`Content-Length` more bytes if present — enough to fully receive a POST body
without waiting for a connection close that may never come.

---

## 3. `jwt_authorized` caching (src/fast_proxy.rs)

Verifies `Authorization: Bearer <jwt>` against `secret`. A cached,
still-valid result for this exact token — cache key bound to the secret via
its truncated SHA-256 hash, so a cache hit under one secret can never replay
under a different one — short-circuits to true without re-checking the
signature. Otherwise the HMAC-SHA256 signature is checked and, on success,
the result is cached until the token's `exp`, capped at `JWT_CACHE_TTL_SECS`
so a token with an implausibly far-future `exp` cannot pin a cache entry
forever.

---

## 4. `serve_cache_hit`'s Connection rewrite (src/fast_proxy.rs)

Writes a cache hit to the client (304 with no body, or 200 with the cached
blob), then reports the keep-alive outcome. The 200 path rewrites the cached
`Connection: keep-alive` to `close` when the client asked to close, because
the stored blob is captured keep-alive-forced — sending it verbatim
would tell a closing client to trust a header the proxy then violates by
closing anyway. The rewrite's header/body boundary bug (a body that happened
to contain the literal string got corrupted) is fixed and regression-tested;
see the `cache_header_rewrite_does_not_corrupt_body` test.

---

## 5. `kill_proxy` reaps the whole prefork tree (tests/e2e_scenarios.rs)

rproxy is a prefork process: master forks workers + a health checker, and
`Child::kill` only kills the master — the workers linger as orphans and pile
up across test runs, eventually slowing the machine enough that later
scenarios fail their serve probe. `start_rproxy` starts the proxy in its own
process group (`process_group(0)`), so `kill_proxy` sends `SIGKILL` to the
whole group instead of just the master, reaping everything in one call.
