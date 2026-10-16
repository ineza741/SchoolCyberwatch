# School CyberWatch — Final Report

**Stabilisation & demo-readiness pass**
Date: 2026-10-08 · Git HEAD: `0451ca0` (12 commits) · Java 21.0.12 · Node v24.21.0 · Maven 3.9.9

---

## 1. Backend tests

`mvn test` → **57 tests, 0 failures, 0 errors, 0 skipped — BUILD SUCCESS**

Baseline was 56; **+1 new regression test**. Log: `%TEMP%\scw-mvn-final.log`.

---

## 2. Build

`npm run build` → **PASS** — 31 modules transformed, **264.83 kB JS / 32.50 kB CSS**.

CSS grew 31.01 → 32.50 kB solely because of the appended dark-theme readability block. No build errors or warnings.

---

## 3. Network total

**`590,473`** — exact OpenSearch count (`track_total_hits: true`) for rules **100300 + 100301** over one reported 72-hour window
(`2026-10-05T09:29:58Z → 2026-10-08T09:29:58Z`, measured **72.0000 h**).

- The old **`1,000` was a sample/page limit** (`getRecentEvents(1000)` capped at 1,000 raw alerts across 13 network rules), **not a total**.
- All three sources agree: `network/summary` = dashboard "Network alerts" = `stats?days=3` (452,222 + 138,251) = **590,473, delta 0**.
- **Not** claimed as permanently identical between requests: the window is re-anchored per request and ingestion continues. The delta was 0 in this run only because the endpoint agent is offline and generating no new events.

Breakdown:

| Rule | Count | Level → severity |
|---|---|---|
| 100300 inbound connections | 452,222 | 5 → Medium |
| 100301 network scans | 138,251 | 10 → High |
| **Total** | **590,473** | — |

(All 13 network rules together = 590,484, only +11; scope deliberately kept to 100300 + 100301 as specified.)

---

## 4. Network high-severity

**`138,251`** — exact, **matching scope and window** (same two rules, same 72 h), derived from `countAlertsByLevel` and graded by the **identical** `SecurityEventMapper` the event list uses (100301 = level 10 → High; 100300 = level 5 → Medium, correctly excluded).

Was **`230`** from the old 1,000-row sample.

**Affected endpoints: `1`** (exact `agent.name` terms aggregation, not sample-derived).

---

## 5. Agent status

**OFFLINE — and it is the true state, not a display bug.**

| Check | Result |
|---|---|
| Wazuh `GET /agents` | `001 WIN-HUR37I74T1G / 192.168.56.103` → **`disconnected`**, last keep-alive **2026-10-06T23:57:06Z** |
| Manager | `000 ubuntuserver` `active`; ports 9200 / 55000 / 1514 open; ping OK |
| Endpoint VM | ping **100% loss**, no ARP entry |
| `VBoxManage list runningvms` | only `ubuntu_server` — **Windows VM is powered off** |
| Backend `/api/endpoints` | `status: "Offline"` |

**No IP, adapter, credential, firewall, Wazuh config or service was changed.**

### Manual steps for you

1. Start the Windows VM in VirtualBox (guest `WIN-HUR37I74T1G`, IP **192.168.56.103**).
2. Keep it on the host-only adapter with IP 192.168.56.103.
3. Once booted, start the **Wazuh Agent** service (`services.msc` → *Wazuh Agent* → **Start**, or `net start WazuhSvc`).
4. Status flips to **Online** within ~1–2 minutes. **No backend restart needed.**

---

## 6. Per-feature status

| Feature | Status | Evidence |
|---|---|---|
| Login (valid + invalid) | ✅ **Working** | Friendly 401 on bad password; valid JWT issued |
| Dashboard (6 cards + stats×30) | ✅ **Working** | 6 cards, 7 types, 30 `overTime` days, no `undefined/null/NaN` |
| Alerts + filters | ✅ **Working** | `severity=High` → 20 rows all High; `search=Network` → 25 rows; rule/type filters pass |
| Alert detail modal | ✅ **Working** | Opens, 11 detail rows, in viewport, closes |
| Endpoints | ✅ **Working** | Agent 001 reported Offline, truthful |
| Incidents create/read/status/notes | ✅ **Working** | `201 id=8`; detail; `OPEN → INVESTIGATING`; note persisted; invalid status → `400` |
| Incident duplicate | ✅ **Working** | `409 {"error":"An incident already exists for this security alert."}`, count stayed 5 |
| Network 100300/100301 | ✅ **Working** | Both rules present in feed; exact summary |
| Reports / PDF | ✅ **Working** | 7/30/90 options, `%PDF` magic, HTTP 200 `application/pdf`, non-trivial size |
| 401 / logout / error & loading | ✅ **Working** | Session cleared, friendly notice, redirect once |

---

## 7. E2E / layout / smoke counts

| Suite | Result |
|---|---|
| Layout audit | **28 / 28** |
| Smoke (browser, read-only) | **12 / 12** |
| Contrast auditor (8 pages × 2 themes + modal) | **0 failures** — was 58 unique / 2,236 flags |
| Final API regression | **25 / 25** |
| Incident workflow | **12 / 12** |
| Browser E2E | **Not re-run this session** — it is destructive (creates an incident). Equivalent coverage verified above; prior session's run was **34/34** |
| Console / page errors | **None unexpected** (only the expected auth logs) |

---

## 8. UI files changed (2)

| File | Why |
|---|---|
| `Frontend/src/styles/global.css` | 41 colour corrections (each asserted against its expected hit count) **plus** one appended, labelled dark-theme block. **Colour values only** — no layout, spacing, type scale, navigation or branding change |
| `Frontend/src/pages/NetworkPage.jsx` | Truthful labels: `Total network events (72h)` / `High-severity network alerts (72h)`, tooltip with the exact ISO window + rule scope, footnote distinguishing exact counts from the bounded 200-row feed |

Worst offenders fixed: dark-mode table `strong` **1.30:1**, `.alert-rule` **2.07:1**, `.nav-label` / `.table-footnote` **2.56:1**, `.alert-desc` **2.93:1**.

---

## 9. Backend files changed (3) — all justified by Task 2

| File | Why |
|---|---|
| `service/NetworkMonitorService.java` | `getSummary()` now issues three `size:0` count/aggregation queries over a shared `Window` instead of downloading 1,000 rows; `NetworkSummary` extended with `windowHours` / `windowStart` / `windowEnd` / `countType`. Side benefit: the summary no longer touches the email pipeline |
| `service/WazuhIndexerClient.java` | Added `countAlertsByAgent()` — terms aggregation on `agent.name` for an exact distinct-endpoint count (never fetches alert rows) |
| `test/.../NetworkMonitorServiceTest.java` | New test locking in exact values, exact 72 h window, **no** `searchAlerts`, **no** email-pipeline interaction |

---

## 10. Git / secrets

- **12 commits, HEAD `0451ca0` — nothing committed, nothing staged by me, no reset.** My 5 files show as `M` / `AM` / `??` (the `A` on two of them pre-dates this session). Only `Backend/target/...` (2 tracked build-output files) changes as a side effect of running `mvn test`.
- `Backend/env.properties` — **gitignored, untracked, absent from `git status`, never modified.**
- All harnesses read credentials **at run time** and never print the password or JWT; **no secret appears in the transcript or in any new artifact.**

> ⚠️ **Pre-existing finding (not introduced here):** the real admin password is **already committed at HEAD** in `README.md`, `Backend/main/resources/application.properties` (Spring `${ADMIN_PASSWORD:…}` default) and `Backend/env.example.properties`. **Recommend rotating the credential and replacing those with placeholders.**

---

## 11. Remaining issues

1. **Pre-existing committed admin password** (above) — rotate + scrub.
2. `GET /api/endpoints` returns `lastSeen: ""` although Wazuh has `2026-10-06T23:57:06Z` — the Computers page cannot show "last seen". Left as-is (no backend change required by scope).
3. Alerts `?search=` matches text fields only, not IP addresses (`192.168.56.103` → 0 rows; `Network` → 25 rows).
4. SMTP still needs a Gmail App Password (out of scope); no backend incident DELETE endpoint (cleanup done via a guarded direct SQL delete).
5. Alert payloads still lack a `protocol` field.

**Database is clean:** **5 incidents / 3 notes** — exactly the pre-session baseline. Test incident `id=8` and its note were removed and verified (`TEST_TITLE_ROWS=0`, `SURVIVORS_UNCHANGED=true`).

---

## 12. DEMO READY: **YES**

The one thing that will read as "Offline" on stage is the Windows endpoint VM being powered off — that is **correct**, and the fix is starting the VM and its Wazuh Agent service (see item 5).
