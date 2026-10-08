# School CyberWatch — Frontend Progress Log

**Project:** School CyberWatch — "A Security Monitoring, Incident Detection, and
Alert Platform for Secondary Schools in Rwanda"
**Log date:** 07 October 2026
**Scope of this entry:** inspection, repair, integration and polish of the
existing React frontend (no rewrite, no backend changes).
**Overall status:** ✅ **Demo ready** — build green, all flows verified against
the live backend with real Wazuh data.

---

## 1. Ground rules applied

| Rule | How it was honoured |
|---|---|
| Do not redesign the working backend | `git status -- Backend` is byte-identical before and after this session |
| Do not replace the React app | Existing components/pages were repaired in place; no new framework, router or UI kit introduced |
| No fake data | Every number, row, chart and badge comes from the Spring Boot API; no hard-coded alerts, agents or statistics |
| No secrets in source | Admin password and JWT were only ever passed through process environment variables; `Backend/env.properties` is untouched and gitignored |
| No commits | HEAD is still `0451ca0` (12 commits); nothing was staged or committed |
| Prove it works | Three automated browser runs plus direct API contract checks — see §5 |

---

## 2. Inspection results

### 2.1 Stack

| Area | Finding |
|---|---|
| React / ReactDOM | 19.3.0 |
| Build tool | Vite 8.3.0 (`npm run dev`, `npm run build`, `npm run preview`) |
| Vite config file | none — the default `index.html` + `src/main.jsx` entry is used |
| Router | none — hand-rolled hash routing in `src/App.jsx` (`#/dashboard`, `#/alerts`, …) |
| TypeScript | none — plain `.jsx`, so build success alone does **not** catch undefined identifiers (this mattered, see §3.1) |
| API client | `src/services/api.js` — one `fetch` wrapper that attaches the JWT, parses JSON, normalises errors, and broadcasts `scw:auth-expired` on HTTP 401 |
| Auth | `src/services/auth.js` — `POST /api/auth/login` and `/api/auth/register`, JWT + profile persisted in `localStorage` under `schoolcyberwatch.auth` |
| Environment | `src/config/api.js` → `VITE_API_BASE_URL`, default `http://localhost:8080/api` |
| Styling | hand-written `src/styles/global.css` (custom properties, light + `.theme-dark`); no Tailwind, no CSS framework |
| Charts | no chart library — plain divs driven by backend counts |
| Backend | Spring Boot on `:8080`, verified working (health, JWT, Wazuh alerts, dashboard stats, incidents, PDF) |

### 2.2 File inventory

```text
Frontend/
  index.html                     entry + theme colour + favicon
  public/favicon.svg             NEW — shield/lock mark (was a 404)
  src/
    App.jsx                      hash routes, auth gate, 401 redirect
    main.jsx
    components/
      AppShell.jsx               sidebar, topbar, profile/logout
      BrandMark.jsx
      AlertDetailModal.jsx       GET /api/alerts/{id} dialog
    config/api.js                base URL
    pages/
      LandingPage.jsx  LoginPage.jsx
      DashboardPage.jsx  ComputersPage.jsx  AlertsPage.jsx
      IncidentsPage.jsx  NetworkPage.jsx  ReportsPage.jsx
      PlaceholderPage.jsx  (not routed)
    services/api.js  services/auth.js
    styles/global.css            single stylesheet
    utils/format.js              numbers, dates, type/severity labels, protocol names
```

### 2.3 Navigation implemented

Dashboard · Computers · Security alerts · Incidents · Network monitoring ·
Reports · Logout — all present in `AppShell` and routed in `App.jsx`.

---

## 3. Problems found and fixed

### 3.1 Crash: `NetworkPage` used an undefined function (blocker)

`orDash()` was called for the source/destination port cells but never imported.
Vite/esbuild does not report undefined globals, so `npm run build` stayed green
while clicking **Network monitoring** in a real browser threw
`ReferenceError: orDash is not defined`.

*Fixed:* added the import.

### 3.2 Broken protocol filter (silent no-results)

The protocol dropdown offered `SSH / TCP / UDP`, but the backend sends IP
protocol numbers (`"17"`, `"6"`), so selecting a protocol could never match a
row.

*Fixed:* options are now derived from the loaded page (`protocolLabel()` in
`utils/format.js` maps `17 → UDP`, `6 → TCP`, `1 → ICMP`, `58 → ICMPv6`), and
the cell renders `UDP` instead of the raw `17`.

### 3.3 Thirty-five component classes had no CSS

The largest issue. The React markup referenced classes that simply did not
exist in `global.css`, so those areas rendered as unstyled text:

| Missing group | Visible consequence |
|---|---|
| `.chart-row/.chart-track/.chart-fill/.chart-value` | "Alerts by severity" and "Alerts by type" looked like a plain list, not charts |
| `.overtime-*` | "Alerts over time" bars had no track, scale or readable axis |
| `.modal-backdrop/.modal-card/.modal-head/.modal-body/.modal-badges/.modal-actions/.modal-close/.modal-description` | **The alert detail dialog had no overlay at all** — it rendered below the fold and was invisible on screen |
| `.detail-section/.detail-row` | Modal fields were bare label/value text |
| `.type-chip(.scan)` | Friendly event names rendered as plain text; scan variant unstyled |
| `.scan-row` | Possible network scans were **not** visually distinguishable, which the brief requires |
| `.mono` | IP addresses not monospaced |
| `.charts-grid` | The two dashboard charts stacked instead of sitting side by side |
| `.panel-total`, `.table-footnote`, `.session-notice`, `.rule-chip`, `.link-view-alert`, `.clickable`, `.filter-narrow`, `.brand-subtitle`, `.sidebar-top`, `.neutral`, `.placeholder-page` | misc. unstyled helpers |

*Fixed:* added every missing rule (light **and** dark theme variants) in one
labelled block at the end of `global.css`, keeping the existing palette,
spacing and shadow tokens.

### 3.4 Summary cards orphaned

The backend returns **6** cards but `.summary-grid` was `repeat(5, 1fr)`, so
"Network alerts" fell alone onto a second row.

*Fixed:* `repeat(3, 1fr)` → a clean 3 × 2 grid (verified: 3 cards per row,
2 rows).

### 3.5 Table columns too narrow (network + alerts)

* Network: `Source / destination port` wrapped to three lines and `5353 / 5353`
  wrapped to two; computer names wrapped as well.
* Alerts: the type column was too tight for the friendly name.

*Fixed:* re-tuned `table-7` / `table-8` grid fractions, shortened the port
header to `Ports` (with a `title` tooltip) — the port cell now fits on one
line (measured 86 px, single line) and all eight headers are single-line.

### 3.6 Missing optional fields displayed as `—`

In the alert dialog the network rows used `orDash()`, which forces a dash for
alerts that have no network data (failed logins, file events), so an
irrelevant "Network" block always appeared.

*Fixed:* raw values are passed through; `DetailSection` already hides empty
rows, so the section disappears entirely when the backend did not supply the
data. Verified: a network alert shows exactly 3 sections / 11 rows, and the
page contains no `undefined` or `null` text.

### 3.7 Favicon 404

`GET /favicon.ico` returned 404 on every load.

*Fixed:* added `public/favicon.svg` (shield + padlock, matching `.brand-mark`)
and linked it from `index.html`. Verified `HTTP 200`.

### 3.8 Smaller cleanups

* `DashboardPage` comment said "7-day statistics" while requesting `days=30` — corrected.
* Dashboard already requested `stats?days=30` (the brief's 30-day view) — left as is.

### 3.9 What was already correct (verified, not changed)

JWT attach + 401 → clear → single redirect with a friendly notice; 503 and
other HTTP errors mapped to plain messages; PDF download bypassing JSON
parsing; backend-side filtering for alerts (never downloads the full Wazuh
history); `limit=200` paging; number formatting (`590,473`); severity badges
that carry text as well as colour; friendly names for all seven rule ids;
409 duplicate handling already matching the backend's exact message.

---

## 4. Live backend contracts confirmed

Checked directly against `http://localhost:8080` with a real JWT:

| Endpoint | Confirmed response |
|---|---|
| `POST /api/auth/login` | `token, email, fullName` |
| `GET /api/dashboard/summary` | 6 cards — Monitored computers `1`, Active alerts `184,911`, Critical and high `184,839`, Open incidents, Resolved incidents, Network alerts `590,473` |
| `GET /api/dashboard/stats?days=30` | `windowDays=30`, `totalAlerts=807,089`, `bySeverity{Critical 17, High 184822, Medium 622250, Low 0}`, `byType` covering all seven detections, `overTime` 30 days, `recentAlerts` 10 |
| `GET /api/alerts?limit=…` | 20 fields incl. `ruleId, severity, agentId, agentIp, username, filePath, threat, sourceIp…`; filters `severity`, `type`, `ruleId`, `from`, `to`, `search` all honoured server-side |
| `GET /api/alerts/{id}` | full detail, `200` |
| `GET /api/endpoints` | `id,name,ip,os,status,lastSeen,version` → Agent `001` / `WIN-HUR37I74T1G` / `192.168.56.103` |
| `GET /api/network/events`, `/summary` | ports, `protocol`, `type`, `category`; summary `{totalEvents 1000, highSeverity 230, affectedEndpoints 1}` |
| `POST /api/incidents` | creates; **second POST → HTTP 409** with body `{"error":"An incident already exists for this security alert."}` — identical to the UI constant |
| `POST /api/incidents/{id}/status`, `/notes` | `OPEN → INVESTIGATING → RESOLVED`; notes persisted |
| `GET /api/reports/security-report.pdf?days=30` | `200`, `application/pdf`, 1,886 bytes, `%PDF` magic |

---

## 5. Verification

Three complementary runs in headless Chrome driven over the Chrome DevTools
Protocol (the admin credentials and JWT were injected through environment
variables and never written to source or printed):

| Run | What it does | Result |
|---|---|---|
| **End-to-end** (destructive) | Logs in with wrong credentials, then drives every page with a real JWT: dashboard charts, alert modal, create-incident prefill, duplicate submit, status change, note add, computers, network, PDF download, 401 expiry, logout, overflow checks | **34 / 34 passed** |
| **Layout audit** (read-only) | Measures computed styles and geometry — grid columns, bar sizes/colours, modal overlay position, chip tints, scan highlight, monospace IPs, dark theme, horizontal overflow | **28 / 28 passed** |
| **Read-only smoke** | Re-runs every page after final code changes without mutating any backend data | **12 / 12 passed** |
| **API contract checks** | Direct HTTP assertions listed in §4 | all passed |

### Selected end-to-end results

```
PASS  Invalid login message                 "Invalid email or password"
PASS  Dashboard summary cards (6)           Monitored computers=1 | Active alerts=184,911 | … | Network alerts=590,473
PASS  Severity chart (4 rows)               rows=4
PASS  Alert type chart (7 rows)             rows=7
PASS  Alerts over time (real days)          days=30
PASS  Alert detail modal visible on screen  {"top":24,"w":660,"inView":true}
PASS  Detail hides missing fields           fields=11 nullish=false
PASS  Incident form prefilled from alert    hash=#/incidents title="Network Connection on WIN-HUR37I74T1G"
PASS  Duplicate 409 handled in UI           "An incident already exists for this security alert."
PASS  Incident status update                OPEN -> INVESTIGATING
PASS  Incident note added                   visible=true
PASS  Endpoint status badge matches value   class="status offline"
PASS  Rule 100301 displayed + highlighted   rules=100300,100301 scanRows=47
PASS  Backend PDF downloaded via UI         school-cyberwatch-report-*.pdf bytes=1888 magic=%PDF
PASS  401 clears session and redirects      notice="Your session has expired. Please sign in again."
PASS  Logout returns to login               cleared=true
PASS  No unexpected console/page errors     only expected 401/409 auth logs
```

### Screen-quality review (measured, §3 fixes confirmed)

* Summary grid: `337px 337px 337px` × 2 rows — no orphaned card.
* Charts: 2 columns side by side; tracks 11 px `rgb(238,241,240)`; critical bar
  `rgb(219,79,79)`; over-time chart 210 px with 30 days, tallest bar 183 px,
  **0 labels overflowing**.
* Modal: `position:fixed`, `z-index:60`, 660 px wide, centred and fully inside
  the viewport, white/16 px radius, label-value detail grid, primary gradient action.
* Network: port cell single line, protocol `UDP`, protocol filter
  `["All protocols","UDP","ICMPv6"]`, scan rows `rgb(255,250,241)` with an
  amber inset marker, IPs monospaced, all eight headers single line.
* Responsive: horizontal overflow delta `0` at 1348 px and 1024 px; tables
  collapse at ≤900 px, sidebar collapses at ≤720 px.
* Dark theme: panels `rgb(32,40,37)`, chart tracks `rgb(39,49,45)` — restyled
  correctly.

> **Tooling note:** the screenshot-viewing tool available in this session
> returned a stale cached image for every file (reproduced with a plain magenta
> test PNG), so pixels could not be trusted. Screen quality was therefore
> verified *programmatically* — computed styles, bounding boxes and overflow
> measurements — which is the evidence quoted above.

### Data integrity

Testing created two incidents (`#6 FE test incident`, `#7` from the
create-from-alert flow). The backend exposes no DELETE endpoint, so both rows
and their notes were removed directly from MySQL to restore the exact
pre-test state: **5 incidents / 3 notes**. No backend files were touched.

---

## 6. Build and runtime status

```text
npm run build   ✓ built in ~0.3 s
                31 modules · index.js 264.49 kB (gzip 78.89 kB)
                              · index.css 31.01 kB (gzip 6.60 kB)

Frontend  http://localhost:5173   HTTP 200
Backend   http://localhost:8080   {"status":"UP"}
```

---

## 7. Known issues / deliberately out of scope

1. **SMTP** — "Send test email" still needs a Gmail App Password. Preserved,
   not triggered, and not a frontend blocker.
2. **Agent 001 reports `Offline`** — real Wazuh agent state. The badge follows
   the backend (`status offline`), which is the correct behaviour.
3. **No incident delete** in the backend API, so incidents cannot be removed
   from the UI (see §5 for how the test rows were cleaned up).
4. **Alert payloads carry no `protocol` field**, so that row stays hidden in
   the alert dialog; the Network page does show it.
5. **`PlaceholderPage`** exists but is not routed — left untouched.

---

## 8. Files changed in this session

**Modified**

| File | Purpose |
|---|---|
| `src/styles/global.css` | Added the 35 missing component classes (incl. dark theme), summary grid 5→3 columns, re-tuned `table-7`/`table-8` widths, panel-heading wrapping |
| `src/pages/NetworkPage.jsx` | Fixed the `orDash` import crash; data-driven protocol filter; protocol names; shortened port header |
| `src/utils/format.js` | Added `protocolLabel()` |
| `src/components/AlertDetailModal.jsx` | Optional network fields now hide when absent; protocol formatting |
| `src/pages/DashboardPage.jsx` | Corrected a stale "7-day" comment |
| `index.html` | Favicon link |

**Created**

| File | Purpose |
|---|---|
| `public/favicon.svg` | Shield + padlock favicon (removes the 404) |

**Not changed:** `Backend/**` (zero files), `Backend/env.properties`, root
`README.md`. No git commit was created.

---

## 9. How to re-run the checks

```powershell
cd Frontend
npm install          # only if node_modules is missing
npm run dev          # http://localhost:5173
npm run build        # must stay green
```

The three browser harnesses used in this session live outside the repository
(`%TEMP%\opencode\scw-e2e.cjs`, `scw-audit.cjs`, `scw-smoke.cjs`). They start
their own headless Chrome, read the admin credentials from
`Backend/env.properties` at run time, and never print the password or JWT. They
can be re-created from this log if they are cleaned up by the OS.

---

# Stabilisation & demo-readiness pass

## 10. Baseline recorded before any change

| Item | Value |
|---|---|
| Git HEAD | `0451ca0`, 12 commits — **nothing committed this session** |
| Maven suite | `Tests run: 56, Failures: 0, Errors: 0` — BUILD SUCCESS |
| Frontend build | PASS (31 modules, 264.49 kB JS / 31.01 kB CSS) |
| Toolchain | Java 21.0.12, Node v24.21.0, bundled Maven 3.9.9 |

## 11. Network statistics: what `1,000` actually was

**Diagnosis (measured, not assumed)**

- `countQuery` sets `track_total_hits: true`, so `countAlerts()` returns exact
  totals — the dashboard's `590,473` was never a 10,000-row cap.
- `/api/network/summary` computed `totalEvents = getRecentEvents(1000).size()`.
  That method caps the OpenSearch page at **1,000 raw alerts across 13 network
  rules**, then filters local/loopback activity in memory. `1,000` was
  therefore a **sample/page limit, not a total**, and `highSeverity` /
  `affectedEndpoints` were derived from that same sample.
- Two different scopes were being shown side by side: the dashboard card counted
  exactly rules **100300 + 100301** over 72 h; the Network page sampled 13 rules.

**Exact indexer probe (read-only, `size:0`, credentials read at runtime)**

| Metric, window 2026-10-05 → 2026-10-08 (72.0000 h) | Value |
|---|---|
| Rules 100300 + 100301 | **590,473** |
| · 100300 inbound connections (level 5 → Medium) | 452,222 |
| · 100301 network scans (level 10 → High) | 138,251 |
| All 13 network rules | 590,484 (only +11) |
| Distinct `agent.name` / `agent.id` | 1 → `WIN-HUR37I74T1G` / `001` |

**Fix**

`getSummary()` now issues three `size:0` count/aggregation queries over one
shared, explicitly reported window instead of downloading 1,000 rows. As a side
effect the summary no longer touches the notification/email pipeline.

**Backend files changed (and why)**

| File | Change | Why |
|---|---|---|
| `service/NetworkMonitorService.java` | `getSummary()` rewritten to exact count + `countAlertsByLevel` (severity mapped by the same `SecurityEventMapper` used for events) + distinct agents; added shared `Window`/`currentWindow()`; `NetworkSummary` record extended with `windowHours`, `windowStart`, `windowEnd`, `countType` | Removes the 1,000-row sample; makes the card scope/window identical to the dashboard's "Network alerts"; reports the window so the UI can label truthfully |
| `service/WazuhIndexerClient.java` | Added `countAlertsByAgent()` (terms aggregation on `agent.name`) | Exact distinct-endpoint count without fetching alert rows |
| `test/.../NetworkMonitorServiceTest.java` | Added `summaryCountsExactlyWithoutFetchingEvents()` | Locks in: exact values, exact 72 h window, no `searchAlerts`, no email-pipeline interaction |

**Frontend label change:** `NetworkPage.jsx` now reads
`Total network events ({windowHours}h)` / `High-severity network alerts
({windowHours}h)` with a tooltip stating scope + ISO window, and the footnote
spells out that the cards are exact counts while the feed is a bounded 200 rows.

**Result:** all three sources now agree — `network/summary` = dashboard card =
`stats?days=3` (452,222 + 138,251) = **590,473**, delta 0 in this run.
Counts are *not* guaranteed identical between requests: ingestion continues, and
the window is re-anchored to `Instant.now()` per request (it happened to be 0
here because the endpoint agent is offline and generating no new events).

## 12. Agent 001 status — why it shows Offline

| Check | Result |
|---|---|
| Wazuh API `GET /agents` | `001 WIN-HUR37I74T1G 192.168.56.103` → **`disconnected`**, Wazuh v4.12.0, `lastKeepAlive 2026-10-06T23:57:06+00:00` |
| Wazuh API `GET /agents` | `000 ubuntuserver` → `active` (manager healthy) |
| Manager ports | 9200, 55000, 1514 all open; ping 192.168.56.101 OK |
| Endpoint VM 192.168.56.103 | **ping 100% loss**, no ARP entry |
| `VBoxManage list runningvms` | only **`ubuntu_server`** — the Windows VM is not running |
| Backend `/api/endpoints` | `status: "Offline"`, `lastSeen: ""` |

**Conclusion: Offline is the true state, not a display bug.** The Windows
endpoint VM is powered off, so the agent stopped reporting ~32 h ago.

**Manual steps for the user** (no IP, adapter, credential, firewall, Wazuh
config or service change was made):
1. Start the Windows VM in VirtualBox (guest `WIN-HUR37I74T1G`, IP 192.168.56.103).
2. Keep it on the host-only adapter with 192.168.56.103.
3. Once booted, start the **Wazuh Agent** service (`services.msc`, or `net start WazuhSvc`).
4. Status flips to Online within a minute or two; no restart of the backend is needed.

## 13. Contrast / projector readability

A headless-Chrome auditor walked every visible text node on 8 pages in **both**
themes plus the alert modal, computed the composited background, and flagged
anything below WCAG AA (4.5:1 normal, 3:1 large).

| | Before | After |
|---|---|---|
| Flags | 2,236 | **0** |
| Unique failing combos | 58 | **0** |
| Worst ratio | 1.00 (dark table text) | — |

Worst offenders fixed: dark-mode table `strong` at **1.30:1** (near-black on a
dark row), `.alert-rule` at **2.07:1**, `.nav-label`/`.table-footnote` at
**2.56:1**, `.alert-desc` at **2.93:1**.

Approach — colour values only, no layout/spacing/type-scale/nav/branding change:
- 41 hex replacements in `global.css`, each asserted against its expected hit
  count so a reused colour cannot half-apply. Muted greys collapsed to one
  accessible token `#63706b` (smallest text `#55625e`); severity/status chips
  darkened *within their existing hue*; brand violet nudged `#746df0 → #625aee`.
- One appended, labelled **dark-theme block** restating those values for dark
  surfaces (`#afbeb7`, `#f2f6f4`, `#8680f2`, `#cfcaff`).
- Gradient backgrounds are skipped by the auditor (they cannot be sampled) —
  those were false positives, verified against the CSS rather than "fixed".

## 14. Verification this session (all measured)

| Suite | Result |
|---|---|
| Maven (`mvn test`) | **57 / 57**, 0 failures — BUILD SUCCESS (56 baseline + 1 new) |
| `npm run build` | **PASS** — 31 modules, 264.83 kB JS / 32.50 kB CSS |
| Layout audit | **28 / 28** (3-col summary, charts, dark theme, modal overlay+centre, sidebar, scan highlight, h-overflow delta = 0) |
| Contrast auditor | **0 failures** (8 pages × 2 themes + modal) |
| Smoke | **12 / 12** (landing → bad login → dashboard → alerts+modal → incidents → computers → network → reports → 401 → logout → console errors) |
| Final regression (API) | **25 / 25** (health, invalid+valid login, 401, 6 cards, stats×30, alerts+filters+detail, endpoints, incidents read, duplicate→409 with count unchanged, network rules, summary, PDF `%PDF` + 200 kB, invalid JWT→401) |
| Incident workflow | **12 / 12** — CREATE `201 id=8`, read, status `OPEN→INVESTIGATING`, invalid status→400, note added + persisted, 5 pre-existing incidents byte-identical |
| Console/page errors | none unexpected (only the expected auth logs) |

**Duplicate-incident 409** returned `{"error":"An incident already exists for this security alert."}`
and the incident count stayed at 5 → no data created.

## 15. Files changed in this session

**Backend (3, justified by Task 2)**

| File | Why |
|---|---|
| `main/.../service/NetworkMonitorService.java` | exact counts instead of a 1,000-row sample |
| `main/.../service/WazuhIndexerClient.java` | new `countAlertsByAgent()` aggregation |
| `test/.../service/NetworkMonitorServiceTest.java` | new regression test |

**Frontend (2)**

| File | Why |
|---|---|
| `src/styles/global.css` | 41 colour corrections + appended dark-theme readability block |
| `src/pages/NetworkPage.jsx` | truthful card labels/tooltip/footnote |

**Untouched:** `Backend/env.properties`, root `README.md`. No commit, no
staging, no reset. Build output under `Backend/target/` changes only because the
suite is re-run (2 files were already tracked at HEAD).

## 16. Findings to carry forward

1. **Pre-existing secret in git (not introduced here).** `Backend/env.properties`
   is correctly gitignored, but the real admin password is present in **three
   files already committed at `0451ca0`**: `README.md`,
   `Backend/main/resources/application.properties` (Spring
   `${ADMIN_PASSWORD:…}` default) and `Backend/env.example.properties`. Rotate
   the credential and replace those with placeholders.
2. `GET /api/endpoints` returns `lastSeen: ""` even though Wazuh has
   `lastKeepAlive 2026-10-06T23:57:06Z` — the Computers page cannot show
   "last seen" for this agent. Left as-is (backend change not required).
3. Alerts `?search=` matches text fields, not IP addresses (`192.168.56.103` →
   0 rows, `Network` → 25 rows).
4. SMTP still needs a Gmail App Password; no backend incident DELETE endpoint.
5. Alert payloads still lack a `protocol` field.
