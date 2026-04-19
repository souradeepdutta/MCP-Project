# 🛡️ Phishing Triage Agent — Project State Analysis

> **Date:** April 12, 2026  
> **Scope:** Full audit of what's built vs. the original vision  
> **Verdict:** Solid Phase 1 MVP foundation — significant room for depth & polish

---

## 1. Executive Summary

Your PoC is **genuinely functional and well-engineered** for a personal-laptop proof of concept. The agent can autonomously ingest a phishing email → enrich IOCs → trace blast radius through Splunk → inspect endpoint activity → generate a structured report with separate executive/technical tabs → push to a premium-looking SOC dashboard. The core "MCP-powered autonomous triage" story works end to end.

That said, when compared against the comprehensive original vision (the 7 functional modules, 6 workflow phases, 12-feature list), there are **meaningful capability gaps** and **polish opportunities** that would elevate this from a working demo to a compelling, portfolio-grade PoC.

---

## 2. Module Coverage Map

The original plan defined **7 functional modules**. Here's where each stands:

| # | Module | Status | Notes |
|---|--------|--------|-------|
| 1 | **Intake** | ✅ Implemented | Mailpit + EML + mock. Fuzzy subject matching works. |
| 2 | **Artifact Extraction** | ✅ Implemented | Sender, recipients, URLs, attachments, body snippet. Solid. |
| 3 | **Correlation** (SIEM) | ⚠️ Partial | Splunk `proxy_logs` + `edr_logs` queried. But no sign-in/auth log correlation. No campaign-level search (e.g., "find similar emails by sender domain"). |
| 4 | **Impact Assessment** | ⚠️ Partial | Click tracing ✅ + endpoint forensics ✅. But **no identity compromise check** (sign-in anomalies, MFA changes, password resets, impossible travel). No "who replied" or "who opened" analysis. |
| 5 | **Decisioning** | ✅ Implemented | 5-tier verdict taxonomy. LLM-driven but evidence-grounded via SOPs. |
| 6 | **Case Automation** | ⚠️ Basic | Cases are created and stored. But no case updates, no status lifecycle (Open → Investigating → Resolved → Closed), no severity scoring beyond verdict keywords, no analyst notes field. |
| 7 | **Governance** | ❌ Not Started | No RBAC, no audit trail of tool calls, no approval gates, no action logging. |

---

## 3. Feature Checklist vs. Original Vision

### ✅ Fully Implemented
- [x] Suspicious email intake (Mailpit + file + mock)
- [x] Email artifact extraction (sender, recipients, URLs, attachments, headers)
- [x] URL/domain/attachment enrichment (VirusTotal live + mock fallback)
- [x] User click and interaction tracing (Splunk `proxy_logs`)
- [x] Endpoint impact assessment (Splunk `edr_logs`)
- [x] Case summary generation (executive + technical split)
- [x] Ticket/case creation
- [x] Premium SOC dashboard with Altair charts

### ⚠️ Partially Implemented
- [ ] Campaign spread detection — you have the *data* across 5 campaigns, but no MCP tool to **search by sender domain or subject similarity** to auto-discover campaign siblings
- [ ] Incident severity scoring — verdict-based keyword matching in `classify_verdict()` is basic; no numeric risk score or CVSS-like weighting

### ❌ Not Implemented
- [ ] **Identity compromise assessment** — the most critical gap. No sign-in anomaly data, no MFA change detection, no auth log index in Splunk
- [ ] **Campaign correlation tool** — no `search_similar_emails()` or `search_campaign_spread()` MCP tool
- [ ] Case update/lifecycle management — no way to update an existing case or change status
- [ ] Analyst approval workflow — all actions are fully autonomous, no checkpoint
- [ ] Audit trail — no logging of which tools were called, when, and with what arguments
- [ ] Full audit trail / export — no PDF/report export
- [ ] Case deletion or archival

---

## 4. What's Working Well

### Strengths
1. **End-to-end autonomy** — The Claude Desktop → MCP → Splunk → DB → Streamlit pipeline is real and operates without manual intervention
2. **Rich synthetic data** — 5 diverse campaigns (C1-C5) cover: credential harvest, supply chain, benign false positive, proxy-blocked, and multi-stage attack chains
3. **Realistic EDR telemetry** — Attack chains include process trees (Excel → mshta → certutil → DLL sideload → beacon), persistence via schtasks, lateral movement via PsExec, and credential dumping via comsvcs.dll
4. **Report quality** — The existing case (`CAS-D12B740F`) shows genuinely good report structure: stepwise evidence, specific IOCs quoted, per-user impact differentiation, and tiered recommended actions
5. **Token optimization** — SOP 4 ensures the agent doesn't regurgitate reports in chat, saving significant API cost
6. **Dual-layer TI** — VirusTotal live lookup with graceful mock fallback is well-designed
7. **Splunk CSV parsing** — The `_raw` CSV chunk fallback parsing is a practical edge-case fix
8. **Dashboard aesthetics** — The dark-theme SOC dashboard with glassmorphism, Altair charts, severity badges, and tab-separated reports is genuinely premium

---

## 5. Gap Analysis — What's Missing

### 🔴 HIGH PRIORITY — Would significantly strengthen the PoC story

#### A. Identity Compromise Assessment (Missing Module 4 component)
**What the original plan requires:**
- Post-click sign-in anomaly detection
- Password reset events
- MFA changes
- Impossible travel / new device registration

**What you'd need:**
1. Create an `auth_logs` index in Splunk with synthetic sign-in data (normal + anomalous)
2. Add data to `generate_sample_data.py` — suspicious sign-ins for compromised users (jsmith, cjones) occurring shortly after their click events
3. New MCP tool: `query_identity_events(username)` → queries `auth_logs` index
4. Update `skills.md` to add a Step 3.5 between blast radius and endpoint forensics

**Impact:** This is the single most valuable addition. Phishing → credential theft → auth abuse is the #1 real-world attack chain, and it's the one gap a reviewer will notice.

#### B. Campaign Correlation Tool
**What's missing:**
- No way for the agent to *discover* that multiple emails are part of the same campaign
- The agent triages one email at a time and doesn't know about siblings

**What you'd need:**
1. New MCP tool: `search_campaign_emails(sender_domain)` or `search_similar_emails(subject_fragment)` → queries Mailpit for matching emails
2. The tool returns count of matching messages and recipient spread
3. Update SOP to include a campaign-check step

**Impact:** "Campaign detection" is one of the top 3 selling points in your original pitch. Currently the data exists but the tool doesn't.


### 🟡 MEDIUM PRIORITY — Would add polish and depth

#### D. Audit Logging
**Missing entirely.** Every tool call should be logged: tool name, arguments, timestamp, caller. This could be as simple as a `tool_audit_log` table in SQLite or a decorator on each MCP tool function.

#### E. Dashboard Enhancements
- **Case export** — PDF or markdown download button for any case
- **IOC table** — Extract and display all IOCs (domains, IPs, hashes, URLs) from the technical details in a structured, copy-friendly table
- **Search/filter** — Text search across case summaries
- **Auto-refresh** — Currently requires manual page reload to see new cases
- **Case comparison** — Side-by-side view of two related cases

#### F. Email Header Analysis Tool
The `extract_email_artifacts` tool extracts basic fields but doesn't analyze:
- SPF/DKIM/DMARC pass/fail
- Authentication-Results header parsing
- Reply-To vs From mismatch detection
- Received header chain analysis

This would strengthen the "email analysis" module from the original plan.

---

### 🟢 LOW PRIORITY — Nice to have for a PoC

#### H. Rate Limiting & Error UX
- VirusTotal free tier has rate limits (4 requests/minute). No retry/backoff logic.
- Splunk queries have no timeout feedback in the dashboard.

#### I. Multi-Alert Batch Investigation
The agent processes one email at a time. A batch mode ("investigate all unread Mailpit messages") would demonstrate operational scale.

#### J. Requirements File
`requirements.txt` is missing `altair` (used in `app.py`). Should be added.

---

## 6. Code Quality Observations

| Area | Finding | Severity |
|------|---------|----------|
| **Imports inside functions** | `csv` and `io` are imported inside `query_splunk_for_clicks` and `query_endpoint_activity` on every call | 🟡 Minor |
| **Duplicate email parsing** | `_parse_eml_file()` and `_fetch_from_mailpit()` share 80% identical code (URL extraction, attachment extraction). Should be refactored into a shared `_parse_email_message(msg)` helper | 🟡 Moderate |
| **No pagination in Mailpit** | `_fetch_from_mailpit` fetches all messages at once. Will break with large inboxes | 🟡 Moderate |
| **`.env` handling** | `.env` with real credentials is properly gitignored and not tracked. ✅ | 🟢 Good |
| **No `altair` in requirements.txt** | `app.py` imports `altair` but it's not listed in `requirements.txt` | 🟡 Minor |
| **`hello.md` is stale** | Lists outdated file structure (`proxy_clicks.csv` vs actual `proxy_logs_full.csv`). Its "What's Next" section is partly completed | 🟢 Cosmetic |
| **`send_test_email.py` vs `send_test_emails.py`** | Two separate email sender scripts exist. The singular file (57 lines) appears to be an earlier version of the plural file (297 lines) | 🟢 Cleanup |

---

## 7. Security of the PoC Itself

> [!NOTE]
> **`.env` is properly gitignored** — Verified that `.env` is listed in `.gitignore` and is **not tracked by git**. Your Splunk credentials and VT API key are safe from accidental commits. ✅

---

## 8. Prioritized Improvement Roadmap

### Tier 1: Maximum Impact, Minimum Effort (1-2 hours each)

| # | Enhancement | Why |
|---|------------|-----|
| 1 | **Add `auth_logs` index + `query_identity_events` tool** | Closes the biggest functional gap. Synthetic auth data is trivial to generate. |
| 2 | **Add `search_campaign_emails` MCP tool** | Enables campaign detection — one of the top-3 demo talking points |
| 3 | **Add case status lifecycle** | `status` column + dropdown in dashboard. Shows operational maturity. |
| 4 | **Refactor duplicate email parsing** | DRY up shared code between `_parse_eml_file` and `_fetch_from_mailpit` |

### Tier 2: Polish & Professionalism (2-4 hours each)

| # | Enhancement | Why |
|---|------------|-----|
| 5 | **Audit logging decorator** | Every tool call logged. Shows governance awareness. |
| 6 | **Dashboard auto-refresh + case export** | QoL for demos |
| 7 | **Email header analysis** (SPF/DKIM) | Strengthens the "email analysis" module |
| 8 | **Refactor parsed email code** | DRY up duplicate parsing logic |

### Tier 3: Stretch Goals

| # | Enhancement | Why |
|---|------------|-----|
| 9 | **Batch investigation mode** | Show operational scale |
| 10 | **IOC extraction table in dashboard** | Show structured threat intel |
| 11 | **Endpoint abstraction layer** | Future-proofing |
| 12 | **PDF report export** | Enterprise readiness signal |

---

## 9. Overall Assessment

```
┌──────────────────────────────────────────────────────────────┐
│  OVERALL PoC MATURITY SCORE                                   │
│                                                                │
│  Architecture & Design:    ████████░░  8/10                   │
│  Feature Completeness:     ██████░░░░  6/10                   │
│  Code Quality:             ███████░░░  7/10                   │
│  Data Richness:            █████████░  9/10                   │
│  UI/UX:                    █████████░  9/10                   │
│  Security Hygiene:         ████████░░  8/10                   │
│  Documentation:            ██████░░░░  6/10                   │
│  Demo Readiness:           ████████░░  8/10                   │
│                                                                │
│  COMPOSITE:                ████████░░  7.3/10                 │
│                                                                │
│  VERDICT: Strong Phase 1 MVP. Adding identity checks +        │
│  campaign detection would push this to 8.5+/10               │
└──────────────────────────────────────────────────────────────┘
```

The foundation is genuinely solid. The biggest wins are:
1. **Identity compromise checks** (auth_logs) — the #1 gap
2. **Campaign correlation tool** — the #1 missing demo feature
3. **Case lifecycle** — shows operational maturity
4. **`.env` cleanup** — security hygiene for a security project

Would you like me to start implementing any of these improvements?
