# Master Project Context: Autonomous Phishing Triage Agent

## 1. Project Overview

We are building a fully functional Proof-of-Concept (PoC) for an Agentic AI pipeline tailored for DevSecOps and SOC teams. This system acts as an autonomous Tier 1/Tier 2 Analyst. It receives phishing alerts, uses the Model Context Protocol (MCP) to query security tools (SIEM, EDR, Threat Intel), synthesizes evidence, and generates deterministic investigation reports.

## 2. Current Tech Stack

- **Backend / Tool Layer:** Python 3.13+, `mcp` SDK (FastMCP framework).
- **SIEM / Data Lake:** Splunk Enterprise (REST API integration).
- **State Management:** SQLite (`cases.db`).
- **Frontend / Dashboard:** Streamlit.
- **AI Orchestrator:** Claude / Gemini (consuming tools via standard MCP I/O).

## 3. Current Architecture & File Structure

The MVP is fully functional and successfully chains multiple tools together.

- `phishing_mcp.py`: The core MCP server exposing the following tools:
  - `extract_email_artifacts`: Extracts sender, recipients, URLs, and attachments.
  - `check_threat_intel`: Evaluates domains, IPs, and file hashes.
  - `query_splunk_for_clicks`: Hits Splunk REST API to trace URL clicks to determine blast radius.
  - `query_endpoint_activity`: Hits Splunk REST API to hunt for malicious child processes (EDR/Sysmon telemetry).
  - `save_investigation_report`: Writes the AI's final verdict to the SQLite database.
- `app.py`: A Streamlit dashboard that reads from `cases.db` to display a single-pane-of-glass UI for analysts.
- `skills.md`: The standard operating procedures (SOPs) governing the LLM's reasoning.

## 4. SOPs & Deep Investigation Protocol (skills.md context)

When conducting a full investigation, the system must follow this exact sequence and investigate all possibilities:

1. **Artifact Extraction:** Run `extract_email_artifacts` to parse domains, URLs, and hashes natively.
2. **Threat Intelligence:** Run `check_threat_intel` on the extracted artifacts to establish global reputation BEFORE internal hunting.
3. **SIEM & Identity Analytics (Blast Radius):** Query Splunk to trace the identity footprint. Investigate:
   - URL clicks and proxy traffic.
   - Authentication anomalies: random/off-hours logins, multiple password failures (brute force), and MFA fatigue.
   - Geographic anomalies: impossible travel or location jumps.
4. **Deep Endpoint Forensics (EDR/Sysmon):** Query endpoint logs on affected IPs. Do not stop at initial execution. Investigate:
   - Unauthorized file drops or new file downloads.
   - Suspicious child process trees (e.g., Office apps spawning `cmd.exe` or `powershell.exe`).
   - Persistence mechanisms (Scheduled tasks, registry modifications).
   - Outbound C2 beaconing.
5. **Verdict & Persistence:** Generate a final severity verdict based on the aggregated evidence and run `save_investigation_report`.

## 5. Next Phase: Full PoC Product

We are moving to a fully realized, dynamic PoC:

- **Live Email Ingestion:** Replace mock email data with a live connector (e.g., Mailpit API or IMAP) to parse raw `.eml` files natively.
- **Dynamic Threat Intel:** Threat Intel tools will scrape or query specific TI websites/sources provided dynamically by the user in the prompt. Do not constrain the agent to hardcoded mock VT data.

## 6. AI Agent Directives & Coding Style

When writing code or assisting with this project, you MUST adhere to the following rules:

- **Maintain Radical Transparency:** Admit uncertainty clearly. If an integration is missing context, ask for it.
- **Accuracy over Comfort:** Prioritize correctness. Do not hallucinate Splunk SPL queries or Python logic.
- **Be Direct and Skimmable:** No sugar-coating. No extra fluff unless requested. Use bullets or numbered lists for clarity. Respect time — get straight to the point.
- **Forward-Thinking:** Focus on what’s next and what’s possible. Suggest fresh, innovative angles for the architecture.
- **Evidence-Driven:** The LLM orchestrator must never guess verdicts. All conclusions must be grounded directly in the JSON returns from the MCP tools.
