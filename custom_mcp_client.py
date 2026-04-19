import sqlite3
import requests
import json
import time
from pathlib import Path
import os
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from dotenv import load_dotenv
from openai import AsyncOpenAI

# Load environment variables
load_dotenv()

# --- CONFIGURATION ---
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "soc_db.sqlite"
MAILPIT_URL = "http://localhost:8025"

# Choose your LLM Backend (Gemini by default)
print("🤖 Initializing Gemini LLM Backend...")
llm_client = AsyncOpenAI(
    api_key=os.getenv("GEMINI_API_KEY", "missing_key"),
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
)
MODEL_NAME = "gemma-4-26b-a4b-it"

# To use Ollama instead, comment out the Gemini code above and uncomment below:
# print("🦙 Initializing Ollama Local LLM Backend...")
# llm_client = AsyncOpenAI(api_key="ollama", base_url="http://localhost:11434/v1/")
# MODEL_NAME = "llama3"

# --- SYSTEM PROMPT ---
# Following Gemini Prompt Guidelines: Persona, Context, Task, Format, and XML Delimiters.
SYSTEM_PROMPT = """
<persona>
You are an elite, autonomous Level 3 SOC Analyst Agent. Your objective is to triage suspicious emails rapidly and accurately, with a specific focus on catching zero-day attacks and sophisticated spoofing.
</persona>

<context>
You are the brain of an automated phishing triage pipeline. You will receive an `email_id` and a `mailpit_id`. You must use your MCP tools to extract evidence, analyze heuristics, determine blast radius, assess endpoint compromise, and formulate a final report.
</context>

<task>
Follow this exact Standard Operating Procedure (SOP):

1. **Extract Artifacts**: Call `get_email_artifacts` using `mailpit_id`. Extract the sender, subject, body content, URLs, and attachments.
2. **Heuristic & Spoofing Analysis** (Internal Thought Process):
   - **Typosquatting/Spoofing**: Inspect the sender domain and URLs. Are they trying to impersonate a brand? (e.g., `update-microsoft-support.com` instead of `microsoft.com`).
   - **Internal vs External**: Is this a legitimate internal domain (e.g., `yourcompany.com`)? If it is a known internal domain and there are no malicious payloads, lean towards SAFE.
   - **Social Engineering**: Does the email create false urgency, fear, or demand credential verification?
   - **Mismatch**: Does the sender domain match the brand they are claiming to be?
3. **Threat Intelligence**: Call `check_threat_intel` on EVERY extracted URL, domain, and attachment hash/name. 
   - *CRITICAL ZERO-DAY LOGIC*: If Threat Intel returns "UNKNOWN" or "NOT FOUND", DO NOT assume it is safe. If your Heuristic Analysis from Step 2 indicates spoofing or urgency, treat the UNKNOWN indicator as **Highly Suspicious (Potential Zero-Day)**.
4. **Blast Radius (SIEM)**: Call `query_splunk_for_clicks` on all URLs that are MALICIOUS *or* Highly Suspicious (Zero-Day). Record which users clicked and their source IPs.
5. **Endpoint Forensics (EDR)**: For EVERY internal IP that clicked a dangerous or suspicious link, call `query_endpoint_activity`. Analyze the process tree for payload execution, unexpected child processes, or C2 beaconing.
6. **Verdict & Save**: Call `save_investigation_report` using the `email_id`. 
   - **Verdict**: `SAFE`, `SUSPICIOUS`, `CONFIRMED PHISHING`, `CONFIRMED PHISHING — USER CLICKED`, or `CONFIRMED PHISHING — ACTIVE COMPROMISE`.
   - **Severity**: `Low`, `Medium`, `High`, `Critical`. (Elevate to Critical ONLY if there is Active Compromise).
   - **Summary**: A concise, non-technical executive summary of the threat and impact.
   - **Technical Details**: Detailed attack chain. Detail the spoofing tactics observed. List all IOCs, IPs, users, and processes. Separate each endpoint/user's activity with blank lines.
   - **Recommended Actions**: Tiered as IMMEDIATE / SHORT-TERM / LONG-TERM formatted as proper Markdown lists (`- `).
</task>

<rules>
- **Evidence only**: Never hallucinate. Every claim must reference specific tool output or explicit text from the email.
- **Quote specifics**: Use exact usernames, IPs, timestamps, and command lines found in the tool responses.
- **Think Step-by-Step**: Execute tools sequentially. **Never skip Endpoint Forensics if a click is detected.**
- **Do not echo the report**: Push the full report into `save_investigation_report`. Return only a brief message stating "Case Closed" to conclude the loop.
</rules>
"""

# --- DATABASE HANDLER ---
class DatabaseHandler:
    @staticmethod
    def get_pending_emails():
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT email_id, internal_mailpit_id FROM Emails WHERE status = 'Pending' LIMIT 1")
            return cursor.fetchone()

    @staticmethod
    def insert_new_email(internal_id, msg_id, subject):
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM Emails WHERE internal_mailpit_id = ?", (internal_id,))
            if not cursor.fetchone():
                print(f"[DB] Found new email: {subject}")
                cursor.execute(
                    "INSERT INTO Emails (internal_mailpit_id, message_id, subject, status) VALUES (?, ?, ?, 'Pending')",
                    (internal_id, msg_id, subject)
                )
                conn.commit()


# --- MAILPIT WATCHER ---
class MailpitWatcher:
    @staticmethod
    def poll_for_new_emails():
        print("[Watcher] Checking Mailpit for new emails...")
        try:
            resp = requests.get(f"{MAILPIT_URL}/api/v1/messages?limit=50", timeout=5)
            if resp.status_code == 200:
                messages = resp.json().get("messages", [])
                for msg in messages:
                    internal_id = msg["ID"]
                    msg_id = msg.get("MessageID", "")
                    subject = msg.get("Subject", "")
                    DatabaseHandler.insert_new_email(internal_id, msg_id, subject)
        except Exception as e:
            print(f"[Watcher] Could not connect to Mailpit: {e}")


# --- AGENT ORCHESTRATOR ---
class AutonomousAgent:
    def __init__(self, email_id: int, mailpit_id: str):
        self.email_id = email_id
        self.mailpit_id = mailpit_id
        # We start the conversation with the System Prompt and the User Request
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Please investigate the newly arrived email. Database email_id is {email_id}. The Mailpit internal ID is '{mailpit_id}'."}
        ]

    async def run(self):
        print(f"\n[Agent] Starting investigation for Email DB ID: {self.email_id}")
        
        # Start the local MCP server (phishing_mcp.py)
        server_params = StdioServerParameters(
            command="python",
            args=["phishing_mcp.py"],
            env=os.environ.copy()
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                # 1. Fetch tools from the MCP server
                mcp_tools = await session.list_tools()
                
                # 2. Convert MCP tools to the format the LLM expects (OpenAI Tool Format)
                llm_tools = []
                for t in mcp_tools.tools:
                    llm_tools.append({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.inputSchema
                        }
                    })
                
                print(f"[Agent] Loaded {len(llm_tools)} tools from MCP server.")

                # 3. Enter the LLM Tool-Calling Loop
                while True:
                    print(f"[LLM] Thinking...")
                    
                    try:
                        response = await llm_client.chat.completions.create(
                            model=MODEL_NAME,
                            messages=self.messages,
                            tools=llm_tools,
                            tool_choice="auto"
                        )
                    except Exception as e:
                        print(f"[LLM] API Error: {e}")
                        print("Please ensure your API key is correct and the server is running.")
                        break

                    response_message = response.choices[0].message
                    
                    # We must append the LLM's raw message to the history so it remembers its own tool calls
                    self.messages.append(response_message)

                    # If the LLM didn't call any tools, it means it is done investigating.
                    if not response_message.tool_calls:
                        print(f"[LLM] Finished Investigation: {response_message.content}")
                        break
                    
                    # If the LLM called tools, execute them via MCP
                    for tool_call in response_message.tool_calls:
                        func_name = tool_call.function.name
                        args = json.loads(tool_call.function.arguments)
                        
                        print(f"[Agent] Executing tool: {func_name}")
                        
                        try:
                            # Send the tool call to the local MCP server
                            mcp_result = await session.call_tool(func_name, args)
                            result_text = mcp_result.content[0].text
                        except Exception as e:
                            result_text = f"Error executing tool: {str(e)}"
                            
                        # Feed the tool's result back to the LLM
                        self.messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "name": func_name,
                            "content": result_text
                        })

# --- MAIN LOOP ---
async def main_loop():
    print("=" * 60)
    print("  PHISHING TRIAGE ORCHESTRATOR STARTED (Phase 1)")
    print(f"  Using Model: {MODEL_NAME}")
    print("=" * 60)
    
    while True:
        MailpitWatcher.poll_for_new_emails()
        
        pending_email = DatabaseHandler.get_pending_emails()
        if pending_email:
            email_id, mailpit_id = pending_email
            agent = AutonomousAgent(email_id, mailpit_id)
            await agent.run()
        else:
            time.sleep(5)  # Wait 5 seconds before polling again

if __name__ == "__main__":
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        print("\n[Orchestrator] Shutting down.")
