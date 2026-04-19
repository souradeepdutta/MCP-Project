"""
Secure MCP Gateway with RBAC, Audit Logging, and Input Validation.

This gateway sits between the AI Orchestrator and the MCP tools. It:
1. Authenticates agents via Bearer tokens.
2. Enforces Role-Based Access Control (RBAC) on tool visibility and execution.
3. Logs every tool call to an immutable audit log.
4. Validates tool inputs (e.g., IP format) to prevent injection attacks.

Architecture:
    Orchestrator --[SSE + Bearer Token]--> Gateway --[delegates]--> phishing_mcp tools
"""

import ipaddress
import json
import logging
import sys

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.routing import Route, Mount

from mcp.server.lowlevel.server import Server
from mcp.server.sse import SseServerTransport
import mcp.types as types

import phishing_mcp
from config import INTERNAL_DOMAINS, GATEWAY_PORT

# ─────────────────────────────────────────────────────────────
# 1. Audit Logging Setup
# ─────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO)
audit_logger = logging.getLogger("audit")
audit_logger.propagate = False
audit_logger.setLevel(logging.INFO)

_fmt = logging.Formatter("%(asctime)s [AUDIT] %(levelname)s - %(message)s")

# Write to file (immutable record)
_file_handler = logging.FileHandler("audit.log")
_file_handler.setFormatter(_fmt)
audit_logger.addHandler(_file_handler)

# Also surface audit events in the terminal for the PoC
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_fmt)
audit_logger.addHandler(_console_handler)

# ─────────────────────────────────────────────────────────────
# 2. Load RBAC Configuration
# ─────────────────────────────────────────────────────────────

try:
    with open("gateway_config.json") as f:
        _config = json.load(f)
    TOKENS: dict[str, str] = _config["tokens"]     # token -> role
    ROLES: dict[str, list[str]] = _config["roles"]  # role  -> [tool_names]
except Exception as e:
    print(f"FATAL: Failed to load gateway_config.json: {e}")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────
# 3. Tool Definitions (with security interceptors)
# ─────────────────────────────────────────────────────────────

# Each entry: (tool_name, description, input_schema, handler_fn)
# The handler_fn receives the arguments dict and the role string.

def _handle_get_email_artifacts(args: dict, role: str) -> list[types.TextContent]:
    mailpit_id = args["internal_mailpit_id"]
    audit_logger.info(f"EXEC | Role: {role} | Tool: get_email_artifacts | Args: {mailpit_id}")
    result = phishing_mcp.get_email_artifacts(mailpit_id)
    return [types.TextContent(type="text", text=result)]


def _handle_check_threat_intel(args: dict, role: str) -> list[types.TextContent]:
    indicator = args["indicator"]
    indicator_type = args["indicator_type"]
    audit_logger.info(f"EXEC | Role: {role} | Tool: check_threat_intel | Args: {indicator}")

    # OpSec Filter: block internal domains from reaching VirusTotal
    if any(domain in indicator.lower() for domain in INTERNAL_DOMAINS):
        audit_logger.warning(f"BLOCKED | Role: {role} | Tool: check_threat_intel | Reason: Internal Domain OpSec")
        return [types.TextContent(type="text", text=f"BLOCKED: '{indicator}' is an internal domain. OpSec policy prevents querying public Threat Intel.")]

    result = phishing_mcp.check_threat_intel(indicator, indicator_type)
    return [types.TextContent(type="text", text=result)]


def _handle_query_splunk_for_clicks(args: dict, role: str) -> list[types.TextContent]:
    url = args["url"]
    audit_logger.info(f"EXEC | Role: {role} | Tool: query_splunk_for_clicks | Args: {url}")
    result = phishing_mcp.query_splunk_for_clicks(url)
    return [types.TextContent(type="text", text=result)]


def _handle_query_endpoint_activity(args: dict, role: str) -> list[types.TextContent]:
    ip_address = args["ip_address"]
    audit_logger.info(f"EXEC | Role: {role} | Tool: query_endpoint_activity | Args: {ip_address}")

    # Input Validation: proper IPv4 check to prevent SPL injection
    try:
        ipaddress.IPv4Address(ip_address)
    except ValueError:
        audit_logger.warning(f"BLOCKED | Role: {role} | Tool: query_endpoint_activity | Reason: Invalid IP format '{ip_address}'")
        return [types.TextContent(type="text", text=f"BLOCKED: '{ip_address}' is not a valid IPv4 address. Preventing SPL injection.")]

    result = phishing_mcp.query_endpoint_activity(ip_address)
    return [types.TextContent(type="text", text=result)]


def _handle_save_investigation_report(args: dict, role: str) -> list[types.TextContent]:
    audit_logger.info(f"EXEC | Role: {role} | Tool: save_investigation_report | Args: email_id={args['email_id']}, verdict={args['verdict']}")
    result = phishing_mcp.save_investigation_report(
        args["email_id"], args["verdict"], args["severity"],
        args["summary"], args["technical_details"], args["recommended_actions"],
        args["confidence_score"], args.get("uncertainty_factors", [])
    )
    return [types.TextContent(type="text", text=result)]


# Master registry of all tools available in the gateway
TOOL_REGISTRY: dict[str, dict] = {
    "get_email_artifacts": {
        "description": "Retrieves extracted indicators from a reported suspicious email via Mailpit using its internal Mailpit ID. Always run this first.",
        "schema": {
            "type": "object",
            "properties": {
                "internal_mailpit_id": {"type": "string", "description": "The internal Mailpit ID of the email."}
            },
            "required": ["internal_mailpit_id"]
        },
        "handler": _handle_get_email_artifacts,
    },
    "check_threat_intel": {
        "description": "Queries threat intelligence for a domain, IP, URL, or file hash. indicator_type must be one of: 'domain', 'ip', 'hash', 'url', 'filename'.",
        "schema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "The indicator value to look up."},
                "indicator_type": {"type": "string", "description": "Type of indicator: domain, ip, hash, url, or filename."}
            },
            "required": ["indicator", "indicator_type"]
        },
        "handler": _handle_check_threat_intel,
    },
    "query_splunk_for_clicks": {
        "description": "Queries the SIEM (Splunk) to see if any users clicked a specific URL. Use this to determine the blast radius.",
        "schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to search for in proxy logs."}
            },
            "required": ["url"]
        },
        "handler": _handle_query_splunk_for_clicks,
    },
    "query_endpoint_activity": {
        "description": "Queries EDR logs in Splunk to check for suspicious process execution on a specific machine. Run this ONLY IF a user has clicked a malicious link.",
        "schema": {
            "type": "object",
            "properties": {
                "ip_address": {"type": "string", "description": "The IPv4 address of the endpoint to investigate."}
            },
            "required": ["ip_address"]
        },
        "handler": _handle_query_endpoint_activity,
    },
    "save_investigation_report": {
        "description": "Saves the final investigation verdict and summary into the local case management database. Run this ONLY as the final step.",
        "schema": {
            "type": "object",
            "properties": {
                "email_id": {"type": "integer", "description": "The integer email ID from the Emails table."},
                "verdict": {"type": "string"},
                "severity": {"type": "string"},
                "summary": {"type": "string"},
                "technical_details": {"type": "string"},
                "recommended_actions": {"type": "string"},
                "confidence_score": {"type": "number", "description": "A float between 0.0 and 1.0 representing your confidence in the verdict."},
                "uncertainty_factors": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "A list of strings explaining any blind spots or reasons for uncertainty. Empty if fully confident."
                }
            },
            "required": ["email_id", "verdict", "severity", "summary", "technical_details", "recommended_actions", "confidence_score", "uncertainty_factors"]
        },
        "handler": _handle_save_investigation_report,
    },
}


# ─────────────────────────────────────────────────────────────
# 4. Server Factory (creates a role-scoped MCP Server per session)
# ─────────────────────────────────────────────────────────────

def create_server_for_role(role: str) -> Server:
    """Build an MCP Server instance that only exposes the tools allowed for the given role."""
    allowed_tool_names = ROLES.get(role, [])
    server = Server(f"Gateway-{role}")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        tools = []
        for name in allowed_tool_names:
            entry = TOOL_REGISTRY.get(name)
            if entry:
                tools.append(types.Tool(name=name, description=entry["description"], inputSchema=entry["schema"]))
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        # Enforce RBAC at execution time
        if name not in allowed_tool_names:
            audit_logger.warning(f"DENIED | Role: {role} | Tool: {name} | Reason: Not authorized for role")
            return [types.TextContent(type="text", text=f"ACCESS DENIED: Tool '{name}' is not authorized for role '{role}'.")]

        entry = TOOL_REGISTRY.get(name)
        if not entry:
            return [types.TextContent(type="text", text=f"ERROR: Tool '{name}' does not exist in the gateway registry.")]

        return entry["handler"](arguments, role)

    return server


# ─────────────────────────────────────────────────────────────
# 5. Starlette App with SSE Transport
# ─────────────────────────────────────────────────────────────

sse_transport = SseServerTransport("/messages/")


async def handle_sse(request: Request):
    """Authenticate the agent, build a role-scoped MCP server, and run it over SSE."""

    # --- Authentication ---
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        audit_logger.warning("DENIED | Reason: Missing or malformed Bearer token")
        return JSONResponse({"error": "Missing or invalid Bearer token"}, status_code=401)

    token = auth_header.split(" ", 1)[1]
    if token not in TOKENS:
        audit_logger.warning(f"DENIED | Token: {token} | Reason: Unknown token")
        return JSONResponse({"error": "Forbidden: unknown token"}, status_code=403)

    role = TOKENS[token]
    audit_logger.info(f"CONNECT | Token: {token} | Role: {role}")
    print(f"[Gateway] Agent connected. Role: {role}")

    # --- Create a role-scoped server and run it ---
    server = create_server_for_role(role)

    async with sse_transport.connect_sse(request.scope, request.receive, request._send) as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

    return Response()


app = Starlette(
    routes=[
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse_transport.handle_post_message),
    ],
)

# ─────────────────────────────────────────────────────────────
# 6. Entrypoint
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  SECURE MCP GATEWAY STARTED")
    print(f"  Roles loaded: {list(ROLES.keys())}")
    print(f"  Tools in registry: {list(TOOL_REGISTRY.keys())}")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=GATEWAY_PORT)
