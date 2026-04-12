import streamlit as st
import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# Page Configuration
# ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="AI SOC Triage Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────
# Custom CSS — Premium SOC Dark Theme
# ─────────────────────────────────────────────────────────────

st.markdown("""
<style>
    /* ── Import Google Font ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    /* ── Global ── */
    .stApp {
        font-family: 'Inter', sans-serif;
    }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a0f1e 0%, #111827 100%);
        border-right: 1px solid rgba(99, 102, 241, 0.15);
    }
    section[data-testid="stSidebar"] .stMarkdown h1,
    section[data-testid="stSidebar"] .stMarkdown h2,
    section[data-testid="stSidebar"] .stMarkdown h3 {
        color: #e0e7ff;
    }
    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stMarkdown li {
        color: #94a3b8;
    }

    /* ── Metric Cards ── */
    .metric-card {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.9) 100%);
        border: 1px solid rgba(99, 102, 241, 0.2);
        border-radius: 16px;
        padding: 24px;
        text-align: center;
        backdrop-filter: blur(12px);
        transition: all 0.3s ease;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
    }
    .metric-card:hover {
        border-color: rgba(99, 102, 241, 0.5);
        transform: translateY(-2px);
        box-shadow: 0 8px 32px rgba(99, 102, 241, 0.15);
    }
    .metric-value {
        font-size: 2.8rem;
        font-weight: 800;
        line-height: 1;
        margin-bottom: 4px;
    }
    .metric-label {
        font-size: 0.85rem;
        font-weight: 500;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 1.5px;
    }

    /* ── Verdict Badges ── */
    .verdict-critical {
        background: linear-gradient(135deg, #991b1b 0%, #dc2626 100%);
        color: #fef2f2;
        padding: 6px 18px;
        border-radius: 24px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
        letter-spacing: 0.5px;
        box-shadow: 0 0 20px rgba(220, 38, 38, 0.3);
    }
    .verdict-warning {
        background: linear-gradient(135deg, #92400e 0%, #f59e0b 100%);
        color: #1a1a2e;
        padding: 6px 18px;
        border-radius: 24px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
        letter-spacing: 0.5px;
        box-shadow: 0 0 20px rgba(245, 158, 11, 0.2);
    }
    .verdict-safe {
        background: linear-gradient(135deg, #065f46 0%, #10b981 100%);
        color: #ecfdf5;
        padding: 6px 18px;
        border-radius: 24px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
        letter-spacing: 0.5px;
        box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
    }

    /* ── Case Card ── */
    .case-card {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.6) 100%);
        border: 1px solid rgba(99, 102, 241, 0.15);
        border-radius: 16px;
        padding: 28px;
        margin-bottom: 16px;
        backdrop-filter: blur(12px);
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.2);
    }
    .case-card h3 {
        color: #e0e7ff;
        margin-bottom: 8px;
    }

    /* ── Section Headers ── */
    .section-header {
        font-size: 1.1rem;
        font-weight: 700;
        color: #818cf8;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-bottom: 16px;
        padding-bottom: 8px;
        border-bottom: 2px solid rgba(99, 102, 241, 0.2);
    }

    /* ── Timeline ── */
    .timeline-item {
        border-left: 3px solid #6366f1;
        padding: 8px 0 8px 20px;
        margin-left: 12px;
        position: relative;
    }
    .timeline-item::before {
        content: '';
        position: absolute;
        left: -7px;
        top: 12px;
        width: 11px;
        height: 11px;
        border-radius: 50%;
        background: #6366f1;
        box-shadow: 0 0 8px rgba(99, 102, 241, 0.6);
    }
    .timeline-time {
        font-size: 0.75rem;
        color: #64748b;
        font-weight: 500;
    }
    .timeline-case {
        font-size: 0.9rem;
        font-weight: 600;
        color: #e0e7ff;
    }
    .timeline-verdict {
        font-size: 0.8rem;
        color: #94a3b8;
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar {
        width: 6px;
    }
    ::-webkit-scrollbar-track {
        background: #0f172a;
    }
    ::-webkit-scrollbar-thumb {
        background: #334155;
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #475569;
    }

    /* ── Hide Streamlit Branding ── */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* ── Tab styling ── */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px 8px 0 0;
        padding: 10px 24px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# Database Functions
# ─────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cases.db"


def load_cases() -> pd.DataFrame:
    """Fetch the high-level list of cases."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT case_id, timestamp, message_id, verdict FROM investigations ORDER BY timestamp DESC",
            conn
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


def get_case_details(case_id: str) -> tuple | None:
    """Fetch the full details for a specific case."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM investigations WHERE case_id=?", (case_id,))
    case = c.fetchone()
    conn.close()
    return case


def classify_verdict(verdict: str) -> str:
    """Classify verdict into severity level."""
    v = verdict.upper()
    if any(kw in v for kw in ["COMPROMISE", "CRITICAL", "ACTIVE"]):
        return "critical"
    elif any(kw in v for kw in ["SUSPICIOUS", "PHISHING", "MALICIOUS", "CLICKED"]):
        return "warning"
    elif any(kw in v for kw in ["BENIGN", "CLEAN", "FALSE POSITIVE"]):
        return "safe"
    return "warning"


# ─────────────────────────────────────────────────────────────
# Load Data
# ─────────────────────────────────────────────────────────────

df = load_cases()

# ─────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ SOC Triage")
    st.markdown("---")

    if df.empty:
        st.info("No cases in the database.")
        selected_case_id = None
    else:
        st.markdown(f"**{len(df)}** investigation(s) on file")
        st.markdown("")

        # Case selector
        df['display_name'] = df['case_id'] + "  ·  " + df['message_id']
        selected_display = st.selectbox(
            "📂 Select Investigation",
            df['display_name'].tolist(),
            label_visibility="visible"
        )
        selected_case_id = selected_display.split("  ·  ")[0].strip()

        st.markdown("---")

        # Mini timeline in sidebar
        st.markdown('<div class="section-header">📋 Recent Activity</div>', unsafe_allow_html=True)
        for _, row in df.head(5).iterrows():
            severity = classify_verdict(row['verdict'])
            icon = "🔴" if severity == "critical" else "🟡" if severity == "warning" else "🟢"
            ts = row['timestamp'][:16].replace("T", " ") if len(row['timestamp']) > 16 else row['timestamp']
            st.markdown(f"""
            <div class="timeline-item">
                <div class="timeline-time">{ts}</div>
                <div class="timeline-case">{icon} {row['case_id']}</div>
                <div class="timeline-verdict">{row['verdict'][:60]}{'...' if len(row['verdict']) > 60 else ''}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown(
        '<p style="color: #475569; font-size: 0.7rem; text-align: center;">Phishing Triage Agent v2.0<br>Powered by MCP</p>',
        unsafe_allow_html=True
    )

# ─────────────────────────────────────────────────────────────
# Main Content
# ─────────────────────────────────────────────────────────────

# Header
st.markdown("""
<div style="display: flex; align-items: center; gap: 16px; margin-bottom: 8px;">
    <span style="font-size: 2.2rem;">🛡️</span>
    <div>
        <h1 style="margin: 0; padding: 0; font-weight: 800; letter-spacing: -0.5px;">
            AI Phishing Investigation Dashboard
        </h1>
        <p style="margin: 0; color: #64748b; font-size: 0.95rem;">
            Autonomous triage reports generated by the MCP Agent
        </p>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

if df.empty:
    st.markdown("""
    <div style="text-align: center; padding: 80px 20px;">
        <div style="font-size: 4rem; margin-bottom: 16px;">📭</div>
        <h2 style="color: #e0e7ff;">No Investigations Yet</h2>
        <p style="color: #64748b; max-width: 500px; margin: 0 auto;">
            Trigger the AI agent to investigate a phishing alert. 
            Cases will appear here automatically once the agent completes its triage.
        </p>
    </div>
    """, unsafe_allow_html=True)

else:
    # ── Metrics Row ──
    total_cases = len(df)
    critical_count = sum(1 for v in df['verdict'] if classify_verdict(v) == "critical")
    warning_count = sum(1 for v in df['verdict'] if classify_verdict(v) == "warning")
    safe_count = sum(1 for v in df['verdict'] if classify_verdict(v) == "safe")
    unique_alerts = df['message_id'].nunique()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #818cf8;">{total_cases}</div>
            <div class="metric-label">Total Cases</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #ef4444;">{critical_count}</div>
            <div class="metric-label">Critical</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #f59e0b;">{warning_count}</div>
            <div class="metric-label">Suspicious</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #10b981;">{unique_alerts}</div>
            <div class="metric-label">Unique Alerts</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Case Detail View ──
    if selected_case_id:
        details = get_case_details(selected_case_id)
        if details:
            case_id, timestamp, msg_id, verdict, summary, actions = details
            severity = classify_verdict(verdict)

            # Verdict badge
            badge_class = f"verdict-{severity}"
            severity_icon = "🔴" if severity == "critical" else "🟡" if severity == "warning" else "🟢"

            # Parse timestamp
            try:
                ts_parsed = datetime.fromisoformat(timestamp)
                formatted_ts = ts_parsed.strftime("%B %d, %Y  ·  %I:%M %p")
            except Exception:
                formatted_ts = timestamp

            # Case header
            st.markdown(f"""
            <div class="case-card">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
                    <div>
                        <h2 style="margin: 0; color: #e0e7ff; font-weight: 800;">{severity_icon} {case_id}</h2>
                        <p style="color: #64748b; margin: 4px 0 12px 0; font-size: 0.9rem;">
                            Alert: <strong style="color: #94a3b8;">{msg_id}</strong>  ·  {formatted_ts}
                        </p>
                    </div>
                    <div>
                        <span class="{badge_class}">{verdict}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Tabs for Summary and Actions
            tab_summary, tab_actions, tab_raw = st.tabs(["📄 Investigation Summary", "⚡ Recommended Actions", "🔍 Raw Data"])

            with tab_summary:
                st.markdown(f"""
                <div class="case-card">
                    <div class="section-header">Investigation Summary</div>
                    <div style="color: #cbd5e1; line-height: 1.8; font-size: 0.95rem;">
                        {summary.replace(chr(10), '<br>')}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with tab_actions:
                st.markdown(f"""
                <div class="case-card">
                    <div class="section-header">Recommended Response Actions</div>
                    <div style="color: #cbd5e1; line-height: 1.8; font-size: 0.95rem;">
                        {actions.replace(chr(10), '<br>')}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with tab_raw:
                st.markdown('<div class="section-header">Raw Case Record</div>', unsafe_allow_html=True)
                st.json({
                    "case_id": case_id,
                    "timestamp": timestamp,
                    "message_id": msg_id,
                    "verdict": verdict,
                    "summary": summary,
                    "recommended_actions": actions
                })