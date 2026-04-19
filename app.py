import streamlit as st
import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime
import altair as alt

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
# Load External CSS
# ─────────────────────────────────────────────────────────────

CSS_PATH = Path(__file__).resolve().parent / "style.css"

with open(CSS_PATH) as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# Constants & Helpers
# ─────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "soc_db.sqlite"

SEVERITY_ICONS = {"critical": "🔴", "warning": "🟡", "safe": "🟢"}


def classify_verdict(verdict: str) -> str:
    """Classify verdict into severity level."""
    v = verdict.upper()
    if any(kw in v for kw in ["COMPROMISE", "CRITICAL", "ACTIVE"]):
        return "critical"
    elif any(kw in v for kw in ["SUSPICIOUS", "PHISHING", "MALICIOUS", "CLICKED"]):
        return "warning"
    elif any(kw in v for kw in ["BENIGN", "CLEAN", "FALSE POSITIVE", "SAFE"]):
        return "safe"
    return "warning"


# ─────────────────────────────────────────────────────────────
# Database Functions
# ─────────────────────────────────────────────────────────────

def load_cases() -> pd.DataFrame:
    """Fetch the high-level list of cases."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            return pd.read_sql_query(
                """
                SELECT i.case_id, i.created_at as timestamp, e.message_id, i.verdict 
                FROM Investigations i
                JOIN Emails e ON i.email_id = e.email_id
                ORDER BY i.created_at DESC
                """,
                conn
            )
    except Exception:
        return pd.DataFrame()


def get_case_details(case_id: str) -> tuple | None:
    """Fetch the full details for a specific case."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT i.case_id, i.created_at, e.message_id, i.verdict, i.summary, i.technical_details, i.recommended_actions
                FROM Investigations i
                JOIN Emails e ON i.email_id = e.email_id
                WHERE i.case_id=?
            """, (case_id,))
            return cursor.fetchone()
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# UI Helpers
# ─────────────────────────────────────────────────────────────

def render_metric_card(value, label: str, color: str):
    """Render a styled metric card with the given value, label, and accent color."""
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value" style="color: {color};">{value}</div>
        <div class="metric-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# Load Data
# ─────────────────────────────────────────────────────────────

df = load_cases()

# Process severities once — reused throughout the dashboard
if not df.empty:
    df['severity'] = df['verdict'].apply(classify_verdict)

# ─────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ SOC Triage")
    st.markdown("---")

    if df.empty:
        st.info("No cases in the database.")
        selected_case_id = None
        filtered_df = pd.DataFrame()
    else:
        st.markdown(f"**{len(df)}** total investigation(s) on file")
        st.markdown("")

        # Filter
        selected_severities = st.multiselect(
            "Filter by Severity",
            options=["critical", "warning", "safe"],
            default=["critical", "warning", "safe"],
            format_func=lambda x: x.capitalize()
        )
        
        filtered_df = df[df['severity'].isin(selected_severities)] if selected_severities else df

        # Case selector
        if filtered_df.empty:
            st.warning("No cases match the selected filters.")
            selected_case_id = None
        else:
            filtered_df['display_name'] = filtered_df['case_id'] + "  ·  " + filtered_df['message_id']
            selected_display = st.selectbox(
                "📂 Select Investigation",
                filtered_df['display_name'].tolist(),
                label_visibility="visible"
            )
            selected_case_id = selected_display.split("  ·  ")[0].strip()

        st.markdown("---")

        # Mini timeline in sidebar — uses pre-computed severity column
        st.markdown('<div class="section-header">📋 Recent Activity</div>', unsafe_allow_html=True)
        for _, row in df.head(5).iterrows():
            icon = SEVERITY_ICONS.get(row['severity'], "🟡")
            ts = row['timestamp'][:16].replace("T", " ") if len(row['timestamp']) > 16 else row['timestamp']
            verdict_text = row['verdict'][:60] + ('...' if len(row['verdict']) > 60 else '')
            st.markdown(f"""
            <div class="timeline-item">
                <div class="timeline-time">{ts}</div>
                <div class="timeline-case">{icon} {row['case_id']}</div>
                <div class="timeline-verdict">{verdict_text}</div>
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
    # ── Metrics Row — derived from pre-computed severity column ──
    severity_counts = df['severity'].value_counts()

    metrics = [
        (len(df), "Total Cases", "#818cf8"),
        (severity_counts.get("critical", 0), "Critical", "#ef4444"),
        (severity_counts.get("warning", 0), "Suspicious", "#f59e0b"),
        (df['message_id'].nunique(), "Unique Alerts", "#10b981"),
    ]

    cols = st.columns(4)
    for col, (value, label, color) in zip(cols, metrics):
        with col:
            render_metric_card(value, label, color)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts Row ──
    chart_col1, chart_col2 = st.columns([1, 2])

    chart_severity_df = severity_counts.reset_index()
    chart_severity_df.columns = ['Severity', 'Count']
    
    with chart_col1:
        st.markdown('<div class="section-header">Severity Distribution</div>', unsafe_allow_html=True)
        
        pie_chart = alt.Chart(chart_severity_df).mark_arc(innerRadius=40).encode(
            theta=alt.Theta(field="Count", type="quantitative"),
            color=alt.Color(field="Severity", type="nominal",
                scale=alt.Scale(domain=['critical', 'warning', 'safe'],
                                range=['#ef4444', '#f59e0b', '#10b981']),
                legend=alt.Legend(orient='bottom', title=None)),
            tooltip=['Severity', 'Count']
        ).properties(height=250, background='transparent')
        
        st.altair_chart(pie_chart, width='stretch')

    with chart_col2:
        st.markdown('<div class="section-header">Investigation Timeline</div>', unsafe_allow_html=True)
        try:
            timeline_df = df.copy()
            timeline_df['date'] = pd.to_datetime(timeline_df['timestamp']).dt.date
            daily_counts = timeline_df.groupby(['date', 'severity']).size().reset_index(name='count')
            
            bar_chart = alt.Chart(daily_counts).mark_bar().encode(
                x=alt.X('date:T', title='', axis=alt.Axis(format='%b %d', labelColor='#94a3b8')),
                y=alt.Y('count:Q', title='Cases', axis=alt.Axis(labelColor='#94a3b8', titleColor='#94a3b8')),
                color=alt.Color('severity:N', 
                    scale=alt.Scale(domain=['critical', 'warning', 'safe'], 
                                    range=['#ef4444', '#f59e0b', '#10b981']),
                    legend=None),
                tooltip=['date:T', 'severity:N', 'count:Q']
            ).properties(height=250, background='transparent')
            
            st.altair_chart(bar_chart, width='stretch')
        except Exception:
            st.info("Not enough temporal data for timeline.")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Case Detail View ──
    if selected_case_id:
        details = get_case_details(selected_case_id)
        if details:
            case_id, timestamp, msg_id, verdict, summary, tech_details, actions = details
            severity = classify_verdict(verdict)

            # Verdict badge
            badge_class = f"verdict-{severity}"
            severity_icon = SEVERITY_ICONS.get(severity, "🟡")

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
            tab_summary, tab_tech, tab_actions, tab_raw = st.tabs(
                ["📄 Investigation Summary", "🔬 Technical Details", "⚡ Recommended Actions", "🔍 Raw Data"]
            )

            with tab_summary:
                st.markdown("#### Investigation Summary")
                st.markdown(summary)

            with tab_tech:
                st.markdown("#### Detailed Technical Analysis")
                st.markdown(tech_details)

            with tab_actions:
                st.markdown("#### Recommended Response Actions")
                st.markdown(actions)

            with tab_raw:
                st.markdown("#### Raw Case Record")
                st.json({
                    "case_id": case_id,
                    "timestamp": timestamp,
                    "message_id": msg_id,
                    "verdict": verdict,
                    "summary": summary,
                    "technical_details": tech_details,
                    "recommended_actions": actions
                })