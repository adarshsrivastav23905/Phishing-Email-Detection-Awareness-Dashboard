import pandas as pd
import streamlit as st

from src.config import DATASET_PATH
from src.database import get_history, init_db, save_analysis
from src.ml_model import predict_ml_label, train_ml_model
from src.phishing_engine import SAMPLE_PHISHING_EMAIL, SAMPLE_SAFE_EMAIL, generate_analysis


st.set_page_config(page_title="Phishing Email Detection & Awareness Dashboard", layout="wide")

st.markdown(
    """
    <style>
    .main {
        background: linear-gradient(135deg, #071b2f 0%, #0d233d 30%, #101d2d 100%);
    }
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
    }
    .hero {
        background: linear-gradient(135deg, rgba(26, 88, 170, 0.2), rgba(13, 35, 61, 0.8));
        border: 1px solid rgba(115, 147, 175, 0.28);
        border-radius: 22px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.5rem;
    }
    .title-label {
        letter-spacing: 0.12em;
        text-transform: uppercase;
        font-size: 0.74rem;
        color: #8ad4ff;
        font-weight: 700;
    }
    .card {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(138, 212, 255, 0.15);
        border-radius: 16px;
        padding: 1rem;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.18);
    }
    .stButton > button {
        border-radius: 10px;
        font-weight: 600;
        background: linear-gradient(135deg, #4ab7ff, #7a7dff);
        color: white;
        border: none;
    }
    .stDownloadButton > button {
        border-radius: 10px;
        font-weight: 600;
        background: linear-gradient(135deg, #148f70, #1bbd8e);
        color: white;
        border: none;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


st.markdown(
    """
    <div class="hero">
      <div class="title-label">Cybersecurity portfolio project</div>
      <h1 style="margin: 0.2rem 0 0.6rem 0; color: #f2f7ff;">Phishing Email Detection & Awareness Dashboard</h1>
      <div style="color: #c7d8ea; font-size: 1.02rem;">Defensive, explainable, and beginner-friendly phishing analysis with awareness education.</div>
    </div>
    """,
    unsafe_allow_html=True,
)


init_db()


@st.cache_resource
def load_model():
    try:
        return train_ml_model(DATASET_PATH)
    except Exception:
        return None


def build_report_text(report):
    risk = report.get("risk_score", 0)
    classification = report.get("classification", "SAFE")
    lines = [
        "Phishing Email Detection & Awareness Dashboard",
        "=" * 60,
        "Executive Security Assessment",
        "=" * 60,
        f"Timestamp: {report.get('created_at', 'N/A')}",
        f"Sender: {report.get('sender', '')}",
        f"Subject: {report.get('subject', '')}",
        f"Overall Classification: {classification}",
        f"Risk Score: {risk}/100",
        "",
        "Executive Summary:",
        (
            "This message was assessed using a defensive phishing detection workflow that combines sender, "
            "content, URL, and attachment indicators. The final risk result reflects the strength and "
            "quantity of suspicious indicators observed during analysis."
        ),
        "",
        "Key Findings:",
    ]
    for item in report.get("explanation", []):
        lines.append(f"- {item}")

    lines += ["", "Risk Driver Breakdown:"]
    metrics = {
        "Sender": report.get("sender_details", {}).get("sender_risk_score", 0),
        "Content": report.get("content_details", {}).get("content_risk_score", 0),
        "URL": report.get("url_details", {}).get("url_risk_score", 0),
        "Attachment": report.get("attachment_details", {}).get("attachment_risk_score", 0),
    }
    for label, score in metrics.items():
        lines.append(f"- {label}: {score}/100")

    lines += ["", "Recommended Response:"]
    for item in report.get("recommendations", []):
        lines.append(f"- {item}")

    lines += ["", "Feature Snapshot:"]
    for key, value in report.get("features", {}).items():
        lines.append(f"- {key}: {value}")

    lines += ["",
        "Assessment Note:",
        "This output is intended for defensive learning and awareness purposes and should be used as an "
        "explainable decision-support tool rather than a replacement for a formal security investigation."]
    return "\n".join(lines)


if "last_report" not in st.session_state:
    st.session_state.last_report = None


with st.sidebar:
    st.header("Controls")
    sample_type = st.segmented_control("Sample profile", ["Custom", "Safe example", "Phishing example"], default="Custom")

    if sample_type == "Safe example":
        sender = SAMPLE_SAFE_EMAIL["sender"]
        display_name = SAMPLE_SAFE_EMAIL["display_name"]
        subject = SAMPLE_SAFE_EMAIL["subject"]
        body = SAMPLE_SAFE_EMAIL["body"]
        url_input = ", ".join(SAMPLE_SAFE_EMAIL["urls"])
        attachment_name = SAMPLE_SAFE_EMAIL["attachment_name"]
    elif sample_type == "Phishing example":
        sender = SAMPLE_PHISHING_EMAIL["sender"]
        display_name = SAMPLE_PHISHING_EMAIL["display_name"]
        subject = SAMPLE_PHISHING_EMAIL["subject"]
        body = SAMPLE_PHISHING_EMAIL["body"]
        url_input = ", ".join(SAMPLE_PHISHING_EMAIL["urls"])
        attachment_name = SAMPLE_PHISHING_EMAIL["attachment_name"]
    else:
        sender = "alice@company.example.com"
        display_name = "IT Help Desk"
        subject = "Password verification needed"
        body = "Hello, please verify your account using the link below to avoid service interruption."
        url_input = "https://portal.example.com/verify"
        attachment_name = ""

    uploaded_file = st.file_uploader("Upload safe .txt or .eml sample", type=["txt", "eml"]) 
    if uploaded_file is not None:
        try:
            raw = uploaded_file.read().decode("utf-8", errors="ignore")
        except Exception:
            raw = uploaded_file.read().decode("latin-1", errors="ignore")
        sender_lines = [line for line in raw.splitlines() if line.lower().startswith("from:")]
        subject_lines = [line for line in raw.splitlines() if line.lower().startswith("subject:")]
        if sender_lines:
            sender = sender_lines[0].split(":", 1)[1].strip()
        if subject_lines:
            subject = subject_lines[0].split(":", 1)[1].strip()
        if "\n\n" in raw:
            body = raw.split("\n\n", 1)[1].strip()
        else:
            body = raw.strip()

    st.markdown("<div class='card'>")
    st.markdown("### Quick security reminder")
    st.markdown("- Never click unexpected links or attachments.")
    st.markdown("- Verify requests using official channels.")
    st.markdown("- If it feels urgent, slow down and confirm.")
    st.markdown("</div>", unsafe_allow_html=True)

with st.form("analysis_form"):
    col1, col2 = st.columns(2)
    with col1:
        sender = st.text_input("Sender email", value=sender)
        subject = st.text_input("Email subject", value=subject)
    with col2:
        display_name = st.text_input("Display name", value=display_name)
        attachment_name = st.text_input("Attachment name", value=attachment_name)

    body = st.text_area("Email body", value=body, height=240)
    url_input = st.text_input("URLs (comma or space separated)", value=url_input)

    submitted = st.form_submit_button("Analyze Email", use_container_width=True)

if submitted:
    report = generate_analysis(sender, subject, body, display_name, url_input, attachment_name)
    save_analysis(report)
    st.session_state.last_report = report

report = st.session_state.last_report

if report:
    score = report["risk_score"]
    classification = report["classification"]

    overview_col1, overview_col2, overview_col3 = st.columns(3)
    with overview_col1:
        st.metric("Risk score", f"{score}/100")
    with overview_col2:
        st.metric("Classification", classification)
    with overview_col3:
        st.metric("Main issue", "Urgency" if score >= 50 else "Low signals")

    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.progress(score / 100)
    if score >= 75:
        st.error(f"Classification: {classification}")
    elif score >= 50:
        st.warning(f"Classification: {classification}")
    elif score >= 25:
        st.info(f"Classification: {classification}")
    else:
        st.success(f"Classification: {classification}")
    st.markdown("</div>", unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs(["Executive overview", "Threat indicators", "Education", "Export & history"])

    with tab1:
        st.subheader("Why this may be suspicious")
        for item in report["explanation"]:
            st.markdown(f"- {item}")

        st.subheader("Recommended actions")
        for item in report["recommendations"]:
            st.markdown(f"- {item}")

        st.subheader("Feature snapshot")
        feature_df = pd.DataFrame(report["features"].items(), columns=["Feature", "Value"])
        st.dataframe(feature_df, use_container_width=True, hide_index=True)

    with tab2:
        metrics = {
            "Sender": report["sender_details"]["sender_risk_score"],
            "Content": report["content_details"]["content_risk_score"],
            "URL": report["url_details"]["url_risk_score"],
            "Attachment": report["attachment_details"]["attachment_risk_score"],
        }
        chart_df = pd.DataFrame({"Risk component": list(metrics.keys()), "Score": list(metrics.values())}).set_index("Risk component")
        st.bar_chart(chart_df)

        st.subheader("Detailed indicator breakdown")
        sender_df = pd.DataFrame({"Findings": report["sender_details"]["sender_findings"]})
        content_df = pd.DataFrame({"Findings": report["content_details"]["content_findings"]})
        url_df = pd.DataFrame({"Findings": report["url_details"]["url_findings"]})
        attachment_df = pd.DataFrame({"Findings": report["attachment_details"]["attachment_findings"]})

        st.caption("Sender findings")
        st.dataframe(sender_df, use_container_width=True, hide_index=True)
        st.caption("Content findings")
        st.dataframe(content_df, use_container_width=True, hide_index=True)
        st.caption("URL findings")
        st.dataframe(url_df, use_container_width=True, hide_index=True)
        st.caption("Attachment findings")
        st.dataframe(attachment_df, use_container_width=True, hide_index=True)

    with tab3:
        st.subheader("Phishing awareness guidance")
        st.markdown(
            "- Slow down and verify unexpected requests through a trusted channel rather than the email itself.\n"
            "- Do not trust urgency, fear, or threats without confirming the source.\n"
            "- Treat password resets, account reviews, invoices, and payment issues as high-risk until verified.\n"
            "- Hover over links, inspect the destination, and avoid shortened or unfamiliar URLs.\n"
            "- Report suspicious messages to your IT or security team and keep training up to date."
        )

    with tab4:
        report_text = build_report_text(report)
        st.download_button(
            label="Download analysis report (.txt)",
            data=report_text,
            file_name="phishing_analysis_report.txt",
            mime="text/plain",
        )

        history = get_history(12)
        if history:
            history_df = pd.DataFrame(history)
            st.download_button(
                label="Download history (.csv)",
                data=history_df.to_csv(index=False),
                file_name="analysis_history.csv",
                mime="text/csv",
            )
            st.dataframe(history_df, use_container_width=True, hide_index=True)
        else:
            st.info("There is no saved history yet.")

else:
    st.info("Run an analysis to see phishing risk findings, explanations, and dashboard insights.")
    st.markdown("### Portfolio-ready project highlights")
    st.markdown(
        "- Explainable phishing risk scoring\n"
        "- Safe synthetic dataset and ethical design\n"
        "- Defensive awareness education\n"
        "- Downloadable report generation\n"
        "- Dashboard analytics with persistent history"
    )
