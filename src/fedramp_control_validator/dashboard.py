"""Streamlit dashboard for fedramp-control-validator.

Run with::

    streamlit run src/fedramp_control_validator/dashboard.py

The dashboard ships with a dark "security operations" theme (see
``.streamlit/config.toml``). It lets an analyst upload AWS Config findings
JSON (or load the bundled sample), then explore the FedRAMP Moderate score,
per-family ratings, the gap analysis, and download the OSCAL 1.1.2 export.
"""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from fedramp_control_validator import __version__
from fedramp_control_validator.gap import build_gaps, gap_summary
from fedramp_control_validator.models import FAIL, NOT_ASSESSED, PARTIAL, PASS
from fedramp_control_validator.oscal import to_oscal
from fedramp_control_validator.parsers import ParseError, load_findings, parse_findings
from fedramp_control_validator.validator import validate

# Resolve the bundled sample relative to the repo root.
SAMPLE_PATH = Path(__file__).resolve().parents[2] / "examples" / "aws_config_findings.json"

_STATUS_COLOR = {
    PASS: "#22c55e",
    FAIL: "#ef4444",
    PARTIAL: "#f59e0b",
    NOT_ASSESSED: "#64748b",
}
_STATUS_LABEL = {
    PASS: "PASS",
    FAIL: "FAIL",
    PARTIAL: "PARTIAL",
    NOT_ASSESSED: "N/A",
}

_CUSTOM_CSS = """
<style>
.block-container { padding-top: 2rem; }
.fcv-pill {
    display: inline-block; padding: 2px 10px; border-radius: 999px;
    font-size: 0.75rem; font-weight: 700; letter-spacing: 0.04em;
    color: #0b0f17;
}
.fcv-gap {
    border-left: 4px solid #ef4444; background: #11161f;
    padding: 0.75rem 1rem; margin-bottom: 0.6rem; border-radius: 6px;
}
.fcv-gap.partial { border-left-color: #f59e0b; }
.fcv-mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
h1 span.fcv-accent { color: #38bdf8; }
</style>
"""


def _pill(status: str) -> str:
    return (
        f'<span class="fcv-pill" style="background:{_STATUS_COLOR[status]}">'
        f"{_STATUS_LABEL[status]}</span>"
    )


def _score_color(score: float) -> str:
    if score >= 90:
        return "#22c55e"
    if score >= 70:
        return "#f59e0b"
    return "#ef4444"


def _load_report():
    st.sidebar.header("Findings input")
    uploaded = st.sidebar.file_uploader("AWS Config findings (JSON)", type=["json"])
    use_sample = st.sidebar.button("Load bundled sample", use_container_width=True)

    if uploaded is not None:
        try:
            doc = json.load(uploaded)
            finding_set = parse_findings(doc, source=uploaded.name)
        except (json.JSONDecodeError, ParseError) as exc:
            st.sidebar.error(f"Could not parse: {exc}")
            return None
    elif use_sample or "loaded_once" not in st.session_state:
        if not SAMPLE_PATH.exists():
            st.sidebar.warning("Bundled sample not found. Upload a findings file.")
            return None
        finding_set = load_findings(SAMPLE_PATH)
        st.session_state["loaded_once"] = True
    else:
        return None

    return validate(finding_set)


def main() -> None:
    st.set_page_config(
        page_title="FedRAMP Control Validator",
        page_icon="🛡️",
        layout="wide",
    )
    st.markdown(_CUSTOM_CSS, unsafe_allow_html=True)
    st.markdown(
        "# 🛡️ FedRAMP <span class='fcv-accent'>Control Validator</span>",
        unsafe_allow_html=True,
    )
    st.caption(
        f"FedRAMP Moderate · NIST 800-53 Rev 5 · OSCAL 1.1.2 export · v{__version__}"
    )

    report = _load_report()
    if report is None:
        st.info("Upload AWS Config findings JSON or load the bundled sample to begin.")
        return

    counts = report.counts()
    score = round(report.overall_score * 100, 1)

    # --- Top-line metrics --------------------------------------------------
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Overall score", f"{score}%")
    c2.metric("Passing", counts[PASS])
    c3.metric("Partial", counts[PARTIAL])
    c4.metric("Failing", counts[FAIL])
    c5.metric("Account", report.account_id)

    st.progress(min(score / 100, 1.0))

    # --- Family scores -----------------------------------------------------
    st.subheader("Control family scores")
    fam_cols = st.columns(4)
    assessed_families = [f for f in report.families if f.status != NOT_ASSESSED]
    for i, family in enumerate(assessed_families):
        fscore = round(family.score * 100, 1)
        with fam_cols[i % 4]:
            st.markdown(
                f"**{family.family}** &nbsp; {_pill(family.status)}<br>"
                f"<span class='fcv-mono' style='color:{_score_color(fscore)};"
                f"font-size:1.4rem'>{fscore}%</span><br>"
                f"<span style='color:#94a3b8;font-size:0.8rem'>{family.title}</span><br>"
                f"<span style='color:#64748b;font-size:0.75rem'>"
                f"{family.passing} pass · {family.partial} partial · "
                f"{family.failing} fail</span>",
                unsafe_allow_html=True,
            )

    # --- Gap analysis ------------------------------------------------------
    st.subheader("Gap analysis")
    gaps = build_gaps(report)
    if not gaps:
        st.success("No failing or partial controls — every assessed control passes.")
    for gap in gaps:
        cls = "fcv-gap partial" if gap.status == PARTIAL else "fcv-gap"
        reasons = "".join(
            f"<li style='color:#cbd5e1;font-size:0.85rem'>{r}</li>" for r in gap.reasons
        )
        st.markdown(
            f"<div class='{cls}'>"
            f"<span class='fcv-mono' style='color:#38bdf8;font-weight:700'>"
            f"{gap.control_id}</span> &nbsp; {_pill(gap.status)} &nbsp;"
            f"<span style='color:#e2e8f0'>{gap.title}</span><br>"
            f"<span style='color:#94a3b8;font-size:0.8rem'>"
            f"{gap.failing_resources}/{gap.total_resources} resources failing · "
            f"rules: {', '.join(gap.rules)}</span>"
            f"<ul style='margin:0.4rem 0 0 1rem'>{reasons}</ul>"
            f"</div>",
            unsafe_allow_html=True,
        )

    # --- Detailed control table -------------------------------------------
    with st.expander("All assessed controls"):
        rows = [
            {
                "Control": c.control_id,
                "Title": c.title,
                "Family": c.family,
                "Status": _STATUS_LABEL[c.status],
                "Passing": c.passing_resources,
                "Failing": c.failing_resources,
                "Rules": ", ".join(c.rules),
            }
            for c in report.assessed_controls
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)

    # --- Downloads ---------------------------------------------------------
    st.subheader("Export")
    d1, d2 = st.columns(2)
    d1.download_button(
        "⬇ OSCAL 1.1.2 Assessment Results",
        data=json.dumps(to_oscal(report), indent=2),
        file_name="assessment-results.json",
        mime="application/json",
        use_container_width=True,
    )
    d2.download_button(
        "⬇ Gap analysis (JSON)",
        data=json.dumps(gap_summary(report), indent=2),
        file_name="gap-analysis.json",
        mime="application/json",
        use_container_width=True,
    )


if __name__ == "__main__":
    main()
