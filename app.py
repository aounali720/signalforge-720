"""Streamlit presentation for SignalForge 720. Run: streamlit run app.py"""
from __future__ import annotations
from datetime import datetime, timezone
from io import BytesIO
import json
import os
from pathlib import Path
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from signalforge import __version__
from signalforge.ai import ai_linkedin
from signalforge.covers import render_cover
from signalforge.database import STATUSES, init_db, list_threats, save_triage, upsert
from signalforge.demo import demo_records
from signalforge.image_ai import openai_concept_image
from signalforge.reports import digest, linkedin_template, pick, recent
from signalforge.sources import collect
from signalforge.exposure import parse_csv, save_assets, list_assets, find_matches, sample_assets
from signalforge.detection import hypotheses, playbook
from signalforge.evidence import case_id, evidence_packet, packet_markdown, packet_json
from signalforge.export import safe_csv

load_dotenv()
st.set_page_config(page_title="SignalForge 720 | Threat-to-Evidence Lab", page_icon="🔷", layout="wide")

st.markdown("""
<style>
.block-container {padding-top: 1.8rem; max-width: 1400px;}
[data-testid="stMetric"] {background: linear-gradient(135deg,#162b431b,#21385712); border: 1px solid #80b7e030; padding: 14px; border-radius: 10px;}
.hero-sub {color: #91a3b5; font-size: 1.02rem; margin-bottom: 1.2rem;}
.mini-label {text-transform: uppercase; letter-spacing: .23em; color: #49c5f0; font-weight: 750;}
.stTabs [data-baseweb="tab-list"]{gap:.6rem; flex-wrap:wrap}
.stTabs [data-baseweb="tab"]{background:#19334a12;border:1px solid #94bfe520;border-radius:8px 8px 0 0}
.sf720-brand {padding:16px 20px; border: 1px solid #459ee844; border-radius:12px; background:linear-gradient(115deg,#0522391b,#15474a13); margin-bottom:10px}
.sf720-code {color:#2fbde4; letter-spacing:.18em; font-size:.74rem}
</style>
""", unsafe_allow_html=True)
init_db()

st.markdown('<div class="sf720-brand"><div class="sf720-code">AOUNSEC // PROJECT 720 · BLUE-TEAM ENGINEERING</div><h1 style="margin:.4rem 0">SIGNALFORGE <span style="color:#24b9ed">720</span></h1><span style="opacity:.83">From threat signals to defensible evidence · Built for SOC + detection + GRC</span></div>', unsafe_allow_html=True)
st.caption("Independent portfolio lab by @aounali720 · No automated proof of compromise or compliance certification")

with st.sidebar:
    st.header("Data collection")
    st.caption("Live sync only runs on demand. No automatic scraping or posting.")
    period = st.slider("Look back for CISA KEV additions (days)", 7, 120, 45)
    use_kev = st.checkbox("CISA KEV", True)
    use_news = st.checkbox("Security news feeds", True)
    use_epss = st.checkbox("FIRST EPSS probability", True)
    if st.button("↻ Sync live sources", type="primary", use_container_width=True):
        with st.spinner("Retrieving public source metadata…"):
            records, errors = collect(days=period, use_kev=use_kev, use_rss=use_news, use_epss=use_epss)
            count = upsert(records)
        if count:
            st.success(f"Imported or refreshed {count} source records.")
        elif not errors:
            st.info("No records in the selected look-back window.")
        for error in errors:
            st.warning(error)
    if st.button("Load 720 signature lab", use_container_width=True):
        upsert(demo_records())
        save_assets(sample_assets())
        st.success("4 synthetic cases and 3 fictional lab assets added.")
    st.divider()
    st.caption("Version " + __version__ + " · API keys stay in your environment; do not commit .env")
    st.caption("Priority is a teaching heuristic, NOT CVSS, and does not establish impact on your assets.")

all_records = list_threats()
real_records = [r for r in all_records if not r.is_demo]
demo_count = sum(r.is_demo for r in all_records)
if demo_count:
    st.warning(f"Training mode: {demo_count} synthetic scenarios are stored. Filter them out before publishing a live briefing.", icon="⚠️")
if not all_records:
    st.info("No records yet. Choose **Sync live sources** or **Load 720 signature lab** on the left to begin.")

metrics = st.columns(5)
metrics[0].metric("Total records", len(all_records))
metrics[1].metric("CISA KEV", sum(r.kev and not r.is_demo for r in all_records))
metrics[2].metric("High priority", sum(r.priority == "High" and not r.is_demo for r in all_records))
metrics[3].metric("Under investigation", sum(r.status == "Investigating" for r in all_records))
metrics[4].metric("Training records", demo_count)

overview, queue, exposure, detection, binder, briefing, creator, methodology = st.tabs([
    "◈ Signal Board", "🔎 Analyst Queue", "🧬 Exposure Lab", "🎯 Detection Lab",
    "📁 Evidence Binder", "📋 Daily Brief", "✍️ Content Studio", "📖 Methodology"
])

with overview:
    st.subheader("Intelligence at a glance")
    if all_records:
        left, right = st.columns([1, 1])
        with left:
            st.markdown("**Priority distribution**")
            priorities = pd.Series([r.priority for r in all_records if not r.is_demo]).value_counts()
            st.bar_chart(priorities.reindex(["High", "Medium", "Low"], fill_value=0))
        with right:
            st.markdown("**Live records by publisher**")
            sources = pd.Series([r.source for r in all_records if not r.is_demo]).value_counts()
            if len(sources):
                st.bar_chart(sources)
            else:
                st.caption("Sync live sources to display publisher distribution.")
        st.subheader("Recent top-priority records")
        display = pick(real_records, 8)
        if display:
            st.dataframe(pd.DataFrame([{
                "Priority": r.priority, "Score": r.priority_score, "Title": r.title,
                "Source": r.source, "Published": r.published_at[:10], "Advisory": r.url
            } for r in display]), hide_index=True, use_container_width=True,
                column_config={"Advisory": st.column_config.LinkColumn("Source", display_text="Open source")})
        else:
            st.info("Live data not loaded; training records are not included in this overview.")

with queue:
    st.subheader("Triage workbench")
    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
    with col1:
        query = st.text_input("Search CVE / product / topic", placeholder="e.g. VPN, ransomware")
    with col2:
        filter_priority = st.selectbox("Priority", ["All", "High", "Medium", "Low"])
    with col3:
        filter_status = st.selectbox("Case status", ["All", *STATUSES])
    with col4:
        filter_data = st.selectbox("Dataset", ["Live", "All", "Demo"])
    selected_demo = False if filter_data == "Live" else True if filter_data == "Demo" else None
    visible = list_threats(search=query, priority=filter_priority, status=filter_status, demo=selected_demo)
    if visible:
        frame = pd.DataFrame([{
            "Priority": r.priority, "Score": r.priority_score,
            "Title": r.title, "CVE": r.cve or "—", "Publisher": r.source,
            "Published": r.published_at[:10], "Status": r.status, "Evidence": r.url
        } for r in visible])
        st.dataframe(frame, hide_index=True, use_container_width=True,
                     column_config={"Evidence": st.column_config.LinkColumn("Evidence", display_text="View")})
        options = {f"{r.title[:90]} · {r.source} · {r.key[-8:]}": r for r in visible}
        selection = st.selectbox("Open a record", list(options))
        record = options[selection]
        if record.is_demo:
            st.error("SYNTHETIC TRAINING SCENARIO — not an actual incident or advisory")
        detail, action = st.columns([1.7, 1])
        with detail:
            st.subheader(record.title)
            st.caption(f"Case ID: {case_id(record)}")
            st.write(record.summary or "No excerpt provided by publisher.")
            st.markdown(f"**Source:** [{record.source}]({record.url})")
            st.markdown(f"**Published:** `{record.published_at}` · **CVE:** `{record.cve or 'not provided'}`")
            st.markdown(f"**CISA KEV:** `{'Simulated for training' if record.is_demo and record.kev else record.kev}` · **EPSS:** `{f'{record.epss:.4f}' if record.epss is not None else 'not available'}`")
            st.markdown(f"**Heuristic priority:** **{record.priority}** ({record.priority_score}/100)")
            st.caption("Evidence for priority: " + record.rationale)
        with action:
            st.markdown("#### Investigation journal")
            with st.form("triage_" + record.key):
                status = st.selectbox("Case state", STATUSES, index=STATUSES.index(record.status))
                notes = st.text_area("Analyst observations / next steps", value=record.analyst_notes, height=150, max_chars=5000)
                if st.form_submit_button("Save triage decision", type="primary"):
                    if save_triage(record.key, status, notes):
                        st.success("Saved locally. Refresh filters to view the updated queue.")
                    else:
                        st.error("Record is no longer available")
    else:
        st.info("No matching records.")


with exposure:
    st.subheader("Asset × advisory intersection")
    st.caption("Unique 720 workflow: link operator-declared CVEs to lab asset inventory. Matching an ID NEVER establishes actual vulnerability or exploitation.")
    st.warning("Do not upload confidential production inventories here or commit generated SQLite data to GitHub. Use fictional lab identifiers for public demos.")
    asset_list = list_assets()
    x, y = st.columns([1.2, 1])
    with x:
        upload = st.file_uploader("Load lab asset declarations (.csv)", type=["csv"], help="Maximum 500 assets and 1 MB. Asset IDs overwrite matching existing rows.")
        mark_demo = st.checkbox("Inventory contains fictional lab assets", value=True)
        if upload is not None and st.button("Import CSV asset declarations"):
            try:
                parsed = parse_csv(upload.getvalue().decode("utf-8-sig"), demo=mark_demo)
                count_assets = save_assets(parsed)
                st.success(f"Imported {count_assets} asset declarations. Reload the page to inspect.")
            except (ValueError, UnicodeDecodeError) as exc:
                st.error(str(exc))
    with y:
        st.markdown("**CSV columns**")
        st.code("asset_id,product,environment,internet_exposed,criticality,known_cves,owner", language="text")
        st.caption("Multiple operator-declared CVEs are separated by semicolons; sample asset file is in assets/example-inventory.csv")
    if asset_list:
        st.dataframe(pd.DataFrame([{
            "Asset": a.asset_id, "Product": a.product, "Environment": a.environment,
            "Internet exposure declared": a.internet_exposed, "Criticality": a.criticality,
            "Declared CVEs": a.known_cves or "—", "Training fixture": a.is_demo
        } for a in asset_list]), hide_index=True, use_container_width=True)
        matches = find_matches(all_records, asset_list)
        if matches:
            st.markdown("**Investigations requiring verification**")
            st.dataframe(pd.DataFrame([{k: v for k,v in m.items() if k not in ("source", "warning")}
                                      for m in matches]), hide_index=True, use_container_width=True)
            st.caption("The 0–100 review score is a teaching heuristic based on advisory priority, declared internet exposure and declared criticality; it is NOT a CVSS or risk rating.")
        else:
            st.info("No exact declared CVE intersections. This is not proof that any asset is safe.")
    else:
        st.info("Load the 720 signature lab or import your own lab asset CSV to explore intersections.")

with detection:
    st.subheader("Hypothesis-driven detection design")
    st.caption("Practice connecting a headline to telemetry and a reproducible benign lab validation. Mapping to ATT&CK does not prove observed adversary activity.")
    if all_records:
        by_key = {r.key: r for r in all_records}
        selection_key = st.selectbox("Select a case for a detection workbook", list(by_key),
                                    format_func=lambda k: f"{case_id(by_key[k])} · {by_key[k].title[:90]}", key="det_case")
        selected = by_key[selection_key]
        if selected.is_demo:
            st.warning("SYNTHETIC SCENARIO — training only")
        detected = hypotheses(selected)
        if detected:
            for hyp in detected:
                with st.expander(hyp.technique, expanded=True):
                    st.write(f"**Tactic:** {hyp.tactic}")
                    st.write(f"**Candidate telemetry:** {hyp.telemetry}")
                    st.write(f"**Analyst question:** {hyp.analyst_question}")
                    st.write(f"**Safe exercise:** {hyp.lab_exercise}")
        else:
            st.info("No automatic hypothesis. Read the primary source and develop a manual data-source hypothesis.")
        workbook = playbook(selected)
        st.download_button("Download detection worksheet", workbook,
                           file_name=f"{case_id(selected)}_detection_workbook.md", mime="text/markdown")
    else:
        st.info("Load the 720 signature lab or sync live advisories first.")

with binder:
    st.subheader("Evidence and control binder")
    st.caption("Create an attributable case file linking triage, operator-declared assets, detection hypotheses, and suggested ISO/NIST review evidence.")
    if all_records:
        available = {r.key: r for r in all_records}
        sel_key = st.selectbox("Select investigation", list(available),
                               format_func=lambda k: f"{case_id(available[k])} · {available[k].title[:90]}", key="evidence_case")
        chosen_case = available[sel_key]
        packet = evidence_packet(chosen_case, list_assets())
        document = packet_markdown(packet)
        st.markdown(document)
        left, right = st.columns(2)
        with left:
            st.download_button("Export Markdown for analyst review", document,
                               file_name=f"{case_id(chosen_case)}_evidence.md", mime="text/markdown", use_container_width=True)
        with right:
            st.download_button("Export JSON + SHA-256 digest", packet_json(packet),
                               file_name=f"{case_id(chosen_case)}_evidence.json", mime="application/json", use_container_width=True)
        st.caption("SHA-256 supports local integrity comparison only; this is not a digital signature, proof of review, or a formal compliance assessment.")
    else:
        st.info("Load synthetic cases or sync public sources first.")

with briefing:
    st.subheader("Source-linked daily intelligence brief")
    st.caption("Source excerpts only. Publish after verifying each original advisory and affected assets.")
    include_demo = st.checkbox("Include training scenarios in the brief (clearly labeled)", False, key="brief_demo")
    candidates = all_records if include_demo else real_records
    brief_window = st.select_slider("Published within last", options=[1, 3, 7, 14, 30], value=3, format_func=lambda x: f"{x} days")
    candidates = recent(candidates, brief_window)
    count = st.slider("Maximum records", 1, 15, 7)
    brief = digest(candidates, count)
    st.markdown(brief)
    st.download_button("Download Markdown brief", brief, file_name="signalforge_daily_brief.md", mime="text/markdown", use_container_width=True)
    if candidates:
        export = safe_csv([r.to_dict() for r in pick(candidates, count)])
        st.download_button("Export selected records as CSV", export, file_name="signalforge_triage.csv", mime="text/csv", use_container_width=True)

with creator:
    st.subheader("Publishable analysis · review required")
    st.caption("Generate content grounded in selected source records, with links appended automatically. No auto-publishing.")
    include_demo_post = st.checkbox("Show synthetic scenarios in Content Studio", False)
    candidates = all_records if include_demo_post else real_records
    if candidates:
        index_by_key = {r.key: r for r in candidates}
        selected_keys = st.multiselect("Select 1–5 source records", options=list(index_by_key),
             default=[r.key for r in pick(candidates, 3)],
             format_func=lambda key: f"{index_by_key[key].title[:90]} — {index_by_key[key].source}", max_selections=5)
        chosen = [index_by_key[k] for k in selected_keys]
        provider = st.selectbox("Writing engine", ["Offline template (free)", "OpenAI", "Claude"])
        if st.button("Generate source-grounded LinkedIn draft", disabled=not chosen, type="primary"):
            try:
                post = linkedin_template(chosen) if provider.startswith("Offline") else ai_linkedin(chosen, provider)
                st.session_state["tp_post"] = post
            except Exception as exc:
                st.error(f"Generation failed: {type(exc).__name__}: {exc}")
        if "tp_post" in st.session_state:
            st.text_area("Review and edit before publishing", key="tp_post", height=330)
            st.download_button("Download LinkedIn post", st.session_state["tp_post"], file_name="linkedin_draft.txt", mime="text/plain")
        st.divider()
        st.markdown("#### LinkedIn graphic (1200 × 627)")
        default_title = chosen[0].title if chosen else "Threat Intelligence Daily Brief"
        headline = st.text_input("Card headline", value=default_title[:100])
        label = st.selectbox("Graphic style", ["Signal trace", "Grid pulse", "Orbit rings"])
        st.caption("Visual motifs are deterministically varied using a fingerprint of each headline and the 720 studio mark.")
        if st.button("Make clean editorial card"):
            st.session_state["tp_graphic"] = render_cover(headline, label=label, demo=any(r.is_demo for r in chosen))
            st.session_state["tp_graphic_label"] = "Original editorial design (not an AI photograph)"
        if st.button("Generate optional OpenAI concept artwork (paid API)"):
            try:
                st.session_state["tp_graphic"] = openai_concept_image(headline)
                st.session_state["tp_graphic_label"] = "AI-generated concept artwork — not documentary evidence"
            except Exception as exc:
                st.error(f"Image generation failed: {type(exc).__name__}: {exc}")
        if "tp_graphic" in st.session_state:
            st.image(st.session_state["tp_graphic"], caption=st.session_state.get("tp_graphic_label", ""), use_container_width=True)
            st.download_button("Download PNG artwork", st.session_state["tp_graphic"], file_name="signalforge_post_art.png", mime="image/png")
    else:
        st.info("Sync live sources first, or explicitly enable synthetic training records.")

with methodology:
    st.subheader("What this system does—and does not—claim")
    st.markdown("""
**Pipeline:** CISA KEV + RSS → FIRST EPSS → transparent queue → declared asset/CVE intersection → ATT&CK-inspired hypothesis worksheet → SHA-256 case evidence packet → reviewable posts.

- **CISA KEV** means exploitation has been observed in the wild; it does **not** prove your organization was affected.
- **EPSS** estimates probability of exploitation activity in the next 30 days. It is **not** a CVSS severity rating.
- **RSS articles** are publisher summaries, not independently verified incident evidence. A mentioned CVE is not proof of exploitation.
- **Priority score (0–100)** is a teaching heuristic: KEV +70, CISA-known ransomware +12, EPSS up to +18, or metadata keyword matching. It is not a production risk rating.
- **Human-in-the-loop:** Analysts confirm vendor advisories, asset exposure, remediation, timestamps, and third-party content rights before posting.
- **Exposure lab:** matches explicitly declared CVEs only. It does not scan assets or validate vulnerable versions. Asset data is local and must not be committed to public GitHub.
- **Detection lab:** keyword mappings are speculative hypotheses, not observed ATT&CK techniques, real alerts, or validated rules.
- **Evidence binder:** control suggestions are not certification; SHA-256 is a consistency check, not a digital signature.
- **Source safety:** no web-page scripts are executed, full news articles are not scraped, secrets are kept out of the database, and all AI content must be checked.
- **Data freshness:** refresh manually. Items persist so analyst notes survive another sync.

**Portfolio talking points:** API ingestion, parsing and normalization, evidence provenance, analytic heuristics, data persistence, error handling, threat triage, human review, safe LLM integration and testing.
""")
    st.caption("Developed as a demonstrable SOC/GRC learning platform; not a commercial threat intelligence service.")
