import json
import os
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

from normalizer.engine import NormalizationEngine
from analyzer.engine import AnalyzerEngine
from ai.bob_client import BobClient, BobAPIError
from ai.fraud_ai import FraudAIAnalyzer, FRAUD_TYPES
from utils.ids import safe_case_id


# ============================================================
# CONFIG
# ============================================================

st.set_page_config(
    page_title="FraudGraph",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="collapsed",
)

BASE_DIR = Path(__file__).resolve().parent
CASES_DIR = BASE_DIR / "data" / "cases"
CASES_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# SIMPLE STYLE
# ============================================================

st.markdown(
    """
    <style>
    .block-container { max-width: 1250px; padding-top: 2rem; }
    .step { color: #6b7280; font-size: 0.85rem; margin-bottom: 0.25rem; }
    .hint { color: #6b7280; font-size: 0.9rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SESSION STATE
# ============================================================

DEFAULTS = {
    "page": "case",
    "case_id": "",
    "case_title": "",
    "case_meta": {},
    "result": None,
    "analysis": None,
    "ai_analysis": None,
    "raw_files": [],
    "normalized_json": None,
}

for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


def reset_app():
    for key, value in DEFAULTS.items():
        st.session_state[key] = value


def go(page: str):
    st.session_state.page = page
    st.rerun()


def write_case_file(case_id: str, result: dict):
    case_dir = CASES_DIR / case_id
    original_dir = case_dir / "original"
    normalized_dir = case_dir / "normalized"
    original_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir.mkdir(parents=True, exist_ok=True)

    for uploaded_file in st.session_state.raw_files:
        target = original_dir / Path(uploaded_file.name).name
        target.write_bytes(uploaded_file.getvalue())

    output_file = normalized_dir / "case.json"
    output_file.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_file


def build_phase2_export(analysis: dict):
    entity_edges = analysis.get("network", {}).get("entity_network", {}).get("edges", [])
    return {
        "analysis": analysis.get("analysis", {}),
        "subject_profiles": analysis.get("subject_profiles", []),
        "entity_relationships": entity_edges,
        "findings": analysis.get("findings", []),
        "data_quality": analysis.get("data_quality", {}),
    }


def write_analysis_file(case_id: str, analysis: dict):
    analysis_dir = CASES_DIR / case_id / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    output_file = analysis_dir / "case_analysis.json"
    output_file.write_text(
        json.dumps(build_phase2_export(analysis), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_file


def _event_search_blob(event: dict) -> str:
    try:
        return json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return str(event)


def build_visualizer_payload(analysis: dict):
    """Build an interactive index over the completed analyzer output."""
    profiles = analysis.get("subject_profiles", [])
    edges = analysis.get("entity_relationships")
    if edges is None:
        edges = analysis.get("network", {}).get("entity_network", {}).get("edges", [])

    profile_by_id = {p.get("subject_id"): p for p in profiles if p.get("subject_id")}
    name_by_subject = {p.get("subject_id"): (p.get("name") or p.get("subject_id")) for p in profiles if p.get("subject_id")}

    event_by_id = {}
    event_evidence = {}
    all_events = []
    for profile in profiles:
        for event in profile.get("timeline", []):
            event_id = event.get("event_id") or event.get("details", {}).get("call_id") or event.get("details", {}).get("transaction_id")
            if not event_id:
                event_id = f"{profile.get('subject_id','unknown')}::{event.get('timestamp','')}::{event.get('type','')}"
            if event_id not in event_by_id:
                clean = dict(event)
                clean["_subject_id"] = profile.get("subject_id")
                clean["_subject_name"] = profile.get("name") or profile.get("subject_id")
                event_by_id[event_id] = clean
                all_events.append(clean)
            for eid in event.get("evidence_ids", []) or event.get("details", {}).get("source_evidence_ids", []):
                event_evidence.setdefault(eid, set()).add(event_id)

    nodes = {}
    type_order = ["PERSON", "ACCOUNT", "PHONE", "DEVICE", "SIM", "IMEI", "IP"]

    def add_node(node_id, node_type):
        if not node_id:
            return
        key = f"{node_type}:{node_id}"
        if key in nodes:
            return
        label = name_by_subject.get(node_id, node_id) if node_type == "PERSON" else node_id
        nodes[key] = {
            "id": key, "entity_id": node_id, "type": node_type, "label": label,
            "display": f"{label} · {node_id}" if label != node_id else node_id,
        }

    for profile in profiles:
        add_node(profile.get("subject_id"), "PERSON")

    normalized_edges = []
    for idx, edge in enumerate(edges):
        source, target = edge.get("source", ""), edge.get("target", "")
        source_type, target_type = edge.get("source_type", "UNKNOWN"), edge.get("target_type", "UNKNOWN")
        if not source or not target:
            continue
        add_node(source, source_type)
        add_node(target, target_type)
        normalized_edges.append({
            "id": f"E{idx+1}", "source": f"{source_type}:{source}", "target": f"{target_type}:{target}",
            "source_entity": source, "target_entity": target, "source_type": source_type, "target_type": target_type,
            "relationship": edge.get("relationship_type", "RELATED"), "event_count": edge.get("event_count", 0),
            "evidence_ids": edge.get("evidence_ids", []) or [],
        })

    def events_for_evidence(evidence_ids):
        ids = set()
        for evidence_id in evidence_ids:
            ids.update(event_evidence.get(evidence_id, set()))
        return sorted((event_by_id[eid] for eid in ids if eid in event_by_id), key=lambda x: x.get("timestamp", ""), reverse=True)

    node_events = {}
    for key, node in nodes.items():
        entity_id, node_type = node["entity_id"], node["type"]
        if node_type == "PERSON":
            profile = profile_by_id.get(entity_id, {})
            events = []
            seen = set()
            for event in profile.get("timeline", []):
                eid = event.get("event_id")
                if eid in seen:
                    continue
                clean = dict(event)
                clean["_subject_id"] = profile.get("subject_id")
                clean["_subject_name"] = profile.get("name") or profile.get("subject_id")
                events.append(clean)
                seen.add(eid)
            node_events[key] = sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)
        else:
            matches, seen, token = [], set(), str(entity_id)
            for event in all_events:
                eid = event.get("event_id")
                if eid in seen:
                    continue
                if token and token in _event_search_blob(event):
                    matches.append(event)
                    seen.add(eid)
            node_events[key] = sorted(matches, key=lambda x: x.get("timestamp", ""), reverse=True)

    edge_details = {}
    for edge in normalized_edges:
        evs = events_for_evidence(edge["evidence_ids"])
        edge_details[edge["id"]] = {
            "calls": [e for e in evs if str(e.get("type", "")).upper() == "CALL"],
            "transactions": [e for e in evs if str(e.get("type", "")).upper() in {"TRANSACTION", "TRANSFER"}],
            "other": [e for e in evs if str(e.get("type", "")).upper() not in {"CALL", "TRANSACTION", "TRANSFER"}],
        }

    counts = {
        "nodes": len(nodes), "edges": len(normalized_edges),
        "calls": sum(1 for e in all_events if str(e.get("type", "")).upper() == "CALL"),
        "transactions": sum(1 for e in all_events if str(e.get("type", "")).upper() in {"TRANSACTION", "TRANSFER"}),
    }
    return {
        "nodes": list(nodes.values()), "edges": normalized_edges, "node_events": node_events, "edge_details": edge_details,
        "counts": counts, "relationship_types": sorted({e["relationship"] for e in normalized_edges}),
        "entity_types": sorted({n["type"] for n in nodes.values()}, key=lambda x: (type_order.index(x) if x in type_order else 99, x)),
    }


def render_investigation_visualizer(analysis: dict):
    payload = build_visualizer_payload(analysis)
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    html = r"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
:root{--ink:#111827;--muted:#64748b;--line:#e2e8f0;--soft:#f8fafc;--blue:#2563eb}
*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.app{border:1px solid var(--line);border-radius:18px;overflow:hidden;background:#fff;box-shadow:0 10px 35px rgba(15,23,42,.06)}
.top{padding:18px 20px 14px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap}.title{font-size:19px;font-weight:760;letter-spacing:-.02em}.subtitle{font-size:12px;color:var(--muted);margin-top:4px}.metrics{display:flex;gap:8px;flex-wrap:wrap}.metric{padding:8px 11px;border:1px solid var(--line);border-radius:10px;background:#fff;min-width:82px}.metric b{display:block;font-size:15px}.metric span{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.controls{padding:12px 14px;border-bottom:1px solid var(--line);display:grid;grid-template-columns:minmax(180px,1.4fr) repeat(3,minmax(120px,1fr)) auto;gap:8px;background:#fff}.control{height:38px;border:1px solid #dbe3ee;border-radius:9px;padding:0 10px;background:#fff;color:var(--ink);font-size:12px;outline:none}.control:focus{border-color:#93c5fd;box-shadow:0 0 0 3px #dbeafe}.btn{height:38px;border:1px solid #dbe3ee;border-radius:9px;padding:0 12px;background:#fff;color:var(--ink);font-weight:650;font-size:12px;cursor:pointer}.btn:hover{background:#f8fafc}
.layout{display:grid;grid-template-columns:minmax(0,1fr) 390px;min-height:700px}.graph{position:relative;min-width:0;border-right:1px solid var(--line);background:radial-gradient(circle at 50% 45%,#fff 0,#fbfdff 62%,#f8fafc 100%)}#network{width:100%;height:700px}.legend{position:absolute;left:14px;bottom:14px;background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:12px;padding:10px 12px;display:flex;gap:9px;flex-wrap:wrap;max-width:92%;font-size:10px}.dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:5px;vertical-align:-1px;border:1px solid rgba(0,0,0,.1)}
.panel{background:#fff;display:flex;flex-direction:column;min-width:0}.panel-head{padding:16px;border-bottom:1px solid var(--line)}.eyebrow{font-size:10px;font-weight:750;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}.entity-title{font-size:18px;font-weight:760;margin-top:5px;word-break:break-word}.entity-id{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);margin-top:3px;word-break:break-all}.pillrow{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}.pill{font-size:10px;padding:4px 7px;border-radius:999px;background:#f1f5f9;color:#475569;border:1px solid #e2e8f0}.panel-body{padding:14px;overflow:auto;max-height:630px}.empty{padding:28px 16px;color:var(--muted);font-size:12px;text-align:center;border:1px dashed #dbe3ee;border-radius:12px;background:#fbfdff}.section{margin-top:16px}.section:first-child{margin-top:0}.section-title{font-size:12px;font-weight:760;margin-bottom:8px;display:flex;justify-content:space-between;gap:8px}.timeline{display:flex;flex-direction:column;gap:8px}.event{border:1px solid var(--line);border-radius:11px;padding:10px;background:#fff}.event-top{display:flex;justify-content:space-between;gap:8px;align-items:flex-start}.event-type{font-size:10px;font-weight:800;letter-spacing:.07em;text-transform:uppercase}.event-time{font-size:10px;color:var(--muted);white-space:nowrap}.event-main{font-size:11px;margin-top:5px;line-height:1.45}.event-meta{display:flex;gap:5px;flex-wrap:wrap;margin-top:7px}.kv{font-size:9px;color:#475569;background:#f8fafc;border:1px solid #e5e7eb;border-radius:6px;padding:3px 5px}.tabs{display:flex;gap:5px;margin-bottom:10px}.tab{border:1px solid var(--line);background:#fff;border-radius:8px;padding:6px 9px;font-size:10px;font-weight:700;cursor:pointer}.tab.active{background:#eff6ff;border-color:#bfdbfe;color:#1d4ed8}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px}.mini-table{width:100%;border-collapse:collapse;font-size:10px}.mini-table th,.mini-table td{padding:7px 8px;text-align:left;border-bottom:1px solid #eef2f7;vertical-align:top}.mini-table th{background:#f8fafc;color:#64748b;font-weight:750;position:sticky;top:0}.mini-table tr:last-child td{border-bottom:0}.amount{font-weight:760}.evidence{font:9px ui-monospace,SFMono-Regular,Menlo,monospace;color:#64748b;word-break:break-all}.notice{font-size:10px;color:#64748b;background:#f8fafc;border:1px solid #e2e8f0;padding:8px;border-radius:9px;line-height:1.45}
@media(max-width:900px){.controls{grid-template-columns:1fr 1fr}.layout{grid-template-columns:1fr}.graph{border-right:0;border-bottom:1px solid var(--line)}#network{height:560px}.panel-body{max-height:none}.panel{min-height:520px}}@media(max-width:560px){.controls{grid-template-columns:1fr}.metric{min-width:72px}.top{padding:14px}.layout{min-height:0}}
</style></head><body>
<div class="app" id="root"><div class="top"><div><div class="title">Final Evidence Graph</div><div class="subtitle">Undirected entity relationships · click an edge for linked calls/transactions · click an entity for its exact evidence timeline</div></div><div class="metrics" id="metrics"></div></div>
<div class="controls"><input id="search" class="control" type="search" placeholder="Search entity, name, phone, account, device…" aria-label="Search entity"><select id="typeFilter" class="control" aria-label="Entity type"><option value="ALL">All entity types</option></select><select id="relFilter" class="control" aria-label="Relationship type"><option value="ALL">All relationships</option></select><select id="eventFilter" class="control" aria-label="Evidence event type"><option value="ALL">All evidence</option><option value="CALL">Calls</option><option value="TRANSACTION">Transactions</option></select><button id="reset" class="btn" type="button">Reset view</button></div>
<div class="layout"><section class="graph" aria-label="Entity relationship graph"><div id="network"></div><div class="legend" id="legend"></div></section><aside class="panel" aria-live="polite"><div class="panel-head" id="panelHead"><div class="eyebrow">Investigation graph</div><div class="entity-title">Select an entity or relationship</div><div class="entity-id">The source analysis remains authoritative.</div></div><div class="panel-body" id="panelBody"><div class="empty">Click a node to inspect its timeline. Click an edge to inspect the calls and transactions that generated that relationship.</div></div></aside></div></div>
<script>(function(){'use strict';const DATA=__PAYLOAD__;const COLORS={PERSON:'#2563eb',ACCOUNT:'#7c3aed',PHONE:'#0891b2',DEVICE:'#ea580c',SIM:'#16a34a',IMEI:'#64748b',IP:'#475569',UNKNOWN:'#94a3b8'};const search=document.getElementById('search'),typeFilter=document.getElementById('typeFilter'),relFilter=document.getElementById('relFilter'),eventFilter=document.getElementById('eventFilter'),reset=document.getElementById('reset'),panelHead=document.getElementById('panelHead'),panelBody=document.getElementById('panelBody'),legend=document.getElementById('legend'),metrics=document.getElementById('metrics');let network=null,selectedNode=null,selectedEdge=null,edgeTab='CALL';function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}function fmtDate(v){if(!v)return'Unknown time';const d=new Date(v);return Number.isNaN(d.getTime())?String(v):d.toLocaleString(undefined,{year:'numeric',month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'});}function short(v,n=90){const s=String(v??'');return s.length>n?s.slice(0,n-1)+'…':s;}function typeColor(t){return COLORS[t]||COLORS.UNKNOWN;}function eventKind(e){const t=String(e?.type||'').toUpperCase();if(t==='CALL')return'CALL';if(t==='TRANSACTION'||t==='TRANSFER')return'TRANSACTION';return'OTHER';}function details(e){return e?.details||{};}function metricsRender(){metrics.innerHTML='';[['Nodes',DATA.counts.nodes],['Edges',DATA.counts.edges],['Calls',DATA.counts.calls],['Transactions',DATA.counts.transactions]].forEach(([a,b])=>{const d=document.createElement('div');d.className='metric';d.innerHTML='<b>'+esc(b)+'</b><span>'+esc(a)+'</span>';metrics.appendChild(d);});}function filtersInit(){DATA.entity_types.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;typeFilter.appendChild(o)});DATA.relationship_types.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;relFilter.appendChild(o)});legend.innerHTML=DATA.entity_types.map(t=>'<span><i class="dot" style="background:'+typeColor(t)+'"></i>'+esc(t)+'</span>').join('');}function matchesEdge(e){if(relFilter.value!=='ALL'&&e.relationship!==relFilter.value)return false;const ef=eventFilter.value;if(ef==='ALL')return true;const d=DATA.edge_details[e.id]||{};return(ef==='CALL'&&d.calls?.length)||(ef==='TRANSACTION'&&d.transactions?.length);}function matchesNode(n){if(typeFilter.value!=='ALL'&&n.type!==typeFilter.value)return false;const q=search.value.trim().toLowerCase();if(!q)return true;return[n.entity_id,n.label,n.display,n.type].some(v=>String(v||'').toLowerCase().includes(q));}function buildGraph(){if(!window.vis){document.getElementById('network').innerHTML='<div class="empty" style="margin:20px">Graph engine could not load. The analysis data is still available in the tables above.</div>';return;}const visibleNodes=DATA.nodes.filter(matchesNode),allowed=new Set(visibleNodes.map(n=>n.id)),visibleEdges=DATA.edges.filter(e=>allowed.has(e.source)&&allowed.has(e.target)&&matchesEdge(e));const ns=visibleNodes.map(n=>({id:n.id,label:short(n.label,22),title:n.display,color:{background:typeColor(n.type),border:'#fff',highlight:{background:'#111827',border:'#111827'},hover:{background:typeColor(n.type),border:'#111827'}},font:{color:'#0f172a',size:n.type==='PERSON'?13:10,face:'Inter, Arial',strokeWidth:3,strokeColor:'#fff'},shape:'dot',size:n.type==='PERSON'?20:13,borderWidth:2}));const es=visibleEdges.map(e=>({id:e.id,from:e.source,to:e.target,label:e.event_count?String(e.event_count):'',title:e.relationship+' · '+e.event_count+' event(s)',width:Math.min(1.5+Math.log2((e.event_count||1)+1),6),color:{color:'#cbd5e1',highlight:'#2563eb',hover:'#94a3b8'},font:{size:9,color:'#64748b',strokeWidth:3,strokeColor:'#fff',align:'middle'},smooth:{type:'dynamic'}}));if(network)network.destroy();network=new vis.Network(document.getElementById('network'),{nodes:new vis.DataSet(ns),edges:new vis.DataSet(es)},{physics:{enabled:true,solver:'forceAtlas2Based',forceAtlas2Based:{gravitationalConstant:-48,centralGravity:.008,springLength:120,springConstant:.035,damping:.72,avoidOverlap:1.1},stabilization:{iterations:450,fit:true}},interaction:{hover:true,navigationButtons:true,keyboard:{enabled:true},multiselect:false,hideEdgesOnDrag:false,zoomView:true}});network.on('click',params=>{if(params.nodes?.length){selectedNode=params.nodes[0];selectedEdge=null;renderNode(selectedNode);network.selectNodes([selectedNode]);}else if(params.edges?.length){selectedEdge=params.edges[0];selectedNode=null;renderEdge(selectedEdge);network.selectEdges([selectedEdge]);}else clearSelection();});network.on('doubleClick',params=>{if(params.nodes?.length)network.focus(params.nodes[0],{scale:1.35,animation:{duration:450,easingFunction:'easeInOutQuad'}});});}function clearSelection(){selectedNode=null;selectedEdge=null;panelHead.innerHTML='<div class="eyebrow">Investigation graph</div><div class="entity-title">Select an entity or relationship</div><div class="entity-id">The source analysis remains authoritative.</div>';panelBody.innerHTML='<div class="empty">Click a node to inspect its timeline. Click an edge to inspect the calls and transactions that generated that relationship.</div>';if(network)network.unselectAll();}function eventCard(e){const d=details(e),k=eventKind(e);let main='';if(k==='CALL')main=(d.caller_phone_id||'')+' → '+(d.receiver_phone_id||'')+(d.duration_seconds?' · '+d.duration_seconds+' sec':'');else if(k==='TRANSACTION')main=(d.sender_account_id||'')+' → '+(d.receiver_account_id||'')+(d.amount!=null?' · ₹'+Number(d.amount).toLocaleString('en-IN'):'');else main=short(JSON.stringify(d),160);const evids=(e.evidence_ids||d.source_evidence_ids||[]).join(', ');return'<div class="event"><div class="event-top"><span class="event-type">'+esc(k==='OTHER'?e.type:k)+'</span><span class="event-time">'+esc(fmtDate(e.timestamp))+'</span></div><div class="event-main">'+esc(main)+'</div><div class="event-meta"><span class="kv">ID: '+esc(e.event_id||'—')+'</span>'+((e.direction)?'<span class="kv">'+esc(e.direction)+'</span>':'')+(evids?'<span class="evidence">'+esc(evids)+'</span>':'')+'</div></div>';}function renderNode(id){const n=DATA.nodes.find(x=>x.id===id);if(!n)return;const events=DATA.node_events[id]||[],calls=events.filter(e=>eventKind(e)==='CALL').length,tx=events.filter(e=>eventKind(e)==='TRANSACTION').length;panelHead.innerHTML='<div class="eyebrow">Entity · '+esc(n.type)+'</div><div class="entity-title">'+esc(n.label)+'</div><div class="entity-id">'+esc(n.entity_id)+'</div><div class="pillrow"><span class="pill">'+events.length+' timeline events</span><span class="pill">'+calls+' calls</span><span class="pill">'+tx+' transactions</span></div>';let body='<div class="section"><div class="section-title"><span>Exact timeline</span><span style="color:#64748b;font-weight:600">newest → oldest</span></div>';body+=events.length?'<div class="timeline">'+events.map(eventCard).join('')+'</div>':'<div class="empty">No timeline event in the analyzer output contains this entity.</div>';panelBody.innerHTML=body+'</div>';}function eventRows(events,kind){return events.filter(e=>eventKind(e)===kind).map(e=>{const d=details(e);if(kind==='CALL')return'<tr><td>'+esc(fmtDate(e.timestamp))+'</td><td>'+esc(d.caller_phone_id||'—')+'</td><td>'+esc(d.receiver_phone_id||'—')+'</td><td>'+esc(d.duration_seconds||'—')+'s</td><td class="evidence">'+esc((e.evidence_ids||[]).join(', '))+'</td></tr>';return'<tr><td>'+esc(fmtDate(e.timestamp))+'</td><td>'+esc(d.sender_account_id||'—')+'</td><td>'+esc(d.receiver_account_id||'—')+'</td><td class="amount">'+(d.amount!=null?'₹'+Number(d.amount).toLocaleString('en-IN'):'—')+'</td><td>'+esc(d.status||'—')+'</td><td class="evidence">'+esc((e.evidence_ids||[]).join(', '))+'</td></tr>';}).join('');}function renderEdge(id){const e=DATA.edges.find(x=>x.id===id),d=DATA.edge_details[id]||{calls:[],transactions:[],other:[]};if(!e)return;const a=DATA.nodes.find(n=>n.id===e.source),b=DATA.nodes.find(n=>n.id===e.target);panelHead.innerHTML='<div class="eyebrow">Relationship · undirected</div><div class="entity-title">'+esc(e.relationship)+'</div><div class="entity-id">'+esc(a?.display||e.source)+' ↔ '+esc(b?.display||e.target)+'</div><div class="pillrow"><span class="pill">'+esc(e.event_count)+' linked events</span><span class="pill">'+esc(e.evidence_ids.length)+' evidence IDs</span></div>';let body='<div class="notice">This edge is rendered as undirected for investigation navigation. The underlying event direction, when present, is preserved inside each log.</div><div class="section"><div class="tabs"><button class="tab '+(edgeTab==='CALL'?'active':'')+'" data-tab="CALL" type="button">Call logs ('+d.calls.length+')</button><button class="tab '+(edgeTab==='TRANSACTION'?'active':'')+'" data-tab="TRANSACTION" type="button">Transactions ('+d.transactions.length+')</button></div>';body+=edgeTab==='CALL'?'<div class="table-wrap"><table class="mini-table"><thead><tr><th>Time</th><th>Caller</th><th>Receiver</th><th>Duration</th><th>Evidence</th></tr></thead><tbody>'+eventRows(d.calls,'CALL')+'</tbody></table></div>':'<div class="table-wrap"><table class="mini-table"><thead><tr><th>Time</th><th>Sender</th><th>Receiver</th><th>Amount</th><th>Status</th><th>Evidence</th></tr></thead><tbody>'+eventRows(d.transactions,'TRANSACTION')+'</tbody></table></div>';if((!d.calls.length&&edgeTab==='CALL')||(!d.transactions.length&&edgeTab==='TRANSACTION'))body+='<div class="empty" style="margin-top:8px">No '+(edgeTab==='CALL'?'call':'transaction')+' event is linked to this relationship by evidence ID.</div>';body+='</div>';if(d.other.length)body+='<div class="section"><div class="section-title">Other linked evidence</div><div class="timeline">'+d.other.map(eventCard).join('')+'</div></div>';panelBody.innerHTML=body;panelBody.querySelectorAll('[data-tab]').forEach(btn=>btn.addEventListener('click',()=>{edgeTab=btn.dataset.tab;renderEdge(id);}));}function apply(){buildGraph();if(selectedNode)renderNode(selectedNode);if(selectedEdge)renderEdge(selectedEdge);}search.addEventListener('input',apply);typeFilter.addEventListener('change',apply);relFilter.addEventListener('change',apply);eventFilter.addEventListener('change',apply);reset.addEventListener('click',()=>{search.value='';typeFilter.value='ALL';relFilter.value='ALL';eventFilter.value='ALL';clearSelection();buildGraph();});metricsRender();filtersInit();buildGraph();})();</script></body></html>"""
    components.html(html.replace("__PAYLOAD__", payload_json), height=780, scrolling=False)


def event_to_row(event: dict):
    details = event.get("details") or {}
    return {
        "timestamp": event.get("timestamp", ""),
        "type": event.get("type", ""),
        "direction": event.get("direction", ""),
        "amount_inr": details.get("amount", ""),
        "source": (
            details.get("sender_account_id")
            or details.get("caller_phone_id")
            or details.get("sender")
            or details.get("phone_id")
            or ""
        ),
        "target": (
            details.get("receiver_account_id")
            or details.get("receiver_phone_id")
            or details.get("receiver")
            or ""
        ),
        "reference": details.get("reference_number", ""),
        "evidence_ids": ", ".join(event.get("evidence_ids", [])),
    }


def build_entity_relationship_rows(analysis: dict):
    rows = []
    entity_network = analysis.get("network", {}).get("entity_network", {})
    edges = entity_network.get("edges", [])

    profile_names = {
        p.get("subject_id"): p.get("name") or p.get("subject_id")
        for p in analysis.get("subject_profiles", [])
    }

    for edge in edges:
        source_type = edge.get("source_type", "")
        target_type = edge.get("target_type", "")
        source = edge.get("source", "")
        target = edge.get("target", "")

        rows.append(
            {
                "Source Type": source_type,
                "Source": profile_names.get(source, source),
                "Source ID": source,
                "Relationship": edge.get("relationship_type", ""),
                "Target Type": target_type,
                "Target": profile_names.get(target, target),
                "Target ID": target,
                "Events": edge.get("event_count", 0),
                "Evidence IDs": ", ".join(edge.get("evidence_ids", [])),
            }
        )

    return rows


# ============================================================
# HEADER
# ============================================================

st.title("FraudGraph")
st.caption("Cyber-fraud evidence normalization and entity analysis")

page_titles = {
    "case": "Step 1 — Create Case",
    "raw": "Step 2 — Raw Data & Normalize",
    "analyzer": "Step 3 — Analyzer",
    "results": "Step 4 — Analysis Result",
}

st.markdown(
    f'<div class="step">{page_titles[st.session_state.page]}</div>',
    unsafe_allow_html=True,
)

# Small reset action, intentionally unobtrusive.
with st.sidebar:
    st.button("Start new case", on_click=reset_app, use_container_width=True)


# ============================================================
# STEP 1 — CREATE CASE
# ============================================================

if st.session_state.page == "case":
    st.header("Create a new case")
    st.write("Enter the case details first. Raw evidence is uploaded in the next step.")

    col1, col2 = st.columns(2)
    with col1:
        case_id = st.text_input(
            "Case ID *",
            placeholder="JH-CYB-001",
            value=st.session_state.case_id,
        )
        case_title = st.text_input(
            "Case name / title *",
            placeholder="Jamtara Cyber Fraud Investigation",
            value=st.session_state.case_title,
        )
        fir_number = st.text_input("FIR number", placeholder="Optional")
        police_station = st.text_input("Police station", placeholder="Optional")

    with col2:
        incident_type = st.text_input(
            "Incident type",
            placeholder="UPI Fraud / SIM Swap / Cyber Fraud",
        )
        complaint_date = st.text_input(
            "Complaint date",
            placeholder="YYYY-MM-DD",
        )
        reported_loss = st.number_input(
            "Reported loss (INR)",
            min_value=0.0,
            value=0.0,
            step=1000.0,
        )
        description = st.text_area(
            "Case description",
            placeholder="Short description of the case",
            height=120,
        )

    if st.button("Create case and continue", type="primary", use_container_width=True):
        clean_id = safe_case_id(case_id)
        if not clean_id:
            st.error("Case ID is required.")
        elif not case_title.strip():
            st.error("Case name / title is required.")
        else:
            st.session_state.case_id = clean_id
            st.session_state.case_title = case_title.strip()
            st.session_state.case_meta = {
                "fir_number": fir_number.strip(),
                "police_station": police_station.strip(),
                "incident_type": incident_type.strip(),
                "complaint_date": complaint_date.strip(),
                "reported_loss_inr": reported_loss,
                "description": description.strip(),
            }
            st.session_state.result = None
            st.session_state.analysis = None
            st.session_state.ai_analysis = None
            st.session_state.raw_files = []
            st.session_state.normalized_json = None
            go("raw")


# ============================================================
# STEP 2 — RAW DATA + NORMALIZE
# ============================================================

elif st.session_state.page == "raw":
    st.header("Raw data")
    st.write(
        f"Case: **{st.session_state.case_title}**  ·  ID: **{st.session_state.case_id}**"
    )

    files = st.file_uploader(
        "Upload raw evidence files",
        type=["csv", "xlsx", "xls", "json", "txt", "pdf"],
        accept_multiple_files=True,
        key=f"raw_evidence_upload_{st.session_state.case_id}",
    )

    if files:
        st.caption(f"{len(files)} file(s) selected")

    if st.button("Normalize raw data", type="primary", use_container_width=True):
        if not files:
            st.error("Upload at least one raw evidence file.")
            st.stop()

        engine = NormalizationEngine(
            case_id=st.session_state.case_id,
            title=st.session_state.case_title,
        )

        meta = st.session_state.case_meta
        case_obj = engine.case["case"]
        case_obj["fir_number"] = meta.get("fir_number", "")
        case_obj["police_station"] = meta.get("police_station", "")
        case_obj["incident_type"] = meta.get("incident_type", "")
        case_obj["complaint_date"] = meta.get("complaint_date", "")
        case_obj["reported_loss_inr"] = meta.get("reported_loss_inr")
        case_obj["description"] = meta.get("description", "")

        progress = st.progress(0)
        for index, uploaded_file in enumerate(files):
            engine.process_file(
                filename=uploaded_file.name,
                file_bytes=uploaded_file.getvalue(),
            )
            progress.progress(int(((index + 1) / len(files)) * 100))

        result = engine.finalize()
        st.session_state.raw_files = list(files)
        st.session_state.result = result
        st.session_state.normalized_json = json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
        write_case_file(st.session_state.case_id, result)
        go("analyzer")

    if st.session_state.result is None:
        if st.button("← Back to case", use_container_width=True):
            go("case")


# ============================================================
# STEP 3 — ANALYZER ACTIONS
# ============================================================

elif st.session_state.page == "analyzer":
    st.header("Analyzer")
    st.write("Normalization is complete. Choose what to do with the normalized case.")

    result = st.session_state.result
    counts = {
        "Persons": len(result.get("persons", [])),
        "Accounts": len(result.get("accounts", [])),
        "Devices": len(result.get("devices", [])),
        "Transactions": len(result.get("transactions", [])),
        "Calls": len(result.get("calls", [])),
        "SIM events": len(result.get("sim_events", [])),
    }

    st.dataframe(
        [{"Entity": k, "Count": v} for k, v in counts.items()],
        use_container_width=True,
        hide_index=True,
    )

    st.divider()
    st.write("### Continue")

    c1, c2 = st.columns(2)

    with c1:
        if st.button("Analyse normalized case", type="primary", use_container_width=True):
            try:
                analysis = AnalyzerEngine(result).analyze()
                st.session_state.analysis = analysis
                write_analysis_file(st.session_state.case_id, analysis)
                go("results")
            except Exception as exc:
                st.error(f"Analysis failed: {exc}")

    with c2:
        st.download_button(
            "Download normalized case.json",
            data=st.session_state.normalized_json or json.dumps(result, indent=2),
            file_name=f'{st.session_state.case_id}.json',
            mime="application/json",
            use_container_width=True,
        )

    if st.button("← Back to raw data", use_container_width=True):
        go("raw")


# ============================================================
# STEP 4 — ANALYSIS RESULT
# ============================================================

else:
    analysis = st.session_state.analysis

    if not analysis:
        st.warning("No analysis is loaded.")
        if st.button("Go to analyzer", use_container_width=True):
            go("analyzer")
        st.stop()

    st.header("Analysis result")
    st.write(
        f"Case: **{analysis['analysis'].get('case_title', '')}**  ·  "
        f"ID: **{analysis['analysis'].get('case_id', '')}**"
    )

    # First option is deliberately the entity-relationship table.
    tabs = st.tabs([
        "Entity Relationships",
        "Person Profiles",
        "Timeline",
        "Graph — Phase 3",
        "AI Fraud Analysis",
    ])

    # --------------------------------------------------------
    # 4A ENTITY RELATIONSHIPS
    # --------------------------------------------------------
    with tabs[0]:
        st.subheader("Entity relationship table")
        st.caption(
            "This is the first visualization-independent analysis output. "
            "Each row represents a relationship derived from the normalized evidence."
        )

        rows = build_entity_relationship_rows(analysis)
        if rows:
            st.dataframe(
                rows,
                use_container_width=True,
                hide_index=True,
                height=560,
            )
        else:
            st.info("No entity relationships could be derived from the supplied evidence.")

    # --------------------------------------------------------
    # 4B PERSON PROFILES
    # --------------------------------------------------------
    with tabs[1]:
        st.subheader("Person profiles")
        profiles = analysis.get("subject_profiles", [])

        if not profiles:
            st.info("No person profiles were derived.")
        else:
            profile_rows = []
            for p in profiles:
                ids = p.get("identifiers", {})
                stats = p.get("statistics", {})
                profile_rows.append(
                    {
                        "Name": p.get("name") or "Unknown",
                        "Person ID": p.get("subject_id", ""),
                        "Role": p.get("role") or "UNSPECIFIED",
                        "Accounts": len(ids.get("account_ids", [])) or len(ids.get("account_numbers", [])),
                        "Phones": len(ids.get("phone_ids", [])) or len(ids.get("phone_numbers", [])),
                        "Devices": len(ids.get("device_ids", [])) or len(ids.get("imeis", [])),
                        "Transactions": stats.get("transactions_count", 0),
                        "Calls": stats.get("calls_count", 0),
                    }
                )

            st.dataframe(
                profile_rows,
                use_container_width=True,
                hide_index=True,
                height=500,
            )

            selected_id = st.selectbox(
                "Open profile",
                [p.get("subject_id", "") for p in profiles],
                format_func=lambda sid: next(
                    (p.get("name") or sid for p in profiles if p.get("subject_id") == sid),
                    sid,
                ),
            )

            profile = next(p for p in profiles if p.get("subject_id") == selected_id)
            st.write(f"**Name:** {profile.get('name') or 'Unknown'}")
            st.write(f"**Role:** {profile.get('role') or 'UNSPECIFIED'}")
            st.write("**Identifiers**")
            st.json(profile.get("identifiers", {}), expanded=False)

    # --------------------------------------------------------
    # 4C TIMELINE
    # --------------------------------------------------------
    with tabs[2]:
        st.subheader("Unified timeline")
        profiles = analysis.get("subject_profiles", [])
        options = [p.get("subject_id", "") for p in profiles]

        if options:
            selected_id = st.selectbox(
                "Select person",
                options,
                format_func=lambda sid: next(
                    (p.get("name") or sid for p in profiles if p.get("subject_id") == sid),
                    sid,
                ),
                key="timeline_subject",
            )
            profile = next(p for p in profiles if p.get("subject_id") == selected_id)
            timeline_rows = [event_to_row(event) for event in profile.get("timeline", [])]
            st.dataframe(
                timeline_rows,
                use_container_width=True,
                hide_index=True,
                height=560,
            )
        else:
            st.info("No person timelines are available.")

    # --------------------------------------------------------
    # 4D GRAPH — FINAL INVESTIGATION VISUALIZER
    # --------------------------------------------------------
    with tabs[3]:
        st.subheader("Final investigation visualizer")
        st.caption(
            "The graph is a navigation layer over the completed analysis: entities are nodes, "
            "relationships are undirected edges, and every interactive detail is resolved back to "
            "the analyzer's evidence-linked events."
        )
        render_investigation_visualizer(analysis)

    # --------------------------------------------------------
    # 4E AI FRAUD ANALYSIS — IBM BOB
    # --------------------------------------------------------
    with tabs[4]:
        st.subheader("AI fraud analysis")
        st.caption(
            "IBM Bob analyzes the derived Phase 2 case only. It does not replace the evidence engine "
            "and it cannot establish guilt. Role outputs are investigative hypotheses."
        )

        with st.expander("IBM Bob connection", expanded=st.session_state.ai_analysis is None):
            env_key = os.getenv("BOB_API_KEY") or os.getenv("BOBSHELL_API_KEY")
            api_key = st.text_input(
                "Bob API key",
                type="password",
                value="" if env_key else "",
                help="Prefer an Inference API key. If you use a General key, also provide Team ID.",
            )
            team_id = st.text_input(
                "Team ID (only needed for a General key)",
                value=os.getenv("BOB_TEAM_ID", ""),
            )
            base_url = st.text_input(
                "Bob inference base URL",
                value=os.getenv("BOB_API_BASE_URL", "https://api.us-east.bob.ibm.com/inference/v1"),
            )
            model = st.text_input(
                "Bob model",
                value=os.getenv("BOB_MODEL", "premium"),
                help="Use the model alias enabled for your IBM Bob subscription/hackathon credits.",
            )

        selected_key = api_key.strip() or os.getenv("BOB_API_KEY") or os.getenv("BOBSHELL_API_KEY") or ""
        if not selected_key:
            st.info("Add BOB_API_KEY in your environment or enter the key above to enable live AI inference.")
        else:
            st.success("IBM Bob is configured for inference.")

        if st.button("Run AI Fraud Analysis", type="primary", use_container_width=True):
            if not selected_key:
                st.error("IBM Bob API key is required.")
            else:
                try:
                    client = BobClient(
                        api_key=selected_key,
                        team_id=team_id.strip() or None,
                        base_url=base_url.strip(),
                        model=model.strip() or "premium",
                    )
                    with st.spinner("IBM Bob is analyzing the derived case..."):
                        ai_result = FraudAIAnalyzer(client).analyze(analysis)
                    st.session_state.ai_analysis = ai_result
                    st.success("AI analysis completed.")
                except BobAPIError as exc:
                    st.error(str(exc))
                except Exception as exc:
                    st.error(f"AI analysis failed: {exc}")

        ai_result = st.session_state.ai_analysis
        if ai_result:
            prediction = ai_result.get("fraud_type_prediction", {})
            roles = ai_result.get("role_analysis", {})

            st.divider()
            st.write("### Predicted fraud type")
            st.metric(
                "Primary fraud type",
                prediction.get("primary_type", "Unknown"),
                f"{prediction.get('estimated_probability_pct', 0):.1f}% estimated probability",
            )

            distribution = prediction.get("distribution", [])
            if distribution:
                st.dataframe(
                    [
                        {
                            "Fraud Type": row.get("fraud_type", ""),
                            "Estimated Probability (%)": row.get("estimated_probability_pct", 0),
                            "AI Reasoning": " | ".join(row.get("reasons", [])),
                        }
                        for row in distribution
                    ],
                    use_container_width=True,
                    hide_index=True,
                )

            if prediction.get("explanation"):
                st.write("**AI explanation:**", prediction["explanation"])

            st.divider()
            st.write("### Suspect-role analysis")
            role_rows = []
            for key, label in [
                ("prime_suspect", "Prime suspect"),
                ("kingpin_candidate", "Kingpin candidate"),
            ]:
                cand = roles.get(key) or {}
                role_rows.append({
                    "Role": label,
                    "Subject ID": cand.get("subject_id") or "—",
                    "Name": cand.get("name") or "—",
                    "Confidence (%)": cand.get("confidence_pct", 0),
                    "Reasons": " | ".join(cand.get("reasons", [])),
                })
            for cand in roles.get("mule_candidates", [])[:5]:
                role_rows.append({
                    "Role": "Mule candidate",
                    "Subject ID": cand.get("subject_id") or "—",
                    "Name": cand.get("name") or "—",
                    "Confidence (%)": cand.get("confidence_pct", 0),
                    "Reasons": " | ".join(cand.get("reasons", [])),
                })
            st.dataframe(role_rows, use_container_width=True, hide_index=True)

            st.divider()
            st.write("### Evidence cross-checks")
            for item in ai_result.get("cross_checks", []):
                st.write("•", item)
            if ai_result.get("limitations"):
                st.write("### Limitations")
                for item in ai_result["limitations"]:
                    st.write("•", item)

            st.download_button(
                "Download AI analysis JSON",
                data=json.dumps(ai_result, indent=2, ensure_ascii=False),
                file_name=f'{st.session_state.case_id}_ai_analysis.json',
                mime="application/json",
                use_container_width=True,
            )

    # --------------------------------------------------------
    # DOWNLOAD ANALYSIS JSON
    # --------------------------------------------------------
    st.divider()
    phase2_export = build_phase2_export(analysis)
    st.download_button(
        "Download analysis.json",
        data=json.dumps(phase2_export, indent=2, ensure_ascii=False),
        file_name=f'{st.session_state.case_id}_analysis.json',
        mime="application/json",
        type="primary",
        use_container_width=True,
    )

    if st.button("← Back to analyzer", use_container_width=True):
        go("analyzer")
