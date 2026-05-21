"""Enterprise-grade PDF incident report generator."""

import datetime
import logging
import os

from weasyprint import HTML

logger = logging.getLogger(__name__)


def _esc(text):
    """HTML-escape a string."""
    if text is None:
        return "-"
    s = str(text)
    s = s.replace("&", "&")
    s = s.replace("<", "<")
    s = s.replace(">", ">")
    return s


def _bool_badge(value):
    if value:
        return '<span class="badge badge-danger">YES</span>'
    return '<span class="badge badge-success">NO</span>'


def _severity_class(severity):
    return {
        "CRITICAL": "crit",
        "HIGH": "high",
        "MEDIUM": "med",
        "LOW": "low",
    }.get((severity or "").upper(), "low")


CSS = (
    "  @page { size: A4; margin: 24mm 20mm 24mm 20mm; "
    '@bottom-center { content: "ADAPTIVEPOT | CONFIDENTIAL"; font-size: 8px; color: #94a3b8; } } '
    "* { margin:0; padding:0; box-sizing:border-box; } "
    'body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 10pt; color: #1e293b; line-height: 1.6; } '
    "h1 { font-size: 18pt; font-weight: 800; margin-bottom: 4px; } "
    "h2 { font-size: 12pt; font-weight: 700; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 4px; margin: 24px 0 12px 0; } "
    "h3 { font-size: 10pt; font-weight: 700; color: #334155; margin: 12px 0 4px 0; } "
    "table { width: 100%; border-collapse: collapse; margin: 8px 0; } "
    "th { background: #f1f5f9; text-align: left; padding: 6px 8px; font-size: 9pt; font-weight: 700; color: #475569; border-bottom: 2px solid #cbd5e1; } "
    "td { padding: 5px 8px; font-size: 9pt; border-bottom: 1px solid #e2e8f0; } "
    '.mono { font-family: "JetBrains Mono", "Fira Code", "SF Mono", monospace; font-size: 8pt; } '
    ".header { display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:20px; } "
    ".header-left h1 { color:#0f172a; } "
    ".header-right { text-align:right; font-size:8pt; color:#64748b; } "
    ".meta-grid { display:grid; grid-template-columns:1fr 1fr; gap:6px 24px; margin:8px 0; } "
    ".meta-item { display:flex; justify-content:space-between; border-bottom:1px dotted #cbd5e1; padding:3px 0; font-size:9pt; } "
    ".meta-item .label { color:#64748b; } "
    ".meta-item .value { font-weight:600; } "
    ".severity { display:inline-block; padding:2px 12px; border-radius:999px; font-size:10pt; font-weight:800; color:#fff; } "
    ".severity.crit { background:#dc2626; } "
    ".severity.high { background:#ea580c; } "
    ".severity.med { background:#ca8a04; } "
    ".severity.low { background:#16a34a; } "
    ".badge { display:inline-block; padding:1px 10px; border-radius:999px; font-size:8pt; font-weight:700; color:#fff; } "
    ".badge-danger { background:#dc2626; } "
    ".badge-success { background:#16a34a; } "
    ".footer { margin-top:32px; padding-top:12px; border-top:1px solid #e2e8f0; font-size:7pt; color:#94a3b8; text-align:center; } "
    ".confidential { color:#dc2626; font-weight:700; }"
)


def generate_report_html(report, events=None):
    ioc = report.get("ioc") or {}
    ip = ioc.get("ip", "unknown")
    session_id = report.get("session_id", "unknown")
    severity = (report.get("severity") or "UNKNOWN").upper()
    sev_cls = _severity_class(severity)
    now_iso = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    country = ioc.get("country") or "-"
    city = ioc.get("city") or ""
    location = f"{city}, {country}" if city else country
    asn = ioc.get("asn") or "-"
    org = ioc.get("org") or "-"
    is_tor = ioc.get("is_tor", False)
    is_vpn = ioc.get("is_vpn", False)
    abuse_score = ioc.get("abuse_score")
    abuse_str = f"{abuse_score}%" if abuse_score is not None else "-"
    techniques = report.get("mitre_techniques") or []
    if isinstance(techniques, list) and techniques and isinstance(techniques[0], dict):
        tech_rows = "".join(
            '<tr><td class="mono">' + _esc(t.get("id", "")) + "</td><td>" + _esc(t.get("name", "")) + "</td></tr>"
            for t in techniques
        )
    else:
        tech_rows = '<tr><td colspan="2">No MITRE techniques mapped</td></tr>'
    kill_chain = _esc(report.get("kill_chain_phase") or "-")
    attacker_goal = _esc(report.get("attacker_goal") or "-")
    attacker_profile = _esc(report.get("attacker_profile") or "-")
    recommendation = _esc(report.get("recommendation") or "-")
    confidence = report.get("confidence")
    conf_str = f"{confidence:.0%}" if isinstance(confidence, (int, float)) else "-"
    event_rows = ""
    if events:
        for evt in sorted(events, key=lambda e: e.get("timestamp") or ""):
            ts = _esc(evt.get("timestamp") or "-")
            etype = _esc(evt.get("event_type") or "-")
            cmd = _esc(evt.get("raw_command") or evt.get("event_data", {}).get("command") or "-")
            mitre = _esc(evt.get("mitre_technique") or "-")
            event_rows += (
                "<tr><td class='mono'>" + ts + "</td><td>" + etype
                + "</td><td class='mono'>" + cmd + "</td><td>" + mitre + "</td></tr>"
            )
    if not event_rows:
        event_rows = '<tr><td colspan="4">No detailed events recorded</td></tr>'

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        "<title>THREAT REPORT -- " + _esc(session_id) + "</title>",
        "<style>" + CSS + "</style>",
        "</head>",
        "<body>",
        '<div class="header">',
        '<div class="header-left">',
        "<h1>ADAPTIVEPOT</h1>",
        '<p style="font-size:9pt; color:#475569;">Threat Intelligence Report</p>',
        "</div>",
        '<div class="header-right">',
        "<p><strong>Report ID:</strong> " + _esc(session_id) + "</p>",
        "<p><strong>Generated:</strong> " + now_iso + "</p>",
        '<p class="confidential">CONFIDENTIAL</p>',
        "</div>",
        "</div>",
        '<div style="margin-bottom:16px;">',
        '<span class="severity ' + sev_cls + '">' + _esc(severity) + "</span>",
        "</div>",
        "<h2>1. Executive Summary</h2>",
        "<p>A " + _esc(severity) + " severity incident was detected from IP <strong>" + _esc(ip)
        + "</strong>. Attacker engaged in <strong>"
        + kill_chain + "</strong> phase activity, goal: <em>" + attacker_goal + "</em>.</p>",
        "<h2>2. Attacker Profile</h2>",
        '<div class="meta-grid">',
        '<div class="meta-item"><span class="label">IP</span><span class="value mono">' + _esc(ip) + "</span></div>",
        '<div class="meta-item"><span class="label">Location</span><span class="value">' + _esc(location) + "</span></div>",
        '<div class="meta-item"><span class="label">ASN / Org</span><span class="value">' + _esc(asn) + " / " + _esc(org) + "</span></div>",
        '<div class="meta-item"><span class="label">Abuse Score</span><span class="value">' + abuse_str + "</span></div>",
        '<div class="meta-item"><span class="label">TOR</span><span class="value">' + _bool_badge(is_tor) + "</span></div>",
        '<div class="meta-item"><span class="label">VPN</span><span class="value">' + _bool_badge(is_vpn) + "</span></div>",
        '<div class="meta-item"><span class="label">Profile</span><span class="value">' + attacker_profile + "</span></div>",
        '<div class="meta-item"><span class="label">Confidence</span><span class="value">' + conf_str + "</span></div>",
        "</div>",
        "<h2>3. MITRE ATT&CK</h2>",
        "<table>",
        '<thead><tr><th>Technique ID</th><th>Name</th></tr></thead>',
        "<tbody>" + tech_rows + "</tbody>",
        "</table>",
        "<h2>4. Kill Chain</h2>",
        "<p><strong>Phase:</strong> " + kill_chain + "</p>",
        "<p><strong>Goal:</strong> " + attacker_goal + "</p>",
        "<h2>5. IOCs</h2>",
        "<table>",
        '<thead><tr><th>Indicator</th><th>Value</th><th>Type</th></tr></thead>',
        "<tbody>",
        '<tr><td class="mono">' + _esc(ip) + "</td><td>Source IP</td><td>IP</td></tr>",
        '<tr><td class="mono">' + _esc(session_id) + "</td><td>Session</td><td>ID</td></tr>",
        "<tr><td>" + _esc(asn) + "</td><td>ASN</td><td>Network</td></tr>",
        "<tr><td>" + _esc(country) + "</td><td>Country</td><td>GeoIP</td></tr>",
        "</tbody>",
        "</table>",
        "<h2>6. Attack Timeline</h2>",
        "<table>",
        '<thead><tr><th>Timestamp</th><th>Event</th><th>Command</th><th>MITRE</th></tr></thead>',
        "<tbody>" + event_rows + "</tbody>",
        "</table>",
        "<h2>7. Recommendations</h2>",
        "<p>" + recommendation + "</p>",
        '<div class="footer">',
        "<p>ADAPTIVEPOT Honeypot Platform -- Confidential -- " + now_iso + "</p>",
        "</div>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts)


class PDFExporter:
    """Compatibility wrapper used by AnalysisService."""

    def __init__(self, output_dir="/app/reports"):
        self.output_dir = output_dir

    async def export(self, report, events=None):
        return await generate_and_save(report, self.output_dir, events)


async def generate_pdf(report, events=None):
    html = generate_report_html(report, events)
    return HTML(string=html).write_pdf()


async def generate_and_save(report, output_dir="/app/reports", events=None):
    os.makedirs(output_dir, exist_ok=True)
    session_id = report.get("session_id", "unknown")
    pdf_bytes = await generate_pdf(report, events)
    filename = f"incident_{session_id}.pdf"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "wb") as f:
        f.write(pdf_bytes)
    logger.info("PDF report saved to %s", filepath)
    return filepath