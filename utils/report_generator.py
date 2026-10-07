import os
import sys
import platform
import socket
from datetime import datetime
from pathlib import Path
import psutil
from core.settings import BASE_DIR, THREAT_LOG_PATH, QUARANTINE_DIR
from core.QuarantineManager import QuarantineManager
from core.SignalBus import emit_log
def generate_incident_report(output_html_path: str = None) -> str:
    """
    Generates a dark-cyber themed Incident Response and Threat Audit Report in HTML format.
    Returns the path to the generated HTML file.
    """
    if not output_html_path:
        reports_dir = Path(BASE_DIR) / "logs" / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_html_path = str(reports_dir / f"CyberGun_Audit_Report_{timestamp}.html")
    qm = QuarantineManager()
    quarantined_files = qm.list_quarantined_files()
    intel_stats = {}
    db_history = []
    try:
        from core.database_manager import get_db_manager
        db_mgr = get_db_manager()
        intel_stats = db_mgr.get_intel_stats()
        db_history = db_mgr.get_scan_history(limit=50)
    except Exception as dbe:
        emit_log(f"[ReportGenerator] Database query notice: {dbe}", "info")
    total_threat_indicators = (
        intel_stats.get("threat_hashes", 0) +
        intel_stats.get("threat_ips", 0) +
        intel_stats.get("threat_emails", 0) +
        intel_stats.get("threat_domains", 0) +
        intel_stats.get("threat_signatures", 0) +
        intel_stats.get("threat_strings", 0)
    )
    threat_lines = []
    if os.path.exists(THREAT_LOG_PATH):
        try:
            with open(THREAT_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
                threat_lines = [line.strip() for line in f if line.strip()][-50:]
        except Exception:
            pass
    hostname = socket.gethostname()
    os_name = f"{platform.system()} {platform.release()} (Build {platform.version()})"
    cpu_info = f"{psutil.cpu_percent(interval=None)}% ({psutil.cpu_count(logical=True)} Cores)"
    mem = psutil.virtual_memory()
    mem_info = f"{round(mem.used / (1024**3), 2)} GB / {round(mem.total / (1024**3), 2)} GB ({mem.percent}% used)"
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    quarantine_rows = ""
    for q in quarantined_files:
        quarantine_rows += f"""
        <tr>
            <td style="color:#00ffc8; font-weight:bold;">{q.get('filename', 'Unknown')}</td>
            <td>{q.get('original_path', 'N/A')}</td>
            <td><code>{q.get('sha256', 'N/A')}</code></td>
            <td>{q.get('quarantine_date', 'N/A')}</td>
            <td><span class="badge badge-danger">VAULT ENCRYPTED</span></td>
        </tr>
        """
    if not quarantined_files:
        quarantine_rows = '<tr><td colspan="5" style="text-align:center; color:#888;">No threats currently in quarantine vault.</td></tr>'
    history_rows = ""
    for h in db_history:
        sev = str(h.get('severity', 'medium')).lower()
        badge_class = "badge-danger" if sev in ['critical', 'high'] else ("badge-info" if sev == 'low' else "badge-warning")
        history_rows += f"""
        <tr>
            <td>{h.get('timestamp', 'N/A')}</td>
            <td style="color:#00ffc8; font-weight:bold;">{h.get('threat_name', 'Unknown')}</td>
            <td>{h.get('threat_type', 'N/A')}</td>
            <td><span class="badge {badge_class}">{sev.upper()}</span></td>
            <td><span class="badge badge-info">{h.get('action_taken', 'Recorded')}</span></td>
            <td style="max-width:250px; overflow:hidden; text-overflow:ellipsis;">{h.get('target_path', 'N/A')}</td>
        </tr>
        """
    if not db_history:
        history_rows = '<tr><td colspan="6" style="text-align:center; color:#888;">No security events recorded in SQLite audit ledger.</td></tr>'
    log_rows = ""
    for line in reversed(threat_lines):
        log_rows += f"<tr><td><code>{line}</code></td></tr>"
    if not threat_lines:
        log_rows = '<tr><td style="text-align:center; color:#888;">No historical threat events recorded.</td></tr>'
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CyberGun Security Incident Report</title>
    <style>
        body {{
            background-color: #0b1016;
            color: #d1d5db;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid #00aaff;
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{
            margin: 0;
            color: #00ffc8;
            font-size: 28px;
            letter-spacing: 1px;
            font-family: 'Consolas', monospace;
        }}
        .header .subtitle {{
            color: #9ca3af;
            font-size: 14px;
            margin-top: 5px;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-danger {{
            background-color: #ef4444;
            color: #fff;
        }}
        .badge-success {{
            background-color: #10b981;
            color: #fff;
        }}
        .badge-info {{
            background-color: #00aaff;
            color: #000;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background-color: #131c26;
            border: 1px solid #1f2d3d;
            border-radius: 8px;
            padding: 20px;
        }}
        .metric-card {{
            border-left: 4px solid #00aaff;
        }}
        .metric-value {{
            font-size: 32px;
            font-weight: bold;
            color: #00ffc8;
            font-family: 'Consolas', monospace;
        }}
        .metric-label {{
            font-size: 12px;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 5px;
        }}
        h2 {{
            color: #00aaff;
            font-size: 18px;
            border-bottom: 1px solid #1f2d3d;
            padding-bottom: 8px;
            margin-top: 0;
            font-family: 'Consolas', monospace;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #1a2533;
        }}
        th {{
            color: #9ca3af;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
        }}
        code {{
            background-color: #080c10;
            color: #38bdf8;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            word-break: break-all;
        }}
        .footer {{
            margin-top: 40px;
            text-align: center;
            font-size: 12px;
            color: #6b7280;
            border-top: 1px solid #1f2d3d;
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>CYBERGUN SECURITY SUITE</h1>
                <div class="subtitle">Threat Mitigation & Forensic Audit Report</div>
            </div>
            <div style="text-align: right;">
                <span class="badge badge-info">OFFICIAL AUDIT</span>
                <div class="subtitle">Generated: {gen_time}</div>
            </div>
        </div>
        <div class="metrics-grid">
            <div class="card metric-card">
                <div class="metric-value">{len(quarantined_files)}</div>
                <div class="metric-label">Quarantined Objects</div>
            </div>
            <div class="card metric-card" style="border-left-color: #10b981;">
                <div class="metric-value">Active</div>
                <div class="metric-label">Real-Time Protection</div>
            </div>
            <div class="card metric-card" style="border-left-color: #f59e0b;">
                <div class="metric-value">{len(threat_lines)}</div>
                <div class="metric-label">Logged Incidents</div>
            </div>
            <div class="card metric-card" style="border-left-color: #a855f7;">
                <div class="metric-value">v1.0</div>
                <div class="metric-label">Engine Suite Version</div>
            </div>
        </div>
        <div class="card" style="margin-bottom: 30px;">
            <h2>System Telemetry & Environment</h2>
            <table>
                <tr><th style="width: 25%;">Host Machine</th><td>{hostname}</td></tr>
                <tr><th>Operating System</th><td>{os_name}</td></tr>
                <tr><th>CPU Allocation</th><td>{cpu_info}</td></tr>
                <tr><th>Memory Utilization</th><td>{mem_info}</td></tr>
            </table>
        </div>
        <div class="card" style="margin-bottom: 30px;">
            <h2>Threat Intelligence Arsenal (SQLite Engine)</h2>
            <div class="metrics-grid" style="margin-bottom: 0;">
                <div class="card metric-card" style="border-left-color: #00ffc8; background: #0e1620;">
                    <div class="metric-value">{intel_stats.get('threat_hashes', 0):,}</div>
                    <div class="metric-label">Malware Hashes</div>
                </div>
                <div class="card metric-card" style="border-left-color: #ef4444; background: #0e1620;">
                    <div class="metric-value">{intel_stats.get('threat_ips', 0):,}</div>
                    <div class="metric-label">Blacklisted IPs</div>
                </div>
                <div class="card metric-card" style="border-left-color: #f59e0b; background: #0e1620;">
                    <div class="metric-value">{intel_stats.get('threat_emails', 0):,}</div>
                    <div class="metric-label">Phishing Indicators</div>
                </div>
                <div class="card metric-card" style="border-left-color: #38bdf8; background: #0e1620;">
                    <div class="metric-value">{intel_stats.get('threat_signatures', 0) + intel_stats.get('threat_strings', 0):,}</div>
                    <div class="metric-label">Signatures & Rules</div>
                </div>
            </div>
        </div>
        <div class="card" style="margin-bottom: 30px;">
            <h2>Vault Quarantined Objects</h2>
            <table>
                <thead>
                    <tr>
                        <th>Object Identifier</th>
                        <th>Original File Path</th>
                        <th>SHA256 Checksum</th>
                        <th>Quarantine Timestamp</th>
                        <th>Isolation Status</th>
                    </tr>
                </thead>
                <tbody>
                    {quarantine_rows}
                </tbody>
            </table>
        </div>
        <div class="card" style="margin-bottom: 30px;">
            <h2>Security Incident Audit Ledger (Database)</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 15%;">Timestamp</th>
                        <th>Threat Name</th>
                        <th>Threat Type</th>
                        <th>Severity</th>
                        <th>Action</th>
                        <th>Target Path</th>
                    </tr>
                </thead>
                <tbody>
                    {history_rows}
                </tbody>
            </table>
        </div>
        <div class="card">
            <h2>Recent Security Incident Feed (Logs)</h2>
            <table>
                <tbody>
                    {log_rows}
                </tbody>
            </table>
        </div>
        <div class="footer">
            CyberGun Threat Mitigation Suite &bull; Automated Forensic Intelligence Report &bull; {hostname}
        </div>
    </div>
</body>
</html>
"""
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    emit_log(f"[ReportGenerator] Audit report generated at: {output_html_path}", "info")
    return output_html_path
