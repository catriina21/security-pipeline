import os
import sys
import re
import urllib.request
import ssl
from datetime import datetime

SECURITY_HEADERS_DB = {
    "Strict-Transport-Security": {"weight": 15, "desc": "Mencegah Cryptographic Failures (Memaksa koneksi HTTPS aman)."},
    "Content-Security-Policy": {"weight": 20, "desc": "Mencegah Security Misconfiguration & XSS Injection."},
    "X-Frame-Options": {"weight": 10, "desc": "Proteksi dari Clickjacking (Security Misconfiguration)."},
    "X-Content-Type-Options": {"weight": 10, "desc": "Mencegah MIME-sniffing (Security Misconfiguration)."},
    "Referrer-Policy": {"weight": 5, "desc": "Mengontrol kebocoran data pada header Referer."},
    "Permissions-Policy": {"weight": 5, "desc": "Membatasi akses fitur hardware browser."}
}

def parse_headers(raw_logs_dir):
    headers_file = os.path.join(raw_logs_dir, "headers.txt")
    results = {}
    content = ""
    if os.path.exists(headers_file):
        with open(headers_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
    for header, meta in SECURITY_HEADERS_DB.items():
        present = bool(re.search(rf"{header}:", content, re.IGNORECASE))
        results[header] = {"present": present, "weight": meta["weight"], "desc": meta["desc"]}
    return results

def verify_soft_404(url):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='ignore').lower()
            soft_404_signatures = [
                "halaman tidak ditemukan", "page not found", "404 not found",
                "kembali ke beranda", "error 404", "tidak ada di server"
            ]
            for sig in soft_404_signatures:
                if sig in body:
                    return False
            return True
    except Exception:
        return False

def parse_sensitive_paths(raw_logs_dir):
    sensitive_file = os.path.join(raw_logs_dir, "sensitive_check.txt")
    confirmed_exposed = []
    if os.path.exists(sensitive_file):
        with open(sensitive_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "EXPOSED (200 OK)" in line:
                    url = line.strip().replace("[⚠️] EXPOSED (200 OK): ", "").replace("[EXPOSED]: ", "")
                    if verify_soft_404(url):
                        confirmed_exposed.append(url)
    return confirmed_exposed

def parse_nmap_ports(raw_logs_dir):
    nmap_file = os.path.join(raw_logs_dir, "nmap.txt")
    open_ports = []
    if os.path.exists(nmap_file):
        with open(nmap_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "/tcp" in line and "open" in line:
                    open_ports.append(line.strip())
    return open_ports

def read_raw_log_file(raw_logs_dir, filename):
    filepath = os.path.join(raw_logs_dir, filename)
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
            return content if content else "Log kosong / Tidak ada temuan."
    return "File log tidak ditemukan."

def calculate_grade(headers_data, exposed_paths):
    score = 100
    for header, info in headers_data.items():
        if not info["present"]:
            score -= info["weight"]
    score -= (len(exposed_paths) * 20)
    score = max(0, score)
    
    if score >= 90: return score, "A", "#10b981"
    elif score >= 75: return score, "B", "#06b6d4"
    elif score >= 60: return score, "C", "#f59e0b"
    elif score >= 40: return score, "D", "#f97316"
    else: return score, "F", "#ef4444"

def generate_report(target_url, report_dir="security-reports"):
    raw_logs_dir = os.path.join(report_dir, "raw_logs")
    output_html = os.path.join(report_dir, "SECURITY-AUDIT-REPORT.html")
    
    headers_data = parse_headers(raw_logs_dir)
    exposed_paths = parse_sensitive_paths(raw_logs_dir)
    open_ports = parse_nmap_ports(raw_logs_dir)
    score, grade, grade_color = calculate_grade(headers_data, exposed_paths)
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_nmap = read_raw_log_file(raw_logs_dir, "nmap.txt")
    log_nikto = read_raw_log_file(raw_logs_dir, "nikto.txt")
    log_nuclei = read_raw_log_file(raw_logs_dir, "nuclei.txt")
    log_dalfox = read_raw_log_file(raw_logs_dir, "dalfox.txt")
    log_trivy = read_raw_log_file(raw_logs_dir, "trivy.txt")

    html_content = f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>DevSecOps Security Audit - {target_url}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 30px; }}
        .container {{ max-width: 950px; margin: auto; background: #1e293b; padding: 35px; border-radius: 12px; border: 1px solid #334155; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3); }}
        .header-card {{ display: flex; align-items: center; background: #0f172a; padding: 25px; border-radius: 10px; border: 1px solid #334155; margin-bottom: 25px; }}
        .grade-box {{ font-size: 52px; font-weight: 800; width: 100px; height: 100px; display: flex; flex-direction: column; align-items: center; justify-content: center; background: {grade_color}; color: #ffffff; border-radius: 10px; margin-right: 25px; flex-shrink: 0; }}
        .grade-box .score-label {{ font-size: 13px; font-weight: 600; margin-top: -4px; opacity: 0.95; }}
        .meta h2 {{ margin: 0 0 6px 0; font-size: 22px; color: #f8fafc; }}
        .meta p {{ margin: 3px 0; font-size: 14px; color: #94a3b8; }}
        .section-title {{ font-size: 16px; font-weight: 700; margin-top: 30px; margin-bottom: 12px; border-bottom: 1px solid #334155; padding-bottom: 8px; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.5px; }}
        .badge {{ display: inline-block; padding: 4px 10px; font-size: 11px; font-weight: 700; border-radius: 4px; color: #fff; }}
        .badge-pass {{ background: #10b981; }}
        .badge-fail {{ background: #ef4444; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; border: 1px solid #334155; }}
        th, td {{ padding: 12px 15px; border: 1px solid #334155; text-align: left; font-size: 13px; }}
        th {{ background: #0f172a; color: #cbd5e1; font-weight: 600; }}
        tr:nth-child(even) {{ background: #162032; }}
        
        .btn-pdf {{ background: #2563eb; color: #ffffff; padding: 10px 20px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; float: right; font-size: 13px; transition: background 0.2s; }}
        .btn-pdf:hover {{ background: #1d4ed8; }}
        
        .pdf-only {{ display: none; }}
        .log-box {{ background: #020617; color: #38bdf8; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; padding: 15px; border-radius: 6px; border: 1px solid #1e293b; white-space: pre-wrap; word-break: break-all; margin-bottom: 20px; }}

        @media print {{
            .no-print {{ display: none !important; }}
            .pdf-only {{ display: block !important; }}
            body {{ background: #ffffff !important; color: #0f172a !important; padding: 0 !important; }}
            .container {{ border: none !important; box-shadow: none !important; padding: 0 !important; background: #ffffff !important; max-width: 100% !important; }}
            .header-card {{ background: #f8fafc !important; border: 1px solid #e2e8f0 !important; }}
            .meta h2 {{ color: #0f172a !important; }}
            .meta p {{ color: #475569 !important; }}
            .section-title {{ color: #0284c7 !important; border-bottom: 1px solid #cbd5e1 !important; }}
            table {{ border: 1px solid #cbd5e1 !important; }}
            th, td {{ border: 1px solid #cbd5e1 !important; color: #0f172a !important; }}
            th {{ background: #f1f5f9 !important; color: #334155 !important; }}
            tr:nth-child(even) {{ background: #f8fafc !important; }}
            .page-break {{ page-break-before: always; padding-top: 20px; }}
            .log-box {{ background: #f8fafc !important; color: #0f172a !important; border: 1px solid #cbd5e1 !important; max-height: none !important; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <button onclick="window.print()" class="btn-pdf no-print">Export / Save as PDF</button>
        <div style="clear: both;"></div>

        <div class="header-card">
            <div class="grade-box">
                <div>{grade}</div>
                <div class="score-label">{score}/100</div>
            </div>
            <div class="meta">
                <h2>DevSecOps Automated Security Audit</h2>
                <p><strong>Target Audit:</strong> {target_url}</p>
                <p><strong>Waktu Exec:</strong> {report_time} WIB</p>
                <p><strong>Engine Standard:</strong> OWASP Top 10 Framework & Mozilla HTTP Observatory Metric</p>
            </div>
        </div>

        <div class="section-title">HTTP Security Headers Audit (OWASP A05: Security Misconfiguration)</div>
        <table>
            <thead>
                <tr>
                    <th>Security Header</th>
                    <th>Bobot Penalti</th>
                    <th>Status</th>
                    <th>Deskripsi & Kategori OWASP</th>
                </tr>
            </thead>
            <tbody>
"""
    for header, info in headers_data.items():
        badge = '<span class="badge badge-pass">TERPASANG</span>' if info["present"] else '<span class="badge badge-fail">ABSEN</span>'
        html_content += f"""
                <tr>
                    <td><code>{header}</code></td>
                    <td style="text-align:center;">-{info['weight']} pt</td>
                    <td>{badge}</td>
                    <td>{info['desc']}</td>
                </tr>
"""

    html_content += """
            </tbody>
        </table>

        <div class="section-title">Sensitive Endpoints Exposure (OWASP A01: Broken Access Control)</div>
"""
    if exposed_paths:
        html_content += "<ul style='padding-left: 20px; margin: 0;'>"
        for p in exposed_paths:
            html_content += f"<li style='color:#ef4444; margin-bottom: 6px; font-size: 14px;'><strong>[EXPOSED]:</strong> <a href='{p}' target='_blank' style='color:#ef4444;'>{p}</a></li>"
        html_content += "</ul>"
    else:
        html_content += "<p style='color:#10b981; font-weight:600; font-size: 14px; margin: 0;'>Tidak ada file sensitif (.env, .git, db backup) yang terkonfirmasi bocor.</p>"

    html_content += """
        <div class="section-title">Active Ports Summary</div>
"""
    if open_ports:
        html_content += "<ul style='padding-left: 20px; margin: 0;'>"
        for port in open_ports:
            html_content += f"<li style='font-size: 14px; margin-bottom: 4px;'><code>{port}</code></li>"
        html_content += "</ul>"
    else:
        html_content += "<p style='color:#94a3b8; font-size: 14px; margin: 0;'>Port standar web (80/443) merespons normal.</p>"

    html_content += f"""
        <div class="pdf-only page-break">
            <div class="section-title">Technical Appendix: Raw Scanning Logs</div>
            
            <h3>1. Nmap Port Scanning Log</h3>
            <div class="log-box">{log_nmap}</div>

            <h3>2. Nikto Web Audit Log</h3>
            <div class="log-box">{log_nikto}</div>

            <h3>3. Nuclei Vulnerability Scan Log</h3>
            <div class="log-box">{log_nuclei}</div>

            <h3>4. Dalfox XSS Audit Log</h3>
            <div class="log-box">{log_dalfox}</div>

            <h3>5. Trivy Container/Repo Audit Log</h3>
            <div class="log-box">{log_trivy}</div>
        </div>

        <div style="text-align: center; margin-top: 40px; font-size: 12px; color: #64748b; border-top: 1px solid #334155; padding-top: 20px;">
            Audit diproses secara 100% lokal (Local-First DevSecOps Engine) tanpa mengirimkan log ke cloud pihak ketiga.
        </div>
    </div>
</body>
</html>
"""

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[✅] Laporan HTML berbasis OWASP Top 10 berhasil dibuat: {output_html}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1"
    generate_report(target)
