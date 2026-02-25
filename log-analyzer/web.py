from flask import Flask, render_template, request, jsonify, Response
from analyzer import parse_text, analyze
import json, random
from datetime import datetime, timedelta

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


def _build_result(result, bf_threshold):
    return {
        "summary": {
            "total_lines": result.total_lines,
            "parsed_entries": result.parsed_entries,
            "unique_ips": result.unique_ips,
            "total_errors": result.total_errors,
            "threat_level": result.threat_level(bf_threshold),
            "has_timestamps": result.has_timestamps,
        },
        "status_codes": dict(result.status_counter),
        "methods": dict(result.method_counter),
        "top_ips": [{"ip": ip, "count": c} for ip, c in result.top_ips],
        "brute_force": [
            {
                "ip": s.ip,
                "auth_failures": s.auth_failures,
                "total_requests": s.total_requests,
                "unique_paths": len(s.unique_paths),
                "threat_score": s.threat_score(),
            }
            for s in result.brute_force_ips
        ],
        "flagged_paths": [
            {"ip": e.ip, "status": e.status, "method": e.method, "path": e.path}
            for e in result.flagged_entries[:50]
        ],
        "scanners": [
            {"ip": e.ip, "agent": e.agent, "path": e.path}
            for e in result.scanner_entries[:20]
        ],
        "ddos_windows": [
            {
                "start": w.start.strftime("%d/%b/%Y %H:%M:%S"),
                "end": w.end.strftime("%d/%b/%Y %H:%M:%S"),
                "total_requests": w.total_requests,
                "unique_ips": w.unique_ips,
                "top_ips": [{"ip": ip, "count": c} for ip, c in w.top_ips],
            }
            for w in result.ddos_windows
        ],
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json()
    if not data or "content" not in data:
        return jsonify({"error": "Envie { content: '...' }"}), 400

    bf_threshold = int(data.get("threshold", 10))
    entries, total_lines = parse_text(data["content"])

    if not entries:
        return jsonify({"error": "Nenhuma entrada válida. Verifique o formato (Apache/Nginx)."}), 422

    result = analyze(entries, total_lines, bf_threshold=bf_threshold)
    return jsonify(_build_result(result, bf_threshold))


@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    content = request.files["file"].read().decode("utf-8", errors="replace")
    bf_threshold = int(request.form.get("threshold", 10))
    entries, total_lines = parse_text(content)

    if not entries:
        return jsonify({"error": "Nenhuma entrada válida encontrada."}), 422

    result = analyze(entries, total_lines, bf_threshold=bf_threshold)
    return jsonify(_build_result(result, bf_threshold))


@app.route("/api/export-html", methods=["POST"])
def api_export_html():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Dados inválidos"}), 400

    html = _render_html_report(data)
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": "attachment; filename=log-report.html"}
    )


@app.route("/api/sample")
def api_sample():
    ips = ["192.168.1.10", "10.0.0.5", "203.0.113.42", "198.51.100.7"]
    attacker = "45.33.32.156"
    scanner = "198.51.100.99"
    now = datetime.now()
    months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

    def ts(offset=0):
        dt = now - timedelta(seconds=offset)
        return f"{dt.day:02d}/{months[dt.month-1]}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"

    def line(ip, path, method, code, agent, size=500, offset=0):
        return f'{ip} - - [{ts(offset)}] "{method} {path} HTTP/1.1" {code} {size} "-" "{agent}"'

    lines = []
    agents = ['Mozilla/5.0 (Windows NT 10.0)', 'curl/7.88', 'python-requests/2.28']
    paths = ["/", "/login", "/api/users", "/dashboard", "/static/app.js"]

    for i in range(80):
        lines.append(line(random.choice(ips), random.choice(paths),
                          random.choice(["GET", "POST"]),
                          random.choice([200, 200, 200, 301, 404, 500]),
                          random.choice(agents), random.randint(200, 8000),
                          offset=random.randint(0, 86400)))

    for i in range(40):
        lines.append(line(attacker, "/login", "POST", 401, "Hydra v9.4", 512,
                          offset=random.randint(0, 300)))

    for p in ["/.env", "/wp-login.php", "/.git/config", "/admin/config", "/phpmyadmin"]:
        lines.append(line(scanner, p, "GET", 404, "sqlmap/1.7.8", 256,
                          offset=random.randint(0, 3600)))

    # Simular flood DDoS em janela de 60s
    flood_ip = "77.88.55.66"
    for i in range(250):
        lines.append(line(flood_ip, "/api/products", "GET", 200, "python-requests/2.31",
                          offset=random.randint(3600, 3660)))

    random.shuffle(lines)
    return jsonify({"content": "\n".join(lines)})


def _render_html_report(data: dict) -> str:
    summary = data.get("summary", {})
    level = summary.get("threat_level", "SECURE")
    level_color = {"SECURE": "#22c55e", "WARNING": "#f59e0b", "CRITICAL": "#ef4444"}.get(level, "#e2e5ec")
    generated = datetime.now().strftime("%d/%m/%Y às %H:%M")

    def status_color(code):
        c = int(str(code))
        if c >= 500: return "#ef4444"
        if c >= 400: return "#f59e0b"
        if c >= 300: return "#3b82f6"
        return "#22c55e"

    status_rows = "".join(
        f'<tr><td style="font-family:monospace;color:{status_color(k)}">{k}</td>'
        f'<td style="text-align:right;font-family:monospace">{v}</td></tr>'
        for k, v in sorted(data.get("status_codes", {}).items())
    )

    ip_rows = "".join(
        f'<tr><td style="font-family:monospace">{item["ip"]}</td>'
        f'<td style="text-align:right;font-family:monospace">{item["count"]}</td></tr>'
        for item in data.get("top_ips", [])
    )

    bf_rows = "".join(
        f'<tr><td style="font-family:monospace;color:#ef4444">{s["ip"]}</td>'
        f'<td style="text-align:right">{s["auth_failures"]}</td>'
        f'<td style="text-align:right">{s["total_requests"]}</td>'
        f'<td style="text-align:right">{s["threat_score"]}/100</td></tr>'
        for s in data.get("brute_force", [])
    ) or '<tr><td colspan="4" style="text-align:center;color:#6b7280">Nenhum detectado</td></tr>'

    ddos_section = ""
    ddos_windows = data.get("ddos_windows", [])
    if ddos_windows:
        rows = "".join(
            f'<tr>'
            f'<td style="font-family:monospace">{w["start"]}</td>'
            f'<td style="font-family:monospace">{w["end"]}</td>'
            f'<td style="text-align:right;color:#ef4444;font-weight:600">{w["total_requests"]}</td>'
            f'<td style="text-align:right">{w["unique_ips"]}</td>'
            f'</tr>'
            for w in ddos_windows
        )
        ddos_section = f"""
        <div class="section">
          <h2>Detecção de DDoS / Flood</h2>
          <table><thead><tr><th>Início</th><th>Fim</th><th>Requisições</th><th>IPs únicos</th></tr></thead>
          <tbody>{rows}</tbody></table>
        </div>"""

    flagged_rows = "".join(
        f'<tr><td style="font-family:monospace">{e["ip"]}</td>'
        f'<td style="font-family:monospace;color:{status_color(e["status"])}">{e["status"]}</td>'
        f'<td style="font-family:monospace">{e["method"]}</td>'
        f'<td style="font-family:monospace;color:#ef4444">{e["path"]}</td></tr>'
        for e in data.get("flagged_paths", [])
    ) or '<tr><td colspan="4" style="text-align:center;color:#6b7280">Nenhum detectado</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<title>Log Report — {generated}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e2e5ec; padding: 40px 48px; max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 24px; font-weight: 600; margin-bottom: 4px; letter-spacing: -0.03em; }}
  h2 {{ font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; color: #6b7280; margin-bottom: 16px; }}
  .meta {{ color: #6b7280; font-size: 13px; margin-bottom: 40px; }}
  .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; letter-spacing: 0.05em; background: {level_color}18; color: {level_color}; border: 1px solid {level_color}30; margin-left: 10px; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 40px; }}
  .stat {{ background: #16191f; border: 1px solid #23272f; border-radius: 10px; padding: 18px 20px; }}
  .stat-val {{ font-size: 28px; font-weight: 700; font-family: monospace; letter-spacing: -0.03em; }}
  .stat-lbl {{ font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 4px; }}
  .section {{ background: #16191f; border: 1px solid #23272f; border-radius: 10px; padding: 24px; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 12px; color: #6b7280; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; border-bottom: 1px solid #23272f; }}
  td {{ padding: 9px 12px; border-bottom: 1px solid #1c2029; }}
  tr:last-child td {{ border-bottom: none; }}
  .footer {{ margin-top: 40px; color: #374151; font-size: 11px; font-family: monospace; }}
</style>
</head>
<body>
  <h1>Log Analyzer Report <span class="badge">{level}</span></h1>
  <p class="meta">Gerado em {generated} · {summary.get("parsed_entries", 0):,} entradas analisadas</p>

  <div class="stats">
    <div class="stat"><div class="stat-val" style="color:#22c55e">{summary.get("total_lines", 0):,}</div><div class="stat-lbl">Linhas totais</div></div>
    <div class="stat"><div class="stat-val" style="color:#3b82f6">{summary.get("unique_ips", 0):,}</div><div class="stat-lbl">IPs únicos</div></div>
    <div class="stat"><div class="stat-val" style="color:#ef4444">{summary.get("total_errors", 0):,}</div><div class="stat-lbl">Total erros</div></div>
    <div class="stat"><div class="stat-val" style="color:#f59e0b">{len(data.get("brute_force", []))}</div><div class="stat-lbl">Brute Force</div></div>
  </div>

  <div class="section">
    <h2>Status HTTP</h2>
    <table><thead><tr><th>Código</th><th style="text-align:right">Ocorrências</th></tr></thead>
    <tbody>{status_rows}</tbody></table>
  </div>

  <div class="section">
    <h2>Top IPs</h2>
    <table><thead><tr><th>IP</th><th style="text-align:right">Requisições</th></tr></thead>
    <tbody>{ip_rows}</tbody></table>
  </div>

  <div class="section">
    <h2>Brute Force</h2>
    <table><thead><tr><th>IP</th><th style="text-align:right">Falhas Auth</th><th style="text-align:right">Requisições</th><th style="text-align:right">Threat Score</th></tr></thead>
    <tbody>{bf_rows}</tbody></table>
  </div>

  {ddos_section}

  <div class="section">
    <h2>Paths Suspeitos</h2>
    <table><thead><tr><th>IP</th><th>Status</th><th>Método</th><th>Path</th></tr></thead>
    <tbody>{flagged_rows}</tbody></table>
  </div>

  <p class="footer">log-analyzer · github.com/Fish7w7/Log-Analyzer</p>
</body>
</html>"""


if __name__ == "__main__":
    print("\n  Log Analyzer — Web UI")
    print("  Acesse: http://localhost:5000\n")
    app.run(debug=True, port=5000)