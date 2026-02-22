from flask import Flask, render_template, request, jsonify
from analyzer import parse_text, analyze, export_json
import json, os, tempfile

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Recebe texto de log e retorna análise em JSON."""
    data = request.get_json()
    if not data or "content" not in data:
        return jsonify({"error": "Envie { content: '...' }"}), 400

    bf_threshold = int(data.get("threshold", 10))
    entries, total_lines = parse_text(data["content"])

    if not entries:
        return jsonify({"error": "Nenhuma entrada válida encontrada. Verifique o formato (Apache/Nginx)."}), 422

    result = analyze(entries, total_lines, bf_threshold=bf_threshold)

    return jsonify({
        "summary": {
            "total_lines": result.total_lines,
            "parsed_entries": result.parsed_entries,
            "unique_ips": result.unique_ips,
            "total_errors": result.total_errors,
            "threat_level": result.threat_level(bf_threshold),
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
    })


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """Recebe um arquivo .log via upload e analisa."""
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    file = request.files["file"]
    content = file.read().decode("utf-8", errors="replace")

    bf_threshold = int(request.form.get("threshold", 10))
    entries, total_lines = parse_text(content)
    if not entries:
        return jsonify({"error": "Nenhuma entrada válida encontrada."}), 422

    result = analyze(entries, total_lines, bf_threshold=bf_threshold)
    return jsonify({
        "summary": {
            "total_lines": result.total_lines,
            "parsed_entries": result.parsed_entries,
            "unique_ips": result.unique_ips,
            "total_errors": result.total_errors,
            "threat_level": result.threat_level(bf_threshold),
        },
        "status_codes": dict(result.status_counter),
        "methods": dict(result.method_counter),
        "top_ips": [{"ip": ip, "count": c} for ip, c in result.top_ips],
        "brute_force": [
            {"ip": s.ip, "auth_failures": s.auth_failures, "total_requests": s.total_requests,
             "unique_paths": len(s.unique_paths), "threat_score": s.threat_score()}
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
    })


@app.route("/api/sample")
def api_sample():
    """Retorna um log de exemplo gerado na hora."""
    import random
    from datetime import datetime, timedelta

    ips = ["192.168.1.10", "10.0.0.5", "203.0.113.42", "198.51.100.7"]
    attacker = "45.33.32.156"
    scanner  = "198.51.100.99"
    now = datetime.now()
    months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

    def ts():
        dt = now - timedelta(seconds=random.uniform(0, 86400))
        return f"{dt.day:02d}/{months[dt.month-1]}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"

    def line(ip, path, method, code, agent, size=500):
        return f'{ip} - - [{ts()}] "{method} {path} HTTP/1.1" {code} {size} "-" "{agent}"'

    lines = []
    agents = ['Mozilla/5.0 (Windows NT 10.0)', 'curl/7.88', 'python-requests/2.28']
    paths  = ["/", "/login", "/api/users", "/dashboard", "/static/app.js"]

    for _ in range(80):
        lines.append(line(random.choice(ips), random.choice(paths),
                         random.choice(["GET","POST"]),
                         random.choice([200,200,200,301,404,500]),
                         random.choice(agents), random.randint(200,8000)))

    for _ in range(40):
        lines.append(line(attacker, "/login", "POST", 401, "Hydra v9.4", 512))

    for p in ["/.env", "/wp-login.php", "/.git/config", "/admin/config", "/phpmyadmin"]:
        lines.append(line(scanner, p, "GET", 404, "sqlmap/1.7.8", 256))

    random.shuffle(lines)
    return jsonify({"content": "\n".join(lines)})


if __name__ == "__main__":
    print("\n  🔍 Log Analyzer — Web UI")
    print("  Acesse: http://localhost:5000\n")
    app.run(debug=True, port=5000)