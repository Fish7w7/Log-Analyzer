#!/usr/bin/env python3
"""
Gera um arquivo access.log de exemplo com tráfego realista + ataques simulados.

Uso:
    python sample/generate.py                    # padrão: 200 linhas
    python sample/generate.py --lines 500        # quantidade customizada
    python sample/generate.py --out meus.log     # arquivo de saída
    python sample/generate.py --no-attack        # só tráfego normal
    python sample/generate.py --seed 42          # resultado reproduzível
"""

import argparse
import os
import random
from datetime import datetime, timedelta


# ─── Dados de exemplo ────────────────────────────────────────────────────────

IPS_NORMAIS = [
    "192.168.1.10", "192.168.1.42", "10.0.0.5",  "10.0.0.17",
    "172.16.0.8",   "203.0.113.42", "198.51.100.7",
    "192.0.2.15",   "104.21.14.101","185.199.108.1",
]

IPS_ATACANTES = [
    ("45.33.32.156",   "Hydra v9.4",        401, "/login",       "brute_force"),
    ("193.32.160.143", "Medusa v2.2",        401, "/admin/login", "brute_force"),
]

IPS_SCANNERS = [
    ("198.51.100.99",  "sqlmap/1.7.8#stable"),
    ("45.142.212.100", "Nikto/2.1.6"),
]

PATHS_NORMAIS = [
    "/", "/index.html", "/about", "/contact", "/pricing",
    "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/login", "/logout", "/dashboard", "/profile",
    "/static/main.js", "/static/style.css", "/static/logo.png",
    "/favicon.ico", "/robots.txt",
]

PATHS_SUSPEITOS = [
    "/.env", "/.env.local", "/.env.production",
    "/wp-login.php", "/wp-admin/", "/wordpress/",
    "/admin/config", "/admin/setup",
    "/.git/config", "/.git/HEAD",
    "/phpmyadmin", "/pma/",
    "/etc/passwd", "/etc/shadow",
    "/shell.php", "/cmd.php", "/backdoor.php",
    "/xmlrpc.php",
]

METODOS          = ["GET", "GET", "GET", "GET", "POST", "PUT", "DELETE"]
CODES_NORMAIS    = [200, 200, 200, 200, 200, 301, 302, 304, 400, 404]
CODES_SERVER_ERR = [500, 502, 503]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]

MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]


# ─── Funções utilitárias ──────────────────────────────────────────────────────

def fmt_time(dt: datetime) -> str:
    return f"{dt.day:02d}/{MONTHS[dt.month-1]}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"


def make_line(ip: str, path: str, method: str, code: int, agent: str, size: int = 0) -> str:
    size = size or random.randint(180, 9500)
    dt   = datetime.now() - timedelta(seconds=random.uniform(0, 86400))
    return f'{ip} - - [{fmt_time(dt)}] "{method} {path} HTTP/1.1" {code} {size} "-" "{agent}"'


# ─── Geradores de tráfego ─────────────────────────────────────────────────────

def gen_normal(n: int) -> list[str]:
    """Tráfego legítimo variado."""
    lines = []
    for _ in range(n):
        lines.append(make_line(
            ip     = random.choice(IPS_NORMAIS),
            path   = random.choice(PATHS_NORMAIS),
            method = random.choice(METODOS),
            code   = random.choice(CODES_NORMAIS),
            agent  = random.choice(USER_AGENTS),
        ))
    return lines


def gen_brute_force(intensity: int = 40) -> list[str]:
    """Simula ataques de brute force de múltiplos IPs."""
    lines = []
    for ip, agent, code, path, _ in IPS_ATACANTES:
        count = random.randint(intensity // 2, intensity)
        for _ in range(count):
            lines.append(make_line(ip, path, "POST", code, agent, size=512))
    return lines


def gen_scanner(repeats: int = 3) -> list[str]:
    """Simula varredura de paths suspeitos."""
    lines = []
    for ip, agent in IPS_SCANNERS:
        paths = random.sample(PATHS_SUSPEITOS, k=min(len(PATHS_SUSPEITOS), 10)) * repeats
        for path in paths:
            lines.append(make_line(ip, path, "GET", random.choice([200, 403, 404]), agent, size=256))
    return lines


def gen_server_errors(n: int = 10) -> list[str]:
    """Simula alguns erros 5xx."""
    return [
        make_line(
            ip     = random.choice(IPS_NORMAIS),
            path   = random.choice(["/api/v1/users", "/api/v1/orders", "/dashboard"]),
            method = random.choice(["GET", "POST"]),
            code   = random.choice(CODES_SERVER_ERR),
            agent  = random.choice(USER_AGENTS),
        )
        for _ in range(n)
    ]


# ─── CLI 

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gera um access.log de exemplo para testar o Log Analyzer.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--lines",     type=int,   default=200,    help="Linhas de tráfego normal (padrão: 200)")
    parser.add_argument("--out",       type=str,   default=None,   help="Arquivo de saída (padrão: sample/access.log)")
    parser.add_argument("--no-attack", action="store_true",        help="Gerar apenas tráfego normal, sem ataques")
    parser.add_argument("--seed",      type=int,   default=None,   help="Seed para resultado reproduzível")
    parser.add_argument("--intensity", type=int,   default=40,     help="Intensidade do brute force (padrão: 40)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        print(f"  Seed: {args.seed}")

    # Monta as linhas
    all_lines: list[str] = gen_normal(args.lines)

    attack_summary = []
    if not args.no_attack:
        bf_lines = gen_brute_force(args.intensity)
        sc_lines = gen_scanner()
        er_lines = gen_server_errors()

        all_lines += bf_lines + sc_lines + er_lines

        for ip, _, _, _, kind in IPS_ATACANTES:
            attack_summary.append(f"brute force ({ip})")
        for ip, agent in IPS_SCANNERS:
            attack_summary.append(f"scanner ({ip} / {agent.split('/')[0]})")

    random.shuffle(all_lines)

    # Define saída
    if args.out:
        output = args.out
    else:
        output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "access.log")

    os.makedirs(os.path.dirname(output) if os.path.dirname(output) else ".", exist_ok=True)

    with open(output, "w", encoding="utf-8") as f:
        f.write("\n".join(all_lines) + "\n")

    # Relatório
    print(f"\n  ✓ Log gerado: {output}")
    print(f"  → {len(all_lines)} linhas no total")
    print(f"  → {args.lines} linhas de tráfego normal")

    if attack_summary:
        print(f"  → Ataques simulados:")
        for s in attack_summary:
            print(f"      • {s}")
    else:
        print(f"  → Sem ataques (--no-attack)")

    print(f"\n  Próximo passo:")
    print(f"    python cli.py {output}\n")


if __name__ == "__main__":
    main()