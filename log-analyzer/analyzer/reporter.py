"""
Formata e exibe os resultados no terminal com cores ANSI.
Também exporta para JSON.
"""

import json
from .detector import AnalysisResult


# ─── Cores ANSI 
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"
    BG_RED  = "\033[41m"


def _bar(value: int, max_value: int, width: int = 30, color: str = C.CYAN) -> str:
    """Gera uma barra de progresso ASCII."""
    filled = int((value / max_value) * width) if max_value > 0 else 0
    bar = "█" * filled + "░" * (width - filled)
    return f"{color}{bar}{C.RESET}"


def _status_color(code: str) -> str:
    c = int(code)
    if c >= 500: return C.RED
    if c >= 400: return C.YELLOW
    if c >= 300: return C.BLUE
    return C.GREEN


def _threat_color(level: str) -> str:
    return {
        "SECURE":   C.GREEN,
        "WARNING":  C.YELLOW,
        "CRITICAL": C.RED,
    }.get(level, C.WHITE)


def _divider(char: str = "─", width: int = 60) -> str:
    return C.DIM + char * width + C.RESET


# ─── Seções do relatório 

def print_header(filepath: str) -> None:
    print()
    print(f"{C.CYAN}{C.BOLD}{'═' * 60}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  LOG/ANALYZER  —  Security Intelligence{C.RESET}")
    print(f"{C.DIM}  Arquivo: {filepath}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'═' * 60}{C.RESET}")
    print()


def print_summary(result: AnalysisResult, bf_threshold: int) -> None:
    level = result.threat_level(bf_threshold)
    color = _threat_color(level)

    print(f"{C.BOLD}[ RESUMO GERAL ]{C.RESET}")
    print(_divider())
    print(f"  Linhas totais    : {C.WHITE}{result.total_lines:,}{C.RESET}")
    print(f"  Entradas válidas : {C.WHITE}{result.parsed_entries:,}{C.RESET}")
    print(f"  IPs únicos       : {C.CYAN}{result.unique_ips:,}{C.RESET}")
    print(f"  Total de erros   : {C.YELLOW}{result.total_errors:,}{C.RESET}")
    print(f"  Nível de ameaça  : {color}{C.BOLD} {level} {C.RESET}")
    print()


def print_top_ips(result: AnalysisResult) -> None:
    top = result.top_ips
    if not top:
        return

    max_count = top[0][1]
    print(f"{C.BOLD}[ TOP IPs POR REQUISIÇÕES ]{C.RESET}")
    print(_divider())

    for i, (ip, count) in enumerate(top, 1):
        stats = result.ip_stats.get(ip)
        bar = _bar(count, max_count, width=25, color=C.CYAN if i > 1 else C.RED)
        fails = f"{C.RED}⚠ {stats.auth_failures} falhas{C.RESET}" if stats and stats.auth_failures > 0 else ""
        print(f"  {C.DIM}#{i:<2}{C.RESET} {C.WHITE}{ip:<18}{C.RESET} {bar} {C.YELLOW}{count:>5}{C.RESET} reqs  {fails}")

    print()


def print_status_codes(result: AnalysisResult) -> None:
    print(f"{C.BOLD}[ STATUS HTTP ]{C.RESET}")
    print(_divider())

    total = result.parsed_entries or 1
    for code, count in sorted(result.status_counter.items()):
        color = _status_color(code)
        bar = _bar(count, total, width=20, color=color)
        label = {
            "2": "Sucesso  ",
            "3": "Redirect ",
            "4": "Erro CLI ",
            "5": "Erro SRV ",
        }.get(code[0], "         ")
        print(f"  {color}{code}{C.RESET} {C.DIM}{label}{C.RESET} {bar} {count:>5}x")

    print()


def print_brute_force(result: AnalysisResult, threshold: int) -> None:
    alerts = [s for s in result.brute_force_ips if s.auth_failures >= threshold]

    print(f"{C.BOLD}[ DETECÇÃO DE BRUTE FORCE ]{C.RESET}  {C.DIM}(threshold: {threshold} falhas){C.RESET}")
    print(_divider())

    if not alerts:
        print(f"  {C.GREEN}✓ Nenhum ataque de brute force detectado.{C.RESET}")
    else:
        for stats in alerts:
            score = stats.threat_score()
            score_color = C.RED if score > 60 else C.YELLOW
            print(f"  {C.RED}{C.BOLD}⚠  {stats.ip}{C.RESET}")
            print(f"     Falhas de auth : {C.RED}{stats.auth_failures}{C.RESET}")
            print(f"     Requisições    : {stats.total_requests}")
            print(f"     Paths únicos   : {len(stats.unique_paths)}")
            print(f"     Threat score   : {score_color}{score}/100{C.RESET}")
            print()

    if not alerts:
        print()


def print_flagged(result: AnalysisResult) -> None:
    entries = result.flagged_entries[:20]  # limita a 20

    print(f"{C.BOLD}[ PATHS SUSPEITOS ]{C.RESET}  {C.DIM}(.env, /admin, wp-login, .git...){C.RESET}")
    print(_divider())

    if not entries:
        print(f"  {C.GREEN}✓ Nenhum path suspeito encontrado.{C.RESET}")
    else:
        print(f"  {C.DIM}{'IP':<18} {'Status':<8} {'Método':<8} Path{C.RESET}")
        print(f"  {C.DIM}{'─'*18} {'─'*6} {'─'*6} {'─'*30}{C.RESET}")
        for e in entries:
            sc = _status_color(str(e.status))
            print(f"  {C.YELLOW}{e.ip:<18}{C.RESET} {sc}{e.status:<8}{C.RESET} {C.DIM}{e.method:<8}{C.RESET} {C.RED}{e.path}{C.RESET}")

    print()


def print_scanners(result: AnalysisResult) -> None:
    if not result.scanner_entries:
        return

    print(f"{C.BOLD}[ SCANNERS DETECTADOS ]{C.RESET}  {C.DIM}(Hydra, sqlmap, Nikto...){C.RESET}")
    print(_divider())

    seen = set()
    for e in result.scanner_entries:
        key = (e.ip, e.agent)
        if key not in seen:
            seen.add(key)
            print(f"  {C.RED}⚠{C.RESET}  {C.WHITE}{e.ip:<18}{C.RESET}  {C.DIM}{e.agent[:50]}{C.RESET}")

    print()


def print_report(result: AnalysisResult, filepath: str, bf_threshold: int = 10) -> None:
    """Imprime o relatório completo no terminal."""
    print_header(filepath)
    print_summary(result, bf_threshold)
    print_top_ips(result)
    print_status_codes(result)
    print_brute_force(result, bf_threshold)
    print_flagged(result)
    print_scanners(result)
    print(_divider("═"))
    print()


def export_json(result: AnalysisResult, output_path: str) -> None:
    """Exporta o resultado completo como JSON."""
    data = {
        "summary": {
            "total_lines": result.total_lines,
            "parsed_entries": result.parsed_entries,
            "unique_ips": result.unique_ips,
            "total_errors": result.total_errors,
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
            for e in result.flagged_entries
        ],
        "scanners": [
            {"ip": e.ip, "agent": e.agent, "path": e.path}
            for e in result.scanner_entries
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"  {C.GREEN}✓ Relatório exportado: {output_path}{C.RESET}")