"""
Motor de detecção: conta IPs, detecta brute force, paths suspeitos, etc.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional
from .parser import LogEntry


SUSPICIOUS_PATHS = [
    ".env", "wp-login", "/admin", "config", "passwd",
    "shadow", ".git", "/.ssh", "phpmyadmin", "xmlrpc",
    "/etc/", "cmd.exe", "shell.php",
]

KNOWN_SCANNERS = [
    "hydra", "sqlmap", "nikto", "masscan", "zgrab",
    "nmap", "dirbuster", "gobuster", "wfuzz",
]


@dataclass
class IPStats:
    ip: str
    total_requests: int = 0
    auth_failures: int = 0      # 401 + 403
    server_errors: int = 0      # 5xx
    unique_paths: set = field(default_factory=set)
    methods: Counter = field(default_factory=Counter)
    status_codes: Counter = field(default_factory=Counter)

    def is_brute_force(self, threshold: int = 10):
        return self.auth_failures >= threshold

    def threat_score(self) -> int:
        """Score simples de 0-100 indicando suspeita."""
        score = 0
        score += min(self.auth_failures * 3, 60)
        score += min(len(self.unique_paths) // 5, 20)
        score += min(self.server_errors, 20)
        return min(score, 100)


@dataclass
class AnalysisResult:
    # Meta
    total_lines: int = 0
    parsed_entries: int = 0

    # Contagens gerais
    status_counter: Counter = field(default_factory=Counter)
    method_counter: Counter = field(default_factory=Counter)
    ip_counter: Counter = field(default_factory=Counter)

    # Detalhes por IP
    ip_stats: dict[str, IPStats] = field(default_factory=dict)

    # Detecções
    brute_force_ips: list[IPStats] = field(default_factory=list)
    flagged_entries: list[LogEntry] = field(default_factory=list)
    scanner_entries: list[LogEntry] = field(default_factory=list)

    @property
    def unique_ips(self) -> int:
        return len(self.ip_counter)

    @property
    def total_errors(self) -> int:
        return sum(v for k, v in self.status_counter.items() if int(k) >= 400)

    @property
    def top_ips(self) -> list[tuple[str, int]]:
        return self.ip_counter.most_common(10)

    def threat_level(self, bf_threshold: int = 10) -> str:
        bf_count = sum(1 for s in self.ip_stats.values() if s.auth_failures >= bf_threshold)
        if bf_count == 0 and not self.scanner_entries:
            return "SECURE"
        if bf_count <= 1:
            return "WARNING"
        return "CRITICAL"


def analyze(entries: list[LogEntry], total_lines: int, bf_threshold: int = 10) -> AnalysisResult:
    """
    Recebe lista de LogEntry e retorna um AnalysisResult completo.
    Essa função é o coração do analisador.
    """
    result = AnalysisResult(
        total_lines=total_lines,
        parsed_entries=len(entries),
    )

    ip_map: dict[str, IPStats] = defaultdict(lambda: IPStats(ip=""))

    for entry in entries:
        # Contadores globais
        result.status_counter[str(entry.status)] += 1
        result.method_counter[entry.method] += 1
        result.ip_counter[entry.ip] += 1

        # Stats por IP
        stats = ip_map[entry.ip]
        stats.ip = entry.ip
        stats.total_requests += 1
        stats.status_codes[str(entry.status)] += 1
        stats.methods[entry.method] += 1
        stats.unique_paths.add(entry.path)

        if entry.is_auth_failure():
            stats.auth_failures += 1
        if entry.is_server_error():
            stats.server_errors += 1

        # Paths suspeitos
        path_lower = entry.path.lower()
        if any(p in path_lower for p in SUSPICIOUS_PATHS):
            result.flagged_entries.append(entry)

        # User-agents de scanners conhecidos
        if entry.agent:
            agent_lower = entry.agent.lower()
            if any(s in agent_lower for s in KNOWN_SCANNERS):
                result.scanner_entries.append(entry)

    result.ip_stats = dict(ip_map)

    # Brute force: IPs com muitas falhas de autenticação
    result.brute_force_ips = [
        stats for stats in ip_map.values()
        if stats.auth_failures >= bf_threshold
    ]
    result.brute_force_ips.sort(key=lambda s: s.auth_failures, reverse=True)

    return result