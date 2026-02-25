from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
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

DDOS_WINDOW_SECONDS = 60
DDOS_THRESHOLD_GLOBAL = 200
DDOS_THRESHOLD_PER_IP = 50


@dataclass
class IPStats:
    ip: str
    total_requests: int = 0
    auth_failures: int = 0
    server_errors: int = 0
    unique_paths: set = field(default_factory=set)
    methods: Counter = field(default_factory=Counter)
    status_codes: Counter = field(default_factory=Counter)

    def is_brute_force(self, threshold: int = 10):
        return self.auth_failures >= threshold

    def threat_score(self) -> int:
        score = 0
        score += min(self.auth_failures * 3, 60)
        score += min(len(self.unique_paths) // 5, 20)
        score += min(self.server_errors, 20)
        return min(score, 100)


@dataclass
class DDoSWindow:
    start: datetime
    end: datetime
    total_requests: int
    unique_ips: int
    top_ips: list


@dataclass
class AnalysisResult:
    total_lines: int = 0
    parsed_entries: int = 0
    status_counter: Counter = field(default_factory=Counter)
    method_counter: Counter = field(default_factory=Counter)
    ip_counter: Counter = field(default_factory=Counter)
    ip_stats: dict = field(default_factory=dict)
    brute_force_ips: list = field(default_factory=list)
    flagged_entries: list = field(default_factory=list)
    scanner_entries: list = field(default_factory=list)
    ddos_windows: list = field(default_factory=list)
    has_timestamps: bool = False

    @property
    def unique_ips(self) -> int:
        return len(self.ip_counter)

    @property
    def total_errors(self) -> int:
        return sum(v for k, v in self.status_counter.items() if int(k) >= 400)

    @property
    def top_ips(self) -> list:
        return self.ip_counter.most_common(10)

    def threat_level(self, bf_threshold: int = 10) -> str:
        bf_count = sum(1 for s in self.ip_stats.values() if s.auth_failures >= bf_threshold)
        has_ddos = len(self.ddos_windows) > 0
        if bf_count == 0 and not self.scanner_entries and not has_ddos:
            return "SECURE"
        if bf_count <= 1 and not has_ddos:
            return "WARNING"
        return "CRITICAL"


def _parse_timestamp(time_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except Exception:
        try:
            return datetime.strptime(time_str[:20], "%d/%b/%Y:%H:%M:%S")
        except Exception:
            return None


def _detect_ddos(entries: list) -> tuple:
    timed = []
    for e in entries:
        ts = _parse_timestamp(e.time)
        if ts:
            timed.append((ts, e.ip))

    if not timed:
        return [], False

    timed.sort(key=lambda x: x[0])
    windows = []
    n = len(timed)

    i = 0
    while i < n:
        window_start = timed[i][0]
        window_end_limit = window_start.replace(
            second=window_start.second,
            microsecond=0
        )
        j = i
        bucket_ips = []
        while j < n and (timed[j][0] - window_start).total_seconds() < DDOS_WINDOW_SECONDS:
            bucket_ips.append(timed[j][1])
            j += 1

        count = j - i
        if count >= DDOS_THRESHOLD_GLOBAL:
            ip_counts = Counter(bucket_ips)
            top = ip_counts.most_common(5)
            suspicious_ips = [ip for ip, c in ip_counts.items() if c >= DDOS_THRESHOLD_PER_IP]
            if count >= DDOS_THRESHOLD_GLOBAL or suspicious_ips:
                windows.append(DDoSWindow(
                    start=timed[i][0],
                    end=timed[j-1][0] if j > i else timed[i][0],
                    total_requests=count,
                    unique_ips=len(set(bucket_ips)),
                    top_ips=top,
                ))
        i += 1

    return windows, True


def analyze(entries: list, total_lines: int, bf_threshold: int = 10) -> AnalysisResult:
    result = AnalysisResult(
        total_lines=total_lines,
        parsed_entries=len(entries),
    )

    ip_map = defaultdict(lambda: IPStats(ip=""))

    for entry in entries:
        result.status_counter[str(entry.status)] += 1
        result.method_counter[entry.method] += 1
        result.ip_counter[entry.ip] += 1

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

        path_lower = entry.path.lower()
        if any(p in path_lower for p in SUSPICIOUS_PATHS):
            result.flagged_entries.append(entry)

        if entry.agent:
            agent_lower = entry.agent.lower()
            if any(s in agent_lower for s in KNOWN_SCANNERS):
                result.scanner_entries.append(entry)

    result.ip_stats = dict(ip_map)

    result.brute_force_ips = [
        stats for stats in ip_map.values()
        if stats.auth_failures >= bf_threshold
    ]
    result.brute_force_ips.sort(key=lambda s: s.auth_failures, reverse=True)

    ddos_windows, has_ts = _detect_ddos(entries)
    result.ddos_windows = ddos_windows
    result.has_timestamps = has_ts

    return result