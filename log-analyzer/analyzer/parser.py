"""
Responsável por ler e transformar linhas de log em dados estruturados.
"""

import re
from dataclasses import dataclass
from typing import Optional


# Suporta formato Apache e Nginx access log
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)


@dataclass
class LogEntry:
    ip: str
    time: str
    method: str
    path: str
    status: int
    size: int
    agent: Optional[str] = None

    def is_error(self):
        return self.status >= 400

    def is_auth_failure(self):
        return self.status in (401, 403)

    def is_server_error(self):
        return self.status >= 500


def parse_line(line: str) -> Optional[LogEntry]:
    """Parseia uma linha de log. Retorna None se o formato não bater."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    return LogEntry(
        ip=match.group("ip"),
        time=match.group("time"),
        method=match.group("method"),
        path=match.group("path"),
        status=int(match.group("status")),
        size=int(match.group("size")),
        agent=match.group("agent"),
    )


def parse_file(filepath: str) -> tuple[list[LogEntry], int]:
    """
    Lê um arquivo .log e retorna (entradas parseadas, total de linhas).
    Linhas inválidas são silenciosamente ignoradas.
    """
    entries = []
    total_lines = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            entry = parse_line(line)
            if entry:
                entries.append(entry)

    return entries, total_lines


def parse_text(text: str) -> tuple[list[LogEntry], int]:
    """Mesma coisa que parse_file, mas recebe o texto diretamente."""
    entries = []
    lines = text.strip().splitlines()

    for line in lines:
        entry = parse_line(line)
        if entry:
            entries.append(entry)

    return entries, len(lines)