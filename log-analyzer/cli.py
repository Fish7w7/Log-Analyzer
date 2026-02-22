#!/usr/bin/env python3
"""
cli.py  —  Log Analyzer CLI
"""

import argparse
import sys
import os
from analyzer import parse_file, analyze, print_report, export_json


def main():
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="🔍 Analisa arquivos .log e detecta padrões de ataque",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "logfile",
        help="Caminho para o arquivo .log (Apache/Nginx)"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=10,
        metavar="N",
        help="Número mínimo de falhas para detectar brute force (padrão: 10)"
    )
    parser.add_argument(
        "--export", "-e",
        metavar="ARQUIVO.json",
        help="Exporta o relatório completo para JSON"
    )
    parser.add_argument(
        "--top", "-n",
        type=int,
        default=10,
        metavar="N",
        help="Quantos IPs mostrar no ranking (padrão: 10)"
    )

    args = parser.parse_args()

    # Valida arquivo
    if not os.path.isfile(args.logfile):
        print(f"\n  ✗ Arquivo não encontrado: {args.logfile}\n", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Carregando {args.logfile}...")

    # Pipeline: parse → analyze → report
    entries, total_lines = parse_file(args.logfile)

    if not entries:
        print("\n  ✗ Nenhuma entrada válida encontrada no arquivo.")
        print("    Verifique se é um log Apache/Nginx no formato padrão.\n")
        sys.exit(1)

    result = analyze(entries, total_lines, bf_threshold=args.threshold)

    print_report(result, args.logfile, bf_threshold=args.threshold)

    if args.export:
        export_json(result, args.export)


if __name__ == "__main__":
    main()