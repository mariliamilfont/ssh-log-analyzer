
import re
import csv
import argparse
from pathlib import Path
from collections import Counter

def read_log_file(file_path):
    # Leitura do arquivo log e retorna as linhas
    with open(file_path, "r", encoding="utf-8") as file:
        return file.readlines()

def parse_log_entry(log):
    # Extrai infos de um evento de auth SSH

    pattern = (
        r"^(\w+\s+\d+\s+\d+:\d+:\d+)"
        r"\s+\S+\s+sshd\[\d+\]:\s+"
        r"(Failed|Accepted)\s+(password|publickey)"
        r"\s+for\s+(\S+)\s+from\s+(\S+)"
    )

    match = re.search(pattern, log)

    if not match:
        return None

    timestamp, status, auth_method, username, ip = match.groups()

    return {
        "timestamp": timestamp,
        "status": "failed" if status == "Failed" else "success",
        "auth_method": auth_method,
        "username": username,
        "ip": ip,
    }

def analyze_logs(logs):
    # Analisa eventos SSH e gera estatísticas

    stats = {
        "total": 0,
        "success": 0,
        "failed": 0,
        "failed_ips": Counter(),
        "failed_users": Counter(),
    }

    for log in logs:
        event = parse_log_entry(log)

        if event is None:
            continue

        stats["total"] += 1

        if event["status"] == "success":
            stats["success"] += 1

        elif event["status"] == "failed":
            stats["failed"] += 1
            stats["failed_ips"][event["ip"]] += 1
            stats["failed_users"][event["username"]] += 1

    return stats

def print_report(stats):
    # Exibe relatório de auth

    print("\n=== SSH AUTHENTICATION REPORT ===")

    print(f"Total de eventos: {stats['total']}")
    print(f"Autenticações bem-sucedidas: {stats['success']}")
    print(f"Tentativas malsucedidas: {stats['failed']}")

    print("\n--- Falhas por endereço IP ---")

    if stats["failed_ips"]:
        for ip, count in stats["failed_ips"].most_common():
            print(f"{ip}: {count} tentativa(s)")
    else:
        print("Nenhuma falha encontrada")

    print("\n--- Falhas por usuário ---")

    if stats["failed_users"]:
        for username, count in stats["failed_users"].most_common():
            print(f"{username}: {count} tentativa(s)")
    else:
        print("Nenhuma falha encontrada")

def export_to_csv(stats, output_dir="output"):
    # Exporta as estatísticas de auth para aquivos CSV

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Resumo geral das autenticações
    summary_file = output_path / "auth_summary.csv"

    with open(summary_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(["metric", "count"])
        writer.writerow(["total_events", stats["total"]])
        writer.writerow(["successful_authentications", stats["success"]])
        writer.writerow(["failed_authentications", stats["failed"]])

    # Quantidade de falhas por IP e usuário
    failed_file = output_path / "failed_attempts.csv"

    with open(failed_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(["type", "value", "count"])

        for ip, count in stats["failed_ips"].most_common():
            writer.writerow(["ip", ip, count])

        for username, count in stats["failed_users"].most_common():
            writer.writerow(["username", username, count])

    print("\nRelatórios CSV gerados com sucesso")
    print(f"- {summary_file}")
    print(f"- {failed_file}")

def parse_arguments():
    # Processa argumentos recebidos pela linha de comando

    parser = argparse.ArgumentParser(
        description="Analyze SSH authentication logs and generate reports"
    )

    parser.add_argument(
        "log_file",
        type=Path,
        nargs="?",
        default=Path("examples/auth.log"),
        help="Path to the SSH log file (default: examples/auth.log)"
    )

    return parser.parse_args()

def main():
    args = parse_arguments()
    log_path = args.log_file

    if not log_path.is_file():
        print(f"Erro: arquivo '{log_path}' não encontrado")
        return

    try:
        logs = read_log_file(log_path)
    except (OSError, UnicodeError) as error:
        print(f"Erro ao ler o arquivo: {error}")
        return

    stats = analyze_logs(logs)

    print(f"Arquivo analisado: {log_path}")
    print_report(stats)

    try:
        export_to_csv(stats)
    except OSError as error:
        print(f"Erro ao exportar os relatórios: {error}")

if __name__ == "__main__":
    main()
