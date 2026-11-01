
import re
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
        print("Nenhuma falha encontrada.")

    print("\n--- Falhas por usuário ---")

    if stats["failed_users"]:
        for username, count in stats["failed_users"].most_common():
            print(f"{username}: {count} tentativa(s)")
    else:
        print("Nenhuma falha encontrada.")


def main():
    log_path = Path("examples/auth.log")

    if not log_path.is_file():
        print(f"Erro: arquivo '{log_path}' não encontrado.")
        return

    logs = read_log_file(log_path)

    stats = analyze_logs(logs)

    print(f"Arquivo analisado: {log_path}")
    print_report(stats)

if __name__ == "__main__":
    main()
