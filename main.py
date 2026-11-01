
import re
from pathlib import Path

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

def main():
    log_path = Path("examples/auth.log")

    if not log_path.is_file():
        print(f"Erro: arquivo '{log_path}' não encontrado.")
        return

    logs = read_log_file(log_path)

    print("=== LOG ANALYZER ===")
    print(f"Arquivo: {log_path}")
    print(f"Total de linhas: {len(logs)}\n")

    for log in logs:
        event = parse_log_entry(log)

        if event:
            print(event)
        else:
            print("Evento não reconhecido:", log.strip())

if __name__ == "__main__":
    main()
