
from pathlib import Path

def read_log_file(file_path):
    # Leitura do arquivo log e retorna as linhas
    with open(file_path, "r", encoding="utf-8") as file:
        return file.readlines()

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
        print(log.strip())

if __name__ == "__main__":
    main()
