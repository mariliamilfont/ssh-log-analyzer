# SSH Log Analyzer

A simple Python command-line tool for analyzing Linux SSH authentication logs. It identifies successful and failed authentication attempts, extracts relevant information, generates statistics, and exports reports to CSV files.

This project was developed as part of the LARCES laboratory onboarding, with the goal of practicing Python, Linux, and Git.

## Features

- Read SSH authentication log files.
- Identify successful and failed authentication attempts.
- Extract timestamps, usernames, source IP addresses, and authentication methods.
- Count successful and failed authentications.
- Identify IP addresses and users associated with failed attempts.
- Display authentication statistics in the terminal.
- Export analysis results to CSV files.
- Accept custom log file paths through command-line arguments.

## Technologies

- Python 3
- Python Standard Library (`argparse`, `csv`, `re`, `pathlib`, `collections`)
- Git

No external Python dependencies are required.

## Project Structure

```text
ssh-log-analyzer/
├── examples/
│   └── auth.log
├── output/
│   └── .gitkeep
├── main.py
├── .gitignore
└── README.md
```

The `output/` directory stores generated CSV reports, which are ignored by Git.

## Requirements

- Python 3 installed
- A terminal (Linux recommended)
- An SSH authentication log file in a supported format

## How to Run

1. Clone the repository:

```bash
git clone https://github.com/mariliamilfont/ssh-log-analyzer.git
cd ssh-log-analyzer
```

2. Run the analyzer with the default example file:

```bash
python3 main.py
```

3. Alternatively, specify a custom log file:

```bash
python3 main.py examples/auth.log
```

4. Display the available command-line options:

```bash
python3 main.py --help
```

## Example Output

```text
Arquivo analisado: examples/auth.log

=== SSH AUTHENTICATION REPORT ===
Total de eventos: 10
Autenticações bem-sucedidas: 4
Tentativas malsucedidas: 6

--- Falhas por endereço IP ---
192.168.1.10: 4 tentativa(s)
192.168.1.15: 2 tentativa(s)

--- Falhas por usuário ---
admin: 4 tentativa(s)
root: 2 tentativa(s)

Relatórios CSV gerados com sucesso
- output/auth_summary.csv
- output/failed_attempts.csv
```

## Generated Reports

The analyzer generates two CSV files:

**`auth_summary.csv`**

Contains the total number of recognized authentication events, successful authentications, and failed authentications.

**`failed_attempts.csv`**

Contains the number of failed authentication attempts grouped by source IP address and username.

Both files are saved in the `output/` directory.

## Limitations

- The analyzer currently supports a limited set of SSH authentication log formats.
- It recognizes `Failed password`, `Accepted password`, and `Accepted publickey` events matching the implemented pattern.
- Unsupported log entries are ignored when calculating statistics.
- The tool does not detect or confirm security incidents.
- The generated reports are overwritten on each execution.

## Purpose

This project demonstrates basic Python scripting, file processing, regular expressions, command-line arguments, CSV generation, and Git version control.

It is intended for educational purposes and can be extended to support additional log formats and security analysis features.
