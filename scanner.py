import click
import json
import os
import re
from scapy.all import rdpcap

header = """
██╗░░░░░░█████╗░░██████╗░  ░█████╗░███╗░░██╗░█████╗░██╗░░░░░██╗░░░██╗███████╗███████╗██████╗░
██║░░░░░██╔══██╗██╔════╝░  ██╔══██╗████╗░██║██╔══██╗██║░░░░░╚██╗░██╔╝╚════██║██╔════╝██╔══██╗
██║░░░░░██║░░██║██║░░██╗░  ███████║██╔██╗██║███████║██║░░░░░░╚████╔╝░░░███╔═╝█████╗░░██████╔╝
██║░░░░░██║░░██║██║░░╚██╗  ██╔══██║██║╚████║██╔══██║██║░░░░░░░╚██╔╝░░██╔══╝░░██╔══╝░░██╔══██╗
███████╗╚█████╔╝╚██████╔╝  ██║░░██║██║░╚███║██║░░██║███████╗░░░██║░░░███████╗███████╗██║░░██║
╚══════╝░╚════╝░░╚═════╝░  ╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚══════╝╚══════╝╚═╝░░╚═╝

Tool: Vulnerability Scanner
Version: 1.0
author : PSYKO

"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Fonction pour afficher l'en-tête
def print_header():
    clear_screen()
    click.echo(header)

# Fonction principale pour le script
@click.command()
@click.option('--scan-type', '-s', type=click.Choice(['log', 'pcap']), help='Type of file to scan (log or pcap)')
@click.option('--file-path', '-f', type=click.Path(exists=True), help='Path to the file to scan')
@click.option('--output', '-o', default=None, help='Path to save the report')
def scan_file(scan_type, file_path, output):
    """
    Scan files for vulnerabilities and output results.

    Args:
        scan_type (str): Type of file to scan ('log' or 'pcap').
        file_path (str): Path to the file to analyze.
        output (str): Path to output file (.txt).
    """
    print_header()

    if scan_type == 'log':
        vulnerabilities = analyze_log(file_path)
    elif scan_type == 'pcap':
        vulnerabilities = analyze_pcap(file_path)
    else:
        click.echo("Unsupported scan type. Choose 'log' or 'pcap'.")
        return

    # Convertir les résultats en JSON formaté
    json_results = json.dumps(vulnerabilities, indent=4)

    # Écrire les résultats dans le fichier de sortie si spécifié
    if output:
        with open(output, 'w') as report_file:
            report_file.write(json_results)
        click.echo(f"Scan completed. Report saved to {output}")
    else:
        click.echo("Scan completed. Results:")
        click.echo(json_results)

def analyze_log(filepath):
    vulnerabilities = {
        "errors": [],
        "warnings": [],
        "unauthorized_access": [],
        "possible_sql_injections": [],
        "server_errors": [],
        "access_denied": [],
        "brute_force_attempts": [],
        "buffer_overflows": [],
        "command_injections": [],
        "session_hijacking": [],
        "xss_attempts": [],
        "path_traversal": [],
        "csrf_attempts": [],
        "dos_attempts": [],
        "json_vulnerabilities": []  # Added key for JSON vulnerabilities
    }

    # SQL Injection patterns
    sql_injection_patterns = [
        re.compile(r"SELECT\s+.*\s+FROM\s+.*", re.IGNORECASE),
        re.compile(r"INSERT\s+INTO\s+.*\s+VALUES\s+.*", re.IGNORECASE),
        re.compile(r"UPDATE\s+.*\s+SET\s+.*", re.IGNORECASE),
        re.compile(r"DELETE\s+FROM\s+.*", re.IGNORECASE),
        re.compile(r"DROP\s+TABLE\s+.*", re.IGNORECASE),
        re.compile(r"UNION\s+ALL\s+SELECT", re.IGNORECASE),
        re.compile(r"OR\s+1=1", re.IGNORECASE),
        re.compile(r"AND\s+1=1", re.IGNORECASE),
        re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),  # Example: BENCHMARK(1000000,MD5(1))
        re.compile(r"EXEC\s*\(", re.IGNORECASE),       # Example: EXEC sp_executesql N'SELECT * FROM sys.tables'
        re.compile(r"sysobjects\s*\.type\s*=\s*N", re.IGNORECASE)  # Example: sysobjects.type=N'U'
    ]

    # Command Injection patterns
    command_injection_patterns = [
        re.compile(r";", re.IGNORECASE),
        re.compile(r"\|\s*cat", re.IGNORECASE),
        re.compile(r"\|\s*more", re.IGNORECASE),
        re.compile(r"\|\s*less", re.IGNORECASE),
        re.compile(r"\$\(", re.IGNORECASE),
        re.compile(r"`", re.IGNORECASE),
        re.compile(r"&&", re.IGNORECASE),
        re.compile(r"\|\|", re.IGNORECASE),
        re.compile(r"=\|", re.IGNORECASE)
    ]

    # XSS patterns
    xss_patterns = [
        re.compile(r"<script>", re.IGNORECASE),
        re.compile(r"onmouseover\s*=", re.IGNORECASE),
        re.compile(r"onerror\s*=", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"alert\s*\(", re.IGNORECASE),
        re.compile(r"document\.cookie", re.IGNORECASE),
        re.compile(r"<img\s+src\s*=", re.IGNORECASE),
        re.compile(r"eval\s*\(", re.IGNORECASE),
        re.compile(r"expression\s*\(", re.IGNORECASE),
        re.compile(r"setTimeout\s*\(", re.IGNORECASE),
        re.compile(r"setInterval\s*\(", re.IGNORECASE)
    ]

    # Path Traversal patterns
    path_traversal_patterns = [
        re.compile(r"\.\./\.\.", re.IGNORECASE),
        re.compile(r"%2e%2e/%2e%2e", re.IGNORECASE),
        re.compile(r"etc/passwd", re.IGNORECASE),
        re.compile(r"windows\\system32", re.IGNORECASE),
        re.compile(r"\.\./", re.IGNORECASE),
        re.compile(r"%2e%2e/", re.IGNORECASE),
        re.compile(r"../../", re.IGNORECASE),
        re.compile(r"..%2f", re.IGNORECASE),
        re.compile(r"..\\..\\..\\..\\", re.IGNORECASE),
        re.compile(r"%c0%ae%c0%ae", re.IGNORECASE)
    ]

    # CSRF patterns
    csrf_patterns = [
        re.compile(r"csrf_token", re.IGNORECASE),
        re.compile(r"anti_csrf_token", re.IGNORECASE),
        re.compile(r"_csrf=", re.IGNORECASE),
        re.compile(r"csrfmiddlewaretoken", re.IGNORECASE)
    ]

    # Brute Force patterns
    brute_force_patterns = [
        re.compile(r"failed login", re.IGNORECASE),
        re.compile(r"too many login attempts", re.IGNORECASE),
        re.compile(r"password\s+attempt", re.IGNORECASE),
        re.compile(r"Brute force attempt", re.IGNORECASE),
        re.compile(r"Invalid password for", re.IGNORECASE),
        re.compile(r"Authentication failure", re.IGNORECASE)
    ]

    # Buffer Overflow patterns
    buffer_overflow_patterns = [
        re.compile(r"Segmentation fault", re.IGNORECASE),
        re.compile(r"buffer overflow detected", re.IGNORECASE),
        re.compile(r"stack smashing detected", re.IGNORECASE),
        re.compile(r"overwritten\s+buffer", re.IGNORECASE),
        re.compile(r"BOF\s+attempt", re.IGNORECASE),
        re.compile(r"memory corruption", re.IGNORECASE),
        re.compile(r"exploit attempt", re.IGNORECASE),
        re.compile(r"exploit behavior", re.IGNORECASE)
    ]

    # Session Hijacking patterns
    session_hijacking_patterns = [
        re.compile(r"session\s+hijack", re.IGNORECASE),
        re.compile(r"stolen session", re.IGNORECASE),
        re.compile(r"session\s+hijacking", re.IGNORECASE),
        re.compile(r"session\s+fixation", re.IGNORECASE)
    ]

    # DOS patterns
    dos_patterns = [
        re.compile(r"denial of service", re.IGNORECASE),
        re.compile(r"DDoS", re.IGNORECASE),
        re.compile(r"DOS\s+attack", re.IGNORECASE),
        re.compile(r"denial of service\s+attack", re.IGNORECASE)
    ]

    # JSON patterns
    json_patterns = [
        re.compile(r"((http|https)://.*\.[a-zA-Z]{2,})/(.*)?\.json", re.IGNORECASE),
        re.compile(r"\"url\":\s*\"https?://[^\"]+?\.json\"", re.IGNORECASE),
        re.compile(r"\"https?://[^\"]+?\.json\"", re.IGNORECASE),
        re.compile(r"\"[a-zA-Z0-9\-_]+\.json\"", re.IGNORECASE),
        re.compile(r"\b\"[a-zA-Z0-9\-_]+\.json\"", re.IGNORECASE)
    ]

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            line = line.strip()

            # Check for SQL Injection attempts
            for pattern in sql_injection_patterns:
                if pattern.search(line):
                    vulnerabilities['possible_sql_injections'].append(line)
                    break

            # Check for Command Injection attempts
            for pattern in command_injection_patterns:
                if pattern.search(line):
                    vulnerabilities['command_injections'].append(line)
                    break

            # Check for XSS attempts
            for pattern in xss_patterns:
                if pattern.search(line):
                    vulnerabilities['xss_attempts'].append(line)
                    break

            # Check for Path Traversal attempts
            for pattern in path_traversal_patterns:
                if pattern.search(line):
                    vulnerabilities['path_traversal'].append(line)
                    break

            # Check for CSRF attempts
            for pattern in csrf_patterns:
                if pattern.search(line):
                    vulnerabilities['csrf_attempts'].append(line)
                    break

            # Check for Brute Force attempts
            for pattern in brute_force_patterns:
                if pattern.search(line):
                    vulnerabilities['brute_force_attempts'].append(line)
                    break

            # Check for Buffer Overflow attempts
            for pattern in buffer_overflow_patterns:
                if pattern.search(line):
                    vulnerabilities['buffer_overflows'].append(line)
                    break

            # Check for Session Hijacking attempts
            for pattern in session_hijacking_patterns:
                if pattern.search(line):
                    vulnerabilities['session_hijacking'].append(line)
                    break

            # Check for DOS attempts
            for pattern in dos_patterns:
                if pattern.search(line):
                    vulnerabilities['dos_attempts'].append(line)
                    break

            # Check for JSON vulnerabilities
            for pattern in json_patterns:
                if pattern.search(line):
                    vulnerabilities['json_vulnerabilities'].append(line)
                    break

    return vulnerabilities


def analyze_pcap(filepath):
    vulnerabilities = {
        "open_ports": [],
        "suspicious_traffic": [],
        "dos_attacks": [],
        "brute_force_attempts": [],
        "tcp_injections": [],
        "dns_spoofing": [],
        "arp_poisoning": [],
        "ssl_attacks": []
    }

    packets = rdpcap(filepath)

    for packet in packets:
        # You can implement your packet analysis here
        pass

    return vulnerabilities

if __name__ == '__main__':
    scan_file()
