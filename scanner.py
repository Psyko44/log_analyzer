import click
import json
import os
import re
import pyshark

header = """
██╗░░░░░░█████╗░░██████╗░  ░█████╗░███╗░░██╗░█████╗░██╗░░░░░██╗░░░██╗███████╗███████╗██████╗░
██║░░░░░██╔══██╗██╔════╝░  ██╔══██╗████╗░██║██╔══██╗██║░░░░░╚██╗░██╔╝╚════██║██╔════╝██╔══██╗
██║░░░░░██║░░██║██║░░██╗░  ███████║██╔██╗██║███████║██║░░░░░░╚████╔╝░░░███╔═╝█████╗░░██████╔╝
██║░░░░░██║░░██║██║░░╚██╗  ██╔══██║██║╚████║██╔══██║██║░░░░░░░╚██╔╝░░██╔══╝░░██╔══╝░░██╔══██╗
███████╗╚█████╔╝╚██████╔╝  ██║░░██║██║░╚███║██║░░██║███████╗░░░██║░░░███████╗███████╗██║░░██║
╚══════╝░╚════╝░░╚═════╝░  ╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚══════╝╚══════╝╚═╝░░╚═╝

Tool: Advanced Vulnerability Scanner
Version: 2.0
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
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose mode')
def scan_file(scan_type, file_path, output, verbose):
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
        "json_vulnerabilities": [],
        "sensitive_data_exposure": [],  # Added for sensitive data exposure
        "remote_code_execution": [],  # Added for remote code execution
        "crypto_vulnerabilities": [],  # Added for cryptographic vulnerabilities
        "authorization_flaws": [],  # Added for authorization flaws
        "business_logic_errors": []  # Added for business logic errors
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
        re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),
        re.compile(r"EXEC\s*\(", re.IGNORECASE),
        re.compile(r"sysobjects\s*\.type\s*=\s*N", re.IGNORECASE),
        re.compile(r"sys\.columns", re.IGNORECASE),  # Added for SQL Injection
        re.compile(r"pg_tables", re.IGNORECASE),  # Added for SQL Injection
        re.compile(r"WHERE 1=1", re.IGNORECASE),  # Added for SQL Injection
        re.compile(r"UNION SELECT", re.IGNORECASE),  # Added for SQL Injection
        re.compile(r"GROUP BY \d", re.IGNORECASE)  # Added for SQL Injection
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
        re.compile(r"=\|", re.IGNORECASE),
        re.compile(r"runas\s*/user:", re.IGNORECASE),  # Added for Command Injection
        re.compile(r"local.service\s+stop", re.IGNORECASE),  # Added for Command Injection
        re.compile(r"cmd.exe", re.IGNORECASE),  # Added for Command Injection
        re.compile(r"bash -c", re.IGNORECASE)  # Added for Command Injection
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
        re.compile(r"setInterval\s*\(", re.IGNORECASE),
        re.compile(r"document\.write\s*\(", re.IGNORECASE),  # Added for XSS
        re.compile(r"location\.replace\s*\(", re.IGNORECASE),  # Added for XSS
        re.compile(r"innerHTML\s*=", re.IGNORECASE)  # Added for XSS
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
        re.compile(r"%c0%ae%c0%ae", re.IGNORECASE),
        re.compile(r"\$\{", re.IGNORECASE),  # Added for Path Traversal
        re.compile(r"\%00", re.IGNORECASE)  # Added for Path Traversal
    ]

    # CSRF patterns
    csrf_patterns = [
        re.compile(r"csrf_token", re.IGNORECASE),
        re.compile(r"anti_csrf_token", re.IGNORECASE),
        re.compile(r"_csrf=", re.IGNORECASE),
        re.compile(r"csrfmiddlewaretoken", re.IGNORECASE),
        re.compile(r"X-Requested-With", re.IGNORECASE)  # Added for CSRF
    ]

    # Brute Force patterns
    brute_force_patterns = [
        re.compile(r"failed login", re.IGNORECASE),
        re.compile(r"too many login attempts", re.IGNORECASE),
        re.compile(r"password\s+attempt", re.IGNORECASE),
        re.compile(r"Brute force attempt", re.IGNORECASE),
        re.compile(r"Invalid password for", re.IGNORECASE),
        re.compile(r"Authentication failure", re.IGNORECASE),
        re.compile(r"wrong password", re.IGNORECASE),  # Added for Brute Force
        re.compile(r"account locked", re.IGNORECASE)  # Added for Brute Force
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
        re.compile(r"heap corruption", re.IGNORECASE),  # Added for Buffer Overflow
        re.compile(r"stack corruption", re.IGNORECASE)  # Added for Buffer Overflow
    ]

    # JSON vulnerabilities patterns
    json_vulnerabilities_patterns = [
        re.compile(r"json\s+parse\s+error", re.IGNORECASE),
        re.compile(r"invalid\s+json\s+format", re.IGNORECASE),
        re.compile(r"malformed\s+json", re.IGNORECASE),
        re.compile(r"json\s+injection", re.IGNORECASE),
        re.compile(r"json\s+serialization\s+error", re.IGNORECASE),
        re.compile(r"json\s+deserialization\s+error", re.IGNORECASE),
        re.compile(r"json\s+replay\s+attack", re.IGNORECASE),
        re.compile(r"json\s+data\s+manipulation", re.IGNORECASE),  # Added for JSON Vulnerabilities
        re.compile(r"json\s+parameter\s+tampering", re.IGNORECASE)  # Added for JSON Vulnerabilities
    ]

    # Session Hijacking patterns
    session_hijacking_patterns = [
        re.compile(r"session\s+id\s+stolen", re.IGNORECASE),
        re.compile(r"session\s+hijack", re.IGNORECASE),
        re.compile(r"sessionid=", re.IGNORECASE),
        re.compile(r"session\s+fixation", re.IGNORECASE)
    ]

    # DOS patterns
    dos_patterns = [
        re.compile(r"denial\s+of\s+service", re.IGNORECASE),
        re.compile(r"DOS\s+attack", re.IGNORECASE),
        re.compile(r"service\s+unavailable", re.IGNORECASE),
        re.compile(r"server\s+overload", re.IGNORECASE),
        re.compile(r"traffic\s+flood", re.IGNORECASE),
        re.compile(r"resource\s+exhaustion", re.IGNORECASE),
        re.compile(r"network\s+congestion", re.IGNORECASE),
        re.compile(r"dos\s+protection", re.IGNORECASE),
        re.compile(r"dos\s+prevention", re.IGNORECASE),
        re.compile(r"dos\s+mitigation", re.IGNORECASE)
    ]

    # Sensitive Data Exposure patterns
    sensitive_data_exposure_patterns = [
        re.compile(r"sensitive\s+data\s+exposed", re.IGNORECASE),
        re.compile(r"data\s+leakage", re.IGNORECASE),
        re.compile(r"confidential\s+information", re.IGNORECASE),
        re.compile(r"exposed\s+credentials", re.IGNORECASE),
        re.compile(r"leaked\s+data", re.IGNORECASE),
        re.compile(r"unprotected\s+data", re.IGNORECASE),
        re.compile(r"data\s+breach", re.IGNORECASE),
        re.compile(r"data\s+exposed", re.IGNORECASE),
        re.compile(r"personal\s+information\s+leak", re.IGNORECASE),
        re.compile(r"private\s+data\s+disclosure", re.IGNORECASE)
    ]

    # Remote Code Execution patterns
    remote_code_execution_patterns = [
        re.compile(r"remote\s+code\s+execution", re.IGNORECASE),
        re.compile(r"RCE\s+vulnerability", re.IGNORECASE),
        re.compile(r"exploitable\s+code", re.IGNORECASE),
        re.compile(r"command\s+execution", re.IGNORECASE),
        re.compile(r"code\s+injection", re.IGNORECASE),
        re.compile(r"exploit\s+code", re.IGNORECASE),
        re.compile(r"arbitrary\s+code\s+execution", re.IGNORECASE),
        re.compile(r"shell\s+command\s+injection", re.IGNORECASE)
    ]

    # Crypto Vulnerabilities patterns
    crypto_vulnerabilities_patterns = [
        re.compile(r"cryptographic\s+vulnerability", re.IGNORECASE),
        re.compile(r"crypto\s+weakness", re.IGNORECASE),
        re.compile(r"encryption\s+flaw", re.IGNORECASE),
        re.compile(r"crypto\s+backdoor", re.IGNORECASE),
        re.compile(r"cryptographic\s+error", re.IGNORECASE),
        re.compile(r"crypto\s+insecure", re.IGNORECASE),
        re.compile(r"crypto\s+misuse", re.IGNORECASE),
        re.compile(r"decryption\s+error", re.IGNORECASE),
        re.compile(r"crypto\s+broken", re.IGNORECASE),
        re.compile(r"crypto\s+issue", re.IGNORECASE)
    ]

    # Authorization Flaws patterns
    authorization_flaws_patterns = [
        re.compile(r"authorization\s+failure", re.IGNORECASE),
        re.compile(r"unauthorized\s+access", re.IGNORECASE),
        re.compile(r"access\s+control\s+issue", re.IGNORECASE),
        re.compile(r"permission\s+problem", re.IGNORECASE),
        re.compile(r"authorization\s+bypass", re.IGNORECASE),
        re.compile(r"insufficient\s+privileges", re.IGNORECASE),
        re.compile(r"privilege\s+escalation", re.IGNORECASE),
        re.compile(r"authorization\s+error", re.IGNORECASE),
        re.compile(r"role\s+based\s+access\s+control\s+failure", re.IGNORECASE),
        re.compile(r"access\s+rights\s+misconfiguration", re.IGNORECASE)
    ]

    # Business Logic Errors patterns
    business_logic_errors_patterns = [
        re.compile(r"business\s+logic\s+error", re.IGNORECASE),
        re.compile(r"logical\s+flaw", re.IGNORECASE),
        re.compile(r"business\s+rule\s+violation", re.IGNORECASE),
        re.compile(r"misconfigured\s+logic", re.IGNORECASE),
        re.compile(r"flawed\s+logic", re.IGNORECASE),
        re.compile(r"logical\s+mistake", re.IGNORECASE),
        re.compile(r"logic\s+error", re.IGNORECASE),
        re.compile(r"business\s+logic\s+issue", re.IGNORECASE),
        re.compile(r"incorrect\s+logic", re.IGNORECASE),
        re.compile(r"business\s+process\s+error", re.IGNORECASE)
    ]

    try:
        with open(filepath, 'r') as log_file:
            log_data = log_file.read()

            # Search for SQL Injection patterns
            for pattern in sql_injection_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["possible_sql_injections"].extend(matches)

            # Search for Command Injection patterns
            for pattern in command_injection_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["command_injections"].extend(matches)

            # Search for XSS patterns
            for pattern in xss_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["xss_attempts"].extend(matches)

            # Search for Path Traversal patterns
            for pattern in path_traversal_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["path_traversal"].extend(matches)

            # Search for CSRF patterns
            for pattern in csrf_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["csrf_attempts"].extend(matches)

            # Search for Brute Force patterns
            for pattern in brute_force_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["brute_force_attempts"].extend(matches)

            # Search for Buffer Overflow patterns
            for pattern in buffer_overflow_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["buffer_overflows"].extend(matches)

            # Search for JSON vulnerabilities patterns
            for pattern in json_vulnerabilities_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["json_vulnerabilities"].extend(matches)

            # Search for Session Hijacking patterns
            for pattern in session_hijacking_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["session_hijacking"].extend(matches)

            # Search for DOS patterns
            for pattern in dos_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["dos_attempts"].extend(matches)

            # Search for Sensitive Data Exposure patterns
            for pattern in sensitive_data_exposure_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["sensitive_data_exposure"].extend(matches)

            # Search for Remote Code Execution patterns
            for pattern in remote_code_execution_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["remote_code_execution"].extend(matches)

            # Search for Crypto Vulnerabilities patterns
            for pattern in crypto_vulnerabilities_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["crypto_vulnerabilities"].extend(matches)

            # Search for Authorization Flaws patterns
            for pattern in authorization_flaws_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["authorization_flaws"].extend(matches)

            # Search for Business Logic Errors patterns
            for pattern in business_logic_errors_patterns:
                matches = pattern.findall(log_data)
                if matches:
                    vulnerabilities["business_logic_errors"].extend(matches)

    except Exception as e:
        vulnerabilities["errors"].append(str(e))

    return vulnerabilities


def analyze_pcap(filepath):
    vulnerabilities = {
        "tcp_injections": [],
        "suspicious_traffic": [],
        "dos_attacks": [],
        "dns_spoofing": [],
        "arp_poisoning": [],
        "ssl_attacks": [],
        "open_ports": [],
        "dark_web_monitoring": [],
        "zero_day_exploits": [],
        "iot_vulnerabilities": [],
        "ai_driven_threats": [],
        "autonomous_response": [],
        "privacy_compliance": [],
        "blockchain_audit_trail": [],
        "error": ""
    }

    try:
        # Utilisation de pyshark pour capturer et analyser les paquets PCAP
        capture = pyshark.FileCapture(filepath)

        for packet in capture:
            # Exemple de détection de port ouvert HTTP
            if 'TCP' in packet and int(packet.tcp.dstport) == 80:
                vulnerabilities["open_ports"].append(f"HTTP port 80 open at {packet.ip.dst}")

            # Exemple de détection de trafic DNS suspect
            if 'DNS' in packet:
                vulnerabilities["suspicious_traffic"].append("Suspicious DNS traffic detected")

            # Exemple de détection d'une attaque DoS basée sur le volume de trafic
            if 'IP' in packet and int(packet.ip.len) > 1500:  # Exemple arbitraire de détection de taille de paquet
                vulnerabilities["dos_attacks"].append("Potential DoS attack detected")

            # Exemple de détection de spoofing ARP
            if 'ARP' in packet:
                vulnerabilities["arp_poisoning"].append("ARP spoofing detected")

            # Exemple de détection d'une attaque SSL/TLS
            if 'TLS' in packet or 'SSL' in packet:
                vulnerabilities["ssl_attacks"].append("SSL/TLS attack detected")

            # Exemple de détection de trafic lié à des dispositifs IoT vulnérables
            if 'CoAP' in packet or 'MQTT' in packet:
                vulnerabilities["iot_vulnerabilities"].append("Traffic from vulnerable IoT devices detected")

            # Exemple de détection d'une menace basée sur l'intelligence artificielle
            if 'HTTP' in packet and 'User-Agent' in packet.http and 'AI' in packet.http['User-Agent']:
                vulnerabilities["ai_driven_threats"].append("AI-driven threat detected")

            # Exemple de détection de réponse autonome (autonomous response)
            if 'HTTP' in packet and 'X-Autonomous-Response' in packet.http:
                vulnerabilities["autonomous_response"].append("Autonomous response detected")

            # Exemple de détection de non-conformité à la vie privée
            if 'HTTP' in packet and 'Cookie' in packet.http and 'tracking_id' in packet.http['Cookie']:
                vulnerabilities["privacy_compliance"].append("Privacy compliance violation detected")

            # Exemple de surveillance du Dark Web
            if 'HTTP' in packet and 'dark_web_monitoring' in packet.http:
                vulnerabilities["dark_web_monitoring"].append("Dark web activity detected")

            # Exemple de détection d'exploits de type Zero-Day
            if 'HTTP' in packet and 'User-Agent' in packet.http and 'Zero-Day' in packet.http['User-Agent']:
                vulnerabilities["zero_day_exploits"].append("Zero-Day exploit detected")

            # Exemple de surveillance de la blockchain
            if 'Bitcoin' in packet or 'Ethereum' in packet:
                vulnerabilities["blockchain_audit_trail"].append("Blockchain transaction detected")

        capture.close()

    except Exception as e:
        vulnerabilities["error"] = str(e)

    return vulnerabilities

if __name__ == '__main__':
    scan_file()
