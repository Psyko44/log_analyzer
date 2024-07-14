# Log_analyzer

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
[![License](https://img.shields.io/badge/license-MIT-green)](https://opensource.org/licenses/MIT)

## Description
A vulnerability scanner tool that analyzes log files and network captures (pcap) for potential security issues such as SQL injections, XSS attacks, command injections, and more. This tool helps identify vulnerabilities in applications or network traffic logs.

## Features
- Supports scanning of log files (.log, .txt, .json) and network capture files (.pcap, .pcapng).
- Detects various types of vulnerabilities including SQL injections, XSS attempts, command injections, path traversals, CSRF attacks, and more.
- Generates JSON-formatted vulnerability reports.
- Command-line interface (CLI) based for easy integration into automated workflows.

## Installation
1. Clone the repository:
   
       git clone https://github.com/your_username/vulnerability-scanner.git
       cd vulnerability-scanner

        Install dependencies:

        pip install -r requirements.txt

## Usage

      To scan a log file:

      python scan.py --scan-type log --file-path /path/to/logfile.log --output /path/to/output.json

      To scan a pcap file:

      python scan.py --scan-type pcap --file-path /path/to/capture.pcap --output /path/to/output.json

## If no output path is specified, the results will be displayed in the terminal.
Options

    
    --scan-type or -s: Specify the type of file to scan (log for log files, pcap for pcap files).
    --file-path or -f: Path to the file to be analyzed.
    --output or -o: Optional. Path to save the JSON report. If not specified, results will be printed to the terminal.

## Example

Scanning a log file and saving the report:

    
      python scan.py -s log -f /path/to/logfile.log -o /path/to/report.json

Contributing

Contributions are welcome! Fork the repository, make your changes, and submit a pull request.
License

This project is licensed under the MIT License. See the LICENSE file for details.
