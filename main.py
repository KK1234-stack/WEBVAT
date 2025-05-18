import argparse
import json
import os

from scanner.sqli_scanner import scan_directory as scan_sqli_directory
from scanner.xss_scanner import scan_directory as scan_xss_directory
from scanner.file_inclusion_scanner import scan_directory as scan_file_inclusion_directory
from scanner.csrf_scanner import scan_directory as scan_csrf_directory
from scanner.command_injection_scanner import scan_directory as scan_command_injection_directory

def filter_files_by_types(directory, file_types):
    """Walk directory and keep only files matching extensions in file_types"""
    matching_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in file_types):
                matching_files.append(os.path.join(root, file))
    return matching_files

def scan_combined(directory, file_types, vuln_types):
    results = []

    # We'll scan entire folder with each scanner that supports folder scanning.
    # Filtering files by type is handled inside individual scanners or here if needed.

    if 'sqli' in vuln_types:
        print("Starting SQL Injection scan...")
        results.extend(scan_sqli_directory(directory))

    if 'xss' in vuln_types:
        print("Starting XSS scan...")
        results.extend(scan_xss_directory(directory))

    if 'file_inclusion' in vuln_types:
        print("Starting File Inclusion scan...")
        results.extend(scan_file_inclusion_directory(directory))

    if 'csrf' in vuln_types:
        print("Starting CSRF scan...")
        results.extend(scan_csrf_directory(directory))

    if 'command_injection' in vuln_types:
        print("Starting Command Injection scan...")
        results.extend(scan_command_injection_directory(directory))

    # Optional: filter results by file extensions if you want to enforce strict filtering here

    return results

def main():
    parser = argparse.ArgumentParser(description="Static Vulnerability Scanner")
    parser.add_argument('--scan-folder', required=True, help='Path to folder containing code files')
    parser.add_argument(
        '--vuln-type',
        default='sqli,xss,file_inclusion,csrf,command_injection',
        help='Comma-separated vulnerability types to scan (sqli, xss, file_inclusion, csrf, command_injection)'
    )
    parser.add_argument(
        '--file-types',
        default='.php,.js,.html',
        help='Comma-separated list of file extensions to scan, e.g. .php,.js,.html'
    )
    parser.add_argument('--save-report', action='store_true', help='Save output to JSON report')
    args = parser.parse_args()

    vuln_types = [v.strip().lower() for v in args.vuln_type.split(',')]
    file_types = [ft.strip() for ft in args.file_types.split(',')]

    print(f"\n🔍 Scanning folder: {args.scan_folder}")
    print(f"🔎 Vulnerability types: {vuln_types}")
    print(f"📄 File types: {file_types}\n")

    results = scan_combined(args.scan_folder, file_types, vuln_types)

    if not results:
        print("✅ No vulnerabilities found.")
    else:
        print(f"❌ Found {len(results)} potential vulnerabilities:\n")
        for r in results:
            print(f"[{r['file']}:{r['line']}] {r['issue']} - {r['code']}")

        if args.save_report:
            report_path = 'reports/scan_report.json'
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"\n📝 Report saved to {report_path}")

if __name__ == '__main__':
    main()
