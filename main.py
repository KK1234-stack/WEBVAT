# main.py
import argparse
import json
from scanner.sqli_scanner import scan_directory as scan_sqli
from scanner.xss_scanner import scan_directory as scan_xss

def main():
    parser = argparse.ArgumentParser(description="Static Vulnerability Scanner")
    parser.add_argument('--scan-folder', required=True, help='Folder with code files')
    parser.add_argument('--scan', choices=['sqli', 'xss', 'both'], default='both', help='Type of scan')
    parser.add_argument('--save-report', action='store_true', help='Save output to JSON')
    args = parser.parse_args()

    print(f"\n🔍 Scanning: {args.scan_folder} [Type: {args.scan}]\n")
    results = []

    if args.scan in ('sqli', 'both'):
        print("📌 Running SQL Injection Scan...\n")
        sqli_results = scan_sqli(args.scan_folder)
        results.extend(sqli_results)

    if args.scan in ('xss', 'both'):
        print("📌 Running XSS Scan...\n")
        xss_results = scan_xss(args.scan_folder)
        results.extend(xss_results)

    if not results:
        print("✅ No vulnerabilities found.")
    else:
        print(f"❌ Found {len(results)} potential issues:\n")
        for r in results:
            print(f"[{r['file']}:{r['line']}] {r['issue']} - {r['code']}")

        if args.save_report:
            report_path = 'reports/scan_report.json'
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"\n📝 Report saved to {report_path}")

if __name__ == '__main__':
    main()
