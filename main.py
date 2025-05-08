# main.py

import argparse
import json
from scanner.sqli_scanner import scan_directory

def main():
    parser = argparse.ArgumentParser(description="Static SQL Injection Scanner")
    parser.add_argument('--scan-folder', required=True, help='Path to folder containing code files')
    parser.add_argument('--save-report', action='store_true', help='Save output to JSON report')
    args = parser.parse_args()

    print(f"\n🔍 Scanning folder: {args.scan_folder}\n")

    results = scan_directory(args.scan_folder)

    if not results:
        print("✅ No vulnerabilities found.")
    else:
        print(f"❌ Found {len(results)} potential vulnerabilities:\n")
        for r in results:
            print(f"[{r['file']}:{r['line']}] {r['issue']} - {r['code']}")
        
        if args.save_report:
            report_path = 'reports/scan_report.json'
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"\n📝 Report saved to {report_path}")

if __name__ == '__main__':
    main()
