import os
from .ssrf_rules import get_ssrf_patterns

def scan_file(file_path):
    results = []
    patterns = get_ssrf_patterns()

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        for rule in patterns:
            if rule["pattern"].search(line):
                results.append({
                    "file": file_path,
                    "line": i + 1,
                    "code": line.strip(),
                    "issue": rule["name"],
                    "description": rule["description"]
                })

    return results

def scan_directory(directory):
    vulnerabilities = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.php', '.js', '.py')):
                full_path = os.path.join(root, file)
                vulnerabilities.extend(scan_file(full_path))
    return vulnerabilities
