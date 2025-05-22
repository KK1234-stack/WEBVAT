import os
from .idor_rules import get_idor_patterns

def scan_file(file_path):
    results = []
    patterns = get_idor_patterns()

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
            if file.endswith(('.php', '.js')):
                full_path = os.path.join(root, file)
                results = scan_file(full_path)
                vulnerabilities.extend(results)
    return vulnerabilities
