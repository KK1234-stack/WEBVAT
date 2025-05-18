import os
from .csrf_rules import get_csrf_patterns

def scan_file(file_path):
    results = []
    patterns = get_csrf_patterns()

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Split forms for scanning each separately
    forms = re.findall(r'(<form.*?>.*?</form>)', content, re.IGNORECASE | re.DOTALL)

    for i, form in enumerate(forms):
        for rule in patterns:
            if rule["pattern"].search(form) is not None:
                results.append({
                    "file": file_path,
                    "line": f"Form #{i+1}",
                    "code": form.strip()[:100] + "...",
                    "issue": rule["name"],
                    "description": rule["description"]
                })
    return results

def scan_directory(directory):
    vulnerabilities = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.php') or file.endswith('.html'):
                full_path = os.path.join(root, file)
                vulnerabilities.extend(scan_file(full_path))
    return vulnerabilities
