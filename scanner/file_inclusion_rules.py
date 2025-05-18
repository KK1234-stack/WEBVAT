import re

FILE_INCLUSION_PATTERNS = [
    {
        "name": "Local File Inclusion (LFI) with user input",
        "pattern": re.compile(r'(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST)\[.*\]', re.IGNORECASE),
        "description": "Including files directly from user input, risk of Local File Inclusion."
    },
    {
        "name": "File inclusion with variable",
        "pattern": re.compile(r'(include|require|include_once|require_once)\s*\(\s*\$[a-zA-Z_]\w*\s*\)', re.IGNORECASE),
        "description": "Including files using variables, ensure variable is sanitized."
    }
]

def get_file_inclusion_patterns():
    return FILE_INCLUSION_PATTERNS

