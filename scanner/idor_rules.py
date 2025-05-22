import re

IDOR_PATTERNS = [
    {
        "name": "Direct use of user input in file path",
        "pattern": re.compile(r'["\']?\./?uploads?/.*\$_(GET|POST|REQUEST)\[.*\]', re.IGNORECASE),
        "description": "Direct object access via user input in file paths, potential IDOR."
    },
    {
        "name": "Access control based on user-supplied ID",
        "pattern": re.compile(r'\$_(GET|POST|REQUEST)\[.*id.*\]', re.IGNORECASE),
        "description": "Use of ID parameter from user input without access checks, possible IDOR."
    },
    {
        "name": "Database access using user input ID",
        "pattern": re.compile(r'SELECT.*FROM.*WHERE.*id\s*=\s*\$_(GET|POST|REQUEST)\[.*\]', re.IGNORECASE),
        "description": "User-controlled ID used in DB query, likely IDOR."
    },
    {
        "name": "File access with user-controlled identifiers",
        "pattern": re.compile(r'fopen\s*\(.*\$_(GET|POST|REQUEST)\[.*\]', re.IGNORECASE),
        "description": "File opened based on user input, could be IDOR if no validation."
    },
    {
        "name": "User input used in authorization logic",
        "pattern": re.compile(r'if\s*\(.*\$_(GET|POST|REQUEST)\[.*user.*\].*==.*\)', re.IGNORECASE),
        "description": "User-controlled user ID or object used in auth logic, potential IDOR."
    }
]

def get_idor_patterns():
    return IDOR_PATTERNS
