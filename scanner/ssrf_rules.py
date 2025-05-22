import re

SSRF_PATTERNS = [
    {
        "name": "file_get_contents with user input",
        "pattern": re.compile(r'file_get_contents\s*\(.*\$_(GET|POST|REQUEST)\[.*\]', re.IGNORECASE),
        "description": "User input directly used in file_get_contents(), possible SSRF."
    },
    {
        "name": "curl_exec with user input",
        "pattern": re.compile(r'curl_exec\s*\(.*\$_(GET|POST|REQUEST)\[.*\]', re.IGNORECASE),
        "description": "User input directly used in curl_exec(), possible SSRF."
    },
    {
        "name": "requests.get with user input",
        "pattern": re.compile(r'requests\.get\s*\(.*\$_(GET|POST|REQUEST)\[.*\]', re.IGNORECASE),
        "description": "User input used in requests.get(), possible SSRF."
    },
    {
        "name": "http.get with user input",
        "pattern": re.compile(r'http\.get\s*\(.*\$_(GET|POST|REQUEST)\[.*\]', re.IGNORECASE),
        "description": "User input used in http.get(), possible SSRF."
    },
    {
        "name": "open with user input (python)",
        "pattern": re.compile(r'open\s*\(.*\$_(GET|POST|REQUEST)\[.*\]', re.IGNORECASE),
        "description": "User input used in open(), possible SSRF or file read."
    }
]

def get_ssrf_patterns():
    return SSRF_PATTERNS
