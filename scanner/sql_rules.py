import re

import re

SQLI_PATTERNS = [
    {
        "name": "Direct SQL query with variable",
        "pattern": re.compile(r'\$\w+\s*=\s*["\'].*(SELECT|INSERT|UPDATE|DELETE).*["\']\s*;', re.IGNORECASE),
        "description": "Query assignment that could contain SQL injection."
    },
    {
        "name": "Query using user input variable",
        "pattern": re.compile(r'\$.*=\s*\$_(GET|POST|REQUEST)\[.*\]', re.IGNORECASE),
        "description": "User input stored in variable, possible unsanitized input."
    },
    {
        "name": "User input inside SQL query",
        "pattern": re.compile(r'["\'].*(SELECT|INSERT|UPDATE|DELETE).*?\$[a-zA-Z_]\w*.*["\']', re.IGNORECASE),
        "description": "SQL query contains user-controlled variable."
    },
    {
        "name": "Query execution with raw input",
        "pattern": re.compile(r'mysqli_query\s*\(.*\$_(GET|POST|REQUEST)', re.IGNORECASE),
        "description": "SQL query executed with direct user input."
    }
]

def get_sqli_patterns():
    return SQLI_PATTERNS
