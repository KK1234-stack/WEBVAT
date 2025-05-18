import re

CSRF_PATTERNS = [
    {
        "name": "Form without CSRF token",
        "pattern": re.compile(r'<form[^>]*>(?!.*csrf_token)', re.IGNORECASE | re.DOTALL),
        "description": "HTML form does not contain anti-CSRF token."
    }
]

def get_csrf_patterns():
    return CSRF_PATTERNS
