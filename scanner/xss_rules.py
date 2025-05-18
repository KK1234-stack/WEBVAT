import re

XSS_PATTERNS = [
    # --- PHP Patterns ---

    {
        "name": "Direct echo of user input",
        "pattern": re.compile(r'echo\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[["\']?\w+["\']?\]', re.IGNORECASE),
        "description": "Directly echoing user input without sanitization."
    },
    {
        "name": "User input used in HTML tag output",
        "pattern": re.compile(r'echo\s*[\'"].*<[^>]+>\s*\$_(GET|POST|REQUEST)', re.IGNORECASE),
        "description": "User input embedded inside HTML tags without sanitization."
    },
    {
        "name": "Print with user input",
        "pattern": re.compile(r'print\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)', re.IGNORECASE),
        "description": "Printing user input without any sanitization."
    },
    {
        "name": "User input in script tags",
        "pattern": re.compile(r'<script[^>]*>\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[.*?\]\s*<\/script>', re.IGNORECASE),
        "description": "User input used directly inside JavaScript block."
    },
    {
        "name": "User input in attributes (href, src, etc.)",
        "pattern": re.compile(r'(href|src)\s*=\s*["\']?\s*\$_(GET|POST|REQUEST)\s*\[.*?\]', re.IGNORECASE),
        "description": "User input used in HTML attributes (possible injection)."
    },
    {
        "name": "Unsanitized input passed to custom function",
        "pattern": re.compile(r'\w+\s*\(\s*\$_(GET|POST|REQUEST)\s*\[.*?\]', re.IGNORECASE),
        "description": "User input passed to a function without validation."
    },

    # --- JS/DOM-based XSS Patterns ---

    {
        "name": "document.write with unsanitized input",
        "pattern": re.compile(r'document\.write\s*\(\s*\w+\s*\)', re.IGNORECASE),
        "description": "Dynamic content written using potentially unsafe variable."
    },
    {
        "name": "innerHTML assignment",
        "pattern": re.compile(r'\.innerHTML\s*=\s*\w+', re.IGNORECASE),
        "description": "Setting innerHTML directly without sanitizing the variable."
    },
    {
        "name": "location.href assignment from input",
        "pattern": re.compile(r'location\.href\s*=\s*.*(document\.location|window\.location|location\.search)', re.IGNORECASE),
        "description": "Untrusted input used to redirect users."
    },
    {
        "name": "eval with user-controlled data",
        "pattern": re.compile(r'eval\s*\(\s*\w+\s*\)', re.IGNORECASE),
        "description": "eval used with dynamic input (extremely dangerous)."
    },
    {
        "name": "setTimeout or setInterval with user input",
        "pattern": re.compile(r'(setTimeout|setInterval)\s*\(\s*\w+\s*,', re.IGNORECASE),
        "description": "setTimeout/setInterval called with potentially unsafe input."
    },
    {
        "name": "Unsafe URL redirection",
        "pattern": re.compile(r'document\.location\s*=\s*\w+', re.IGNORECASE),
        "description": "User input used to change document location."
    },
    {
        "name": "Assigning input to DOM properties",
        "pattern": re.compile(r'document\.getElementById\s*\(\s*[\'"].+[\'"]\s*\)\.\w+\s*=\s*\w+', re.IGNORECASE),
        "description": "Unsafe assignment of input to DOM node properties."
    },
    {
        "name": "Unescaped input used in templates",
        "pattern": re.compile(r'{{\s*\w+\s*}}', re.IGNORECASE),
        "description": "Templating output not escaped properly (common in JS frameworks)."
    },
]

def get_xss_patterns():
    return XSS_PATTERNS
