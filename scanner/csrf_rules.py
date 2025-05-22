import re

CSRF_PATTERNS = [
    {
        "name": "Form without CSRF token (basic)",
        "pattern": re.compile(r'<form[^>]*>(?!.*csrf_token)', re.IGNORECASE | re.DOTALL),
        "description": "HTML form does not contain anti-CSRF token."
    },
    {
        "name": "Form without hidden input field",
        "pattern": re.compile(r'<form[^>]*>(?!.*<input[^>]+type=["\']hidden["\'])', re.IGNORECASE | re.DOTALL),
        "description": "Form appears to lack hidden input fields, which are often used for CSRF tokens."
    },
    {
        "name": "Suspicious form action to external domain",
        "pattern": re.compile(r'<form[^>]+action=["\']https?://(?!localhost|127\.0\.0\.1)', re.IGNORECASE),
        "description": "Form posts to an external domain — this could be susceptible to CSRF attacks."
    },
    {
        "name": "No CSRF meta tag in head",
        "pattern": re.compile(r'<head[^>]*>(?!.*<meta[^>]+name=["\']csrf-token["\'])', re.IGNORECASE | re.DOTALL),
        "description": "Missing meta tag for CSRF token (common in JS-based apps like Rails or Laravel)."
    },
    {
        "name": "No CSRF headers in AJAX setup (jQuery)",
        "pattern": re.compile(r'\$.ajax\([^)]*?(?!headers\s*:\s*\{[^}]*["\']X-CSRF-Token["\'])', re.IGNORECASE | re.DOTALL),
        "description": "AJAX request does not include CSRF header."
    },
    {
        "name": "No fetch CSRF header (modern JS)",
        "pattern": re.compile(r'fetch\([^)]*?(?!headers\s*:\s*\{[^}]*["\']X-CSRF-Token["\'])', re.IGNORECASE | re.DOTALL),
        "description": "Fetch API request does not include CSRF token in headers."
    },
    {
        "name": "No CSRF token in form with method POST",
        "pattern": re.compile(r'<form[^>]+method=["\']post["\'][^>]*>(?!.*csrf_token)', re.IGNORECASE | re.DOTALL),
        "description": "POST form without CSRF token — high risk."
    },
    {
        "name": "Suspicious login form without CSRF token",
        "pattern": re.compile(r'<form[^>]*action=["\'][^"\']*(login|signin)[^"\']*["\'][^>]*>(?!.*csrf_token)', re.IGNORECASE | re.DOTALL),
        "description": "Login-related form appears to lack CSRF protection."
    },
    {
        "name": "No CSRF protection function call in Flask",
        "pattern": re.compile(r'@app\.route\([^)]*\)[\s\S]*?def [\w_]+\([^)]*\):\s*(?!.*csrf\.protect)', re.IGNORECASE),
        "description": "Flask route function lacks `csrf.protect()` usage."
    },
    {
        "name": "No CSRF middleware in Django settings",
        "pattern": re.compile(r'MIDDLEWARE\s*=\s*\[[^\]]*(?!["\']django.middleware.csrf.CsrfViewMiddleware["\'])', re.IGNORECASE | re.DOTALL),
        "description": "Django middleware list missing CSRF middleware."
    }
]

def get_csrf_patterns():
    return CSRF_PATTERNS
