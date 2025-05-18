import re

COMMAND_INJECTION_PATTERNS = [
    {
        "name": "Use of exec/system with user input",
        "pattern": re.compile(r'(exec|system|shell_exec|passthru|popen)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)\[.*\]', re.IGNORECASE),
        "description": "Command executed directly with unsanitized user input."
    },
    {
        "name": "Use of backticks with user input",
        "pattern": re.compile(r'`.*\$_(GET|POST|REQUEST|COOKIE)\[.*\].*`', re.IGNORECASE),
        "description": "Shell command executed using backticks with user input."
    }
]

def get_command_injection_patterns():
    return COMMAND_INJECTION_PATTERNS
