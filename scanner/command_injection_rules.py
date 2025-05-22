import re

COMMAND_INJECTION_PATTERNS = [
    {
        "name": "PHP: Dangerous function with user input",
        "pattern": re.compile(r'(exec|system|shell_exec|passthru|popen|proc_open)\s*\(.*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*\]', re.IGNORECASE),
        "description": "Dangerous command execution function with direct user input in PHP."
    },
    {
        "name": "PHP: Backticks with user input",
        "pattern": re.compile(r'`[^`]*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*\][^`]*`', re.IGNORECASE),
        "description": "Backticks used for command execution with unsanitized input in PHP."
    },
    {
        "name": "Python: os.system with input",
        "pattern": re.compile(r'os\.system\s*\(\s*input\s*\(\s*\)', re.IGNORECASE),
        "description": "Python's os.system used with raw input, may lead to command injection."
    },
    {
        "name": "Python: subprocess with user input",
        "pattern": re.compile(r'subprocess\.(call|Popen|run)\s*\(\s*input\s*\(\s*\)', re.IGNORECASE),
        "description": "Python subprocess module used unsafely with input()."
    },
    {
        "name": "Python: eval/exec with input",
        "pattern": re.compile(r'(eval|exec)\s*\(\s*input\s*\(\s*\)', re.IGNORECASE),
        "description": "eval or exec used with input, vulnerable to code/command injection."
    },
    {
        "name": "Shell command concatenation (generic)",
        "pattern": re.compile(r'(cat|ls|ping|curl|wget|rm|mv|cp)\s*\+\s*\w+', re.IGNORECASE),
        "description": "Shell command built via string concatenation—potential injection vector."
    },
    {
        "name": "Concatenation of user input into command string",
        "pattern": re.compile(r'(["\'](rm|ping|wget|curl|cat|ls|cp).*["\']\s*\+\s*\w+)', re.IGNORECASE),
        "description": "String-based command injection risk due to concatenation of external input."
    },
    {
        "name": "User input passed into shell=True call",
        "pattern": re.compile(r'subprocess\.(call|run|Popen)\s*\(.*(input|sys\.argv).*shell\s*=\s*True', re.IGNORECASE),
        "description": "User-controlled input executed with shell=True."
    },
    {
        "name": "Node.js: child_process with request param",
        "pattern": re.compile(r'child_process\.(exec|spawn|execSync)\s*\(.*req\.(query|body|params)\.', re.IGNORECASE),
        "description": "Node.js child_process used with HTTP request input."
    },
    {
        "name": "Suspicious semicolon in command string",
        "pattern": re.compile(r'["\'].*;.*["\']', re.IGNORECASE),
        "description": "Semicolons inside command strings might enable command chaining."
    },
    {
        "name": "Bash-style command substitution",
        "pattern": re.compile(r'\$\((.*?)\)', re.IGNORECASE),
        "description": "Bash-style command substitution used; may enable injection if input is inserted."
    },
    {
        "name": "Perl: system call with user input",
        "pattern": re.compile(r'system\s*\(.*\$\w+\s*\)', re.IGNORECASE),
        "description": "Perl system() call with variable that could be user-controlled."
    }
]

def get_command_injection_patterns():
    return COMMAND_INJECTION_PATTERNS
