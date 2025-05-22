import re

FILE_INCLUSION_PATTERNS = [
    {
        "name": "PHP: LFI with direct user input",
        "pattern": re.compile(r'(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\[[\'"]?\w+[\'"]?\]', re.IGNORECASE),
        "description": "Including files directly from user input, risk of Local File Inclusion."
    },
    {
        "name": "PHP: RFI with user input",
        "pattern": re.compile(r'(include|require|include_once|require_once)\s*\(\s*("|\')?http[s]?://\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\[[\'"]?\w+[\'"]?\]', re.IGNORECASE),
        "description": "Remote File Inclusion possible if external URLs are passed via user input."
    },
    {
        "name": "PHP: Dynamic include using variable",
        "pattern": re.compile(r'(include|require|include_once|require_once)\s*\(\s*\$[a-zA-Z_][\w]*\s*\)', re.IGNORECASE),
        "description": "Includes file using variable; must validate and sanitize the input source."
    },
    {
        "name": "PHP: Dynamic include with concatenation",
        "pattern": re.compile(r'(include|require|include_once|require_once)\s*\(\s*("|\')?\s*\.\s*\$[a-zA-Z_][\w]*\s*\.\s*("|\')?\s*\)', re.IGNORECASE),
        "description": "File path built using string concatenation—high LFI risk."
    },
    {
        "name": "PHP: File access functions with user input",
        "pattern": re.compile(r'(file_get_contents|readfile|fopen|file|file_exists|unlink|is_readable|is_file)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.*\]', re.IGNORECASE),
        "description": "File access functions using unsanitized user input, can lead to LFI or information disclosure."
    },
    {
        "name": "PHP: Allow URL include setting enabled",
        "pattern": re.compile(r'ini_set\s*\(\s*[\'"]allow_url_include[\'"]\s*,\s*[\'"]1[\'"]\s*\)', re.IGNORECASE),
        "description": "Enabling URL includes can allow RFI if used with external input."
    },
    {
        "name": "Python: open() with input() or argv",
        "pattern": re.compile(r'open\s*\(\s*(input|sys\.argv)\s*\(', re.IGNORECASE),
        "description": "Python file open using user input or command-line argument."
    },
    {
        "name": "Python: open() with unsanitized variable",
        "pattern": re.compile(r'open\s*\(\s*\w+\s*\)', re.IGNORECASE),
        "description": "File opened using a variable—ensure it’s sanitized and validated."
    },
    {
        "name": "Node.js: fs.readFile with req param",
        "pattern": re.compile(r'fs\.(readFile|readFileSync|createReadStream)\s*\(\s*req\.(body|query|params)\.', re.IGNORECASE),
        "description": "Node.js fs module reading file from unsanitized HTTP request parameter."
    },
    {
        "name": "Generic: Directory traversal sequence",
        "pattern": re.compile(r'\.\./', re.IGNORECASE),
        "description": "Presence of directory traversal—used to escape web root and access sensitive files."
    },
    {
        "name": "PHP: Read sensitive file",
        "pattern": re.compile(r'(file_get_contents|fopen|readfile)\s*\(\s*["\']?/etc/passwd["\']?', re.IGNORECASE),
        "description": "Directly attempting to read sensitive OS files—can be used for LFI testing."
    }
]

def get_file_inclusion_patterns():
    return FILE_INCLUSION_PATTERNS
