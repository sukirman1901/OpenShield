"""
Remediation Agent - Secure Code Generation & Vulnerability Fixing
Generates secure code fixes for identified vulnerabilities
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import re

from core.agent import BaseAgent
from core.memory import Finding


class RemediationAgent(BaseAgent):
    """Agent that generates secure code fixes for vulnerabilities"""

    def __init__(self, config, gemini_client, memory):
        super().__init__("RemediationAgent", config, gemini_client, memory)

        # Code fix templates by language
        self.fix_templates = {
            "php": self._get_php_fixes,
            "python": self._get_python_fixes,
            "javascript": self._get_javascript_fixes,
            "java": self._get_java_fixes,
        }

    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute remediation generation"""
        finding = kwargs.get("finding")
        code = kwargs.get("code")
        language = kwargs.get("language", "unknown")

        if not finding:
            raise ValueError("Finding is required for remediation")

        return await self.generate_fix(finding, code, language)

    async def generate_fix(
        self, finding: Finding, vulnerable_code: Optional[str] = None, language: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Generate secure code fix for a vulnerability

        Args:
            finding: Security finding to fix
            vulnerable_code: Optional vulnerable code snippet
            language: Programming language

        Returns:
            Dict with fixed code, explanation, and steps
        """
        self.log_action("GeneratingFix", f"Creating remediation for {finding.title}")

        # Detect vulnerability type
        vuln_type = self._detect_vuln_type(finding)

        # Auto-detect language if not provided
        if language == "unknown" and vulnerable_code:
            language = self._detect_language(vulnerable_code)

        # Generate fix using template or AI
        if language in self.fix_templates:
            fix = await self.fix_templates[language](finding, vuln_type, vulnerable_code)
        else:
            # Use AI for custom language/framework
            fix = await self._generate_ai_fix(finding, vulnerable_code, language)

        # Add metadata
        fix["finding_id"] = finding.id
        fix["generated_at"] = datetime.now().isoformat()
        fix["language"] = language
        fix["vuln_type"] = vuln_type

        self.log_action("FixGenerated", f"Remediation ready for {vuln_type}")

        return fix

    def _detect_vuln_type(self, finding: Finding) -> str:
        """Detect vulnerability type from finding"""
        title_lower = finding.title.lower()

        if "xss" in title_lower:
            return "xss"
        elif "sql" in title_lower:
            return "sqli"
        elif "csrf" in title_lower:
            return "csrf"
        elif "command injection" in title_lower:
            return "command_injection"
        elif "path traversal" in title_lower:
            return "path_traversal"
        elif "xxe" in title_lower:
            return "xxe"
        elif "ssrf" in title_lower:
            return "ssrf"
        elif "insecure deserialization" in title_lower:
            return "deserialization"
        else:
            return "unknown"

    def _detect_language(self, code: str) -> str:
        """Auto-detect programming language from code"""
        if "<?php" in code or "$_" in code:
            return "php"
        elif "def " in code or "import " in code:
            return "python"
        elif "function" in code or "const " in code or "let " in code:
            return "javascript"
        elif "public class" in code or "private " in code:
            return "java"
        else:
            return "unknown"

    async def _get_php_fixes(
        self, finding: Finding, vuln_type: str, vulnerable_code: Optional[str]
    ) -> Dict[str, Any]:
        """Generate PHP security fixes"""

        fixes = {
            "xss": {
                "vulnerable": vulnerable_code or "echo $_GET['search'];",
                "fixed": "echo htmlspecialchars($_GET['search'], ENT_QUOTES, 'UTF-8');",
                "explanation": "Use htmlspecialchars() to encode HTML special characters, preventing XSS attacks",
                "steps": [
                    "1. Identify all output points of user input",
                    "2. Wrap with htmlspecialchars()",
                    "3. Use ENT_QUOTES flag to encode both single and double quotes",
                    "4. Specify UTF-8 encoding",
                    "5. Test with XSS payloads: <script>alert(1)</script>",
                ],
                "additional_measures": [
                    "Implement Content-Security-Policy header",
                    "Set HTTPOnly flag on cookies",
                    "Use output encoding libraries like OWASP ESAPI",
                ],
            },
            "sqli": {
                "vulnerable": vulnerable_code or "SELECT * FROM users WHERE id = {$_GET['id']}",
                "fixed": """$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
$user = $stmt->fetch();""",
                "explanation": "Use prepared statements with parameterized queries to prevent SQL injection",
                "steps": [
                    "1. Replace string concatenation with prepared statements",
                    "2. Use PDO or MySQLi with parameter binding",
                    "3. Never interpolate user input directly into SQL",
                    "4. Validate input data types",
                    "5. Test with SQLi payloads: ' OR '1'='1",
                ],
                "additional_measures": [
                    "Use ORM frameworks (Laravel Eloquent, Doctrine)",
                    "Implement least privilege database access",
                    "Enable SQL query logging and monitoring",
                ],
            },
            "csrf": {
                "vulnerable": vulnerable_code
                or "<form method='POST' action='/update'>\n  <input name='email'>\n</form>",
                "fixed": """<?php
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<form method='POST' action='/update'>
  <input type='hidden' name='csrf_token' value='<?= $_SESSION['csrf_token'] ?>'>
  <input name='email'>
</form>

<?php
// Validation
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF token validation failed');
}
?>""",
                "explanation": "Generate and validate CSRF tokens for all state-changing operations",
                "steps": [
                    "1. Generate unique CSRF token per session",
                    "2. Include token in all forms as hidden field",
                    "3. Validate token on server-side before processing",
                    "4. Regenerate token after successful validation",
                    "5. Set SameSite cookie attribute",
                ],
                "additional_measures": [
                    "Use framework CSRF protection (Laravel, Symfony)",
                    "Implement double-submit cookie pattern",
                    "Require custom headers for AJAX requests",
                ],
            },
            "command_injection": {
                "vulnerable": vulnerable_code or "system('ping -c 4 ' . $_GET['host']);",
                "fixed": """// Avoid system calls - use built-in functions
$host = $_GET['host'];

// Strict validation
if (!filter_var($host, FILTER_VALIDATE_IP) && 
    !filter_var($host, FILTER_VALIDATE_DOMAIN)) {
    die('Invalid host');
}

// Use safe alternative
$output = shell_exec(escapeshellarg('ping') . ' -c 4 ' . escapeshellarg($host));""",
                "explanation": "Avoid system calls entirely. If necessary, use strict validation and proper escaping",
                "steps": [
                    "1. Replace system calls with language built-in functions",
                    "2. If system calls unavoidable, validate input strictly",
                    "3. Use escapeshellarg() and escapeshellcmd()",
                    "4. Never pass user input directly to shell",
                    "5. Implement whitelist validation",
                ],
                "additional_measures": [
                    "Run processes with minimal privileges",
                    "Use sandboxing/containers",
                    "Disable dangerous PHP functions in php.ini",
                ],
            },
            "path_traversal": {
                "vulnerable": vulnerable_code or "include($_GET['page'] . '.php');",
                "fixed": """$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'];

// Whitelist validation
if (!in_array($page, $allowed_pages)) {
    die('Invalid page');
}

// Safe include
include($page . '.php');""",
                "explanation": "Use whitelist validation for file paths, never trust user input",
                "steps": [
                    "1. Define whitelist of allowed files/paths",
                    "2. Validate user input against whitelist",
                    "3. Use basename() to strip directory components",
                    "4. Avoid using user input in file paths entirely",
                    "5. Store files outside web root",
                ],
                "additional_measures": [
                    "Use realpath() to resolve symbolic links",
                    "Check file exists within allowed directory",
                    "Implement proper access controls",
                ],
            },
        }

        fix_data = fixes.get(
            vuln_type,
            {
                "vulnerable": vulnerable_code or "// Vulnerable code",
                "fixed": "// Secure implementation needed",
                "explanation": "Apply security best practices for this vulnerability type",
                "steps": ["Consult OWASP guidelines for specific remediation"],
                "additional_measures": [],
            },
        )

        return fix_data

    async def _get_python_fixes(
        self, finding: Finding, vuln_type: str, vulnerable_code: Optional[str]
    ) -> Dict[str, Any]:
        """Generate Python security fixes"""

        fixes = {
            "xss": {
                "vulnerable": vulnerable_code
                or "return f'<h1>Search: {request.args.get(\"q\")}</h1>'",
                "fixed": """from markupsafe import escape

return f'<h1>Search: {escape(request.args.get("q"))}</h1>'""",
                "explanation": "Use escape() or Jinja2 auto-escaping to prevent XSS",
                "steps": [
                    "1. Import escape from markupsafe",
                    "2. Wrap all user input in escape()",
                    "3. Use Jinja2 templates with auto-escaping enabled",
                    "4. Never use |safe filter on user input",
                ],
            },
            "sqli": {
                "vulnerable": vulnerable_code
                or "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                "fixed": """# Use parameterized queries
cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))

# Or with SQLAlchemy ORM
user = User.query.filter_by(id=user_id).first()""",
                "explanation": "Always use parameterized queries or ORM, never string formatting",
                "steps": [
                    "1. Replace f-strings/format() with parameterized queries",
                    "2. Use ? or %s placeholders",
                    "3. Pass parameters as tuple",
                    "4. Consider using SQLAlchemy ORM",
                ],
            },
            "command_injection": {
                "vulnerable": vulnerable_code or "os.system(f'ping -c 4 {host}')",
                "fixed": """import subprocess
import shlex

# Use subprocess with list arguments
result = subprocess.run(
    ['ping', '-c', '4', host],
    capture_output=True,
    text=True,
    timeout=10
)""",
                "explanation": "Use subprocess with list arguments, never shell=True with user input",
                "steps": [
                    "1. Replace os.system() with subprocess.run()",
                    "2. Pass command as list, not string",
                    "3. Never use shell=True with user input",
                    "4. Validate input against whitelist",
                    "5. Set timeout to prevent DoS",
                ],
            },
            "deserialization": {
                "vulnerable": vulnerable_code or "data = pickle.loads(user_input)",
                "fixed": """import json

# Use JSON instead of pickle
try:
    data = json.loads(user_input)
except json.JSONDecodeError:
    raise ValueError('Invalid JSON')

# If pickle necessary, sign the data
import hmac
import hashlib

def safe_pickle_loads(data, secret_key):
    signature, pickled = data.split(b':', 1)
    expected = hmac.new(secret_key, pickled, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature.decode(), expected):
        raise ValueError('Invalid signature')
    return pickle.loads(pickled)""",
                "explanation": "Avoid pickle with untrusted data. Use JSON or sign pickled data",
                "steps": [
                    "1. Replace pickle with JSON when possible",
                    "2. If pickle required, implement HMAC signing",
                    "3. Validate signatures before unpickling",
                    "4. Use safe serialization formats",
                ],
            },
        }

        return fixes.get(
            vuln_type,
            {
                "vulnerable": vulnerable_code or "# Vulnerable code",
                "fixed": "# Secure implementation",
                "explanation": "Apply Python security best practices",
                "steps": ["Follow OWASP Python Security guidelines"],
            },
        )

    async def _get_javascript_fixes(
        self, finding: Finding, vuln_type: str, vulnerable_code: Optional[str]
    ) -> Dict[str, Any]:
        """Generate JavaScript security fixes"""

        fixes = {
            "xss": {
                "vulnerable": vulnerable_code or "element.innerHTML = userInput;",
                "fixed": """// Use textContent instead of innerHTML
element.textContent = userInput;

// Or use DOMPurify for HTML content
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);""",
                "explanation": "Use textContent or sanitize HTML with DOMPurify",
                "steps": [
                    "1. Replace innerHTML with textContent for plain text",
                    "2. Use DOMPurify.sanitize() for HTML content",
                    "3. Avoid eval(), setTimeout/setInterval with strings",
                    "4. Implement Content-Security-Policy",
                ],
            },
            "csrf": {
                "vulnerable": vulnerable_code
                or "fetch('/api/update', {method: 'POST', body: data})",
                "fixed": """// Add CSRF token to requests
const csrfToken = document.querySelector('meta[name=\"csrf-token\"]').content;

fetch('/api/update', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify(data)
})""",
                "explanation": "Include CSRF token in all state-changing requests",
                "steps": [
                    "1. Get CSRF token from meta tag or cookie",
                    "2. Include token in request headers",
                    "3. Validate token on server-side",
                    "4. Use SameSite cookies",
                ],
            },
        }

        return fixes.get(
            vuln_type,
            {
                "vulnerable": vulnerable_code or "// Vulnerable code",
                "fixed": "// Secure implementation",
                "explanation": "Apply JavaScript security best practices",
                "steps": ["Follow OWASP JavaScript Security guidelines"],
            },
        )

    async def _get_java_fixes(
        self, finding: Finding, vuln_type: str, vulnerable_code: Optional[str]
    ) -> Dict[str, Any]:
        """Generate Java security fixes"""

        fixes = {
            "sqli": {
                "vulnerable": vulnerable_code
                or 'Statement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);',
                "fixed": """// Use PreparedStatement
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();""",
                "explanation": "Always use PreparedStatement with parameter binding",
                "steps": [
                    "1. Replace Statement with PreparedStatement",
                    "2. Use ? placeholders for parameters",
                    "3. Bind parameters with setXxx() methods",
                    "4. Never concatenate user input into SQL",
                ],
            },
            "xxe": {
                "vulnerable": vulnerable_code
                or "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocumentBuilder db = dbf.newDocumentBuilder();",
                "fixed": """DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Disable external entities
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

DocumentBuilder db = dbf.newDocumentBuilder();""",
                "explanation": "Disable external entity processing in XML parsers",
                "steps": [
                    "1. Disable DOCTYPE declarations",
                    "2. Disable external entities",
                    "3. Disable XInclude",
                    "4. Set expandEntityReferences to false",
                ],
            },
        }

        return fixes.get(
            vuln_type,
            {
                "vulnerable": vulnerable_code or "// Vulnerable code",
                "fixed": "// Secure implementation",
                "explanation": "Apply Java security best practices",
                "steps": ["Follow OWASP Java Security guidelines"],
            },
        )

    async def _generate_ai_fix(
        self, finding: Finding, vulnerable_code: Optional[str], language: str
    ) -> Dict[str, Any]:
        """Use AI to generate custom security fix"""

        prompt = f"""Generate a secure code fix for the following vulnerability:

**Vulnerability:**
Title: {finding.title}
Description: {finding.description}
Severity: {finding.severity}

**Vulnerable Code ({language}):**
```
{vulnerable_code or "Not provided"}
```

**Target:** {finding.target}

Provide:
1. The vulnerable code (if not provided, create example)
2. Fixed/secure version of the code
3. Detailed explanation of the fix
4. Step-by-step remediation instructions
5. Additional security measures to consider

Format as structured response with clear sections.
"""

        result = await self.think(
            prompt, "You are a senior security engineer providing code remediation guidance."
        )

        # Parse AI response
        response = result["response"]

        return {
            "vulnerable": self._extract_section(response, "vulnerable code") or vulnerable_code,
            "fixed": self._extract_section(response, "fixed") or "See AI response",
            "explanation": self._extract_section(response, "explanation") or response,
            "steps": self._extract_steps(response),
            "additional_measures": self._extract_section(response, "additional") or [],
            "ai_generated": True,
        }

    def _extract_section(self, text: str, section_name: str) -> Optional[str]:
        """Extract section from AI response"""
        pattern = rf"{section_name}[:\s]+(.*?)(?=\n\n|\Z)"
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else None

    def _extract_steps(self, text: str) -> List[str]:
        """Extract numbered steps from AI response"""
        steps = re.findall(r"\d+\.\s+(.+)", text)
        return steps if steps else ["See full AI response for details"]

    async def generate_diff(self, vulnerable_code: str, fixed_code: str) -> str:
        """Generate unified diff between vulnerable and fixed code"""
        import difflib

        diff = difflib.unified_diff(
            vulnerable_code.splitlines(keepends=True),
            fixed_code.splitlines(keepends=True),
            fromfile="vulnerable.code",
            tofile="fixed.code",
            lineterm="",
        )

        return "".join(diff)
