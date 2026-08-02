window.VOID_PROMPTS = [
  {
    id: 'recon-target',
    name: 'Recon Target',
    category: 'recon',
    template: 'Perform reconnaissance on {{target}}. Map the attack surface: discover endpoints, identify technologies, find forms and input points, check security headers, and analyze cookies. Report a structured summary.',
    tags: ['target']
  },
  {
    id: 'test-vuln-class',
    name: 'Test Vuln Class',
    category: 'detection',
    template: 'Test {{target}} for {{vuln_class}} vulnerabilities. Use the /{{vuln_class}} skill methodology. Start with safe detection payloads, then escalate if indicators are found. Record all findings with evidence.',
    tags: ['target', 'vuln_class']
  },
  {
    id: 'analyze-response',
    name: 'Analyze Response',
    category: 'analysis',
    template: 'Analyze this HTTP response for security issues:\n\nURL: {{url}}\nStatus: {{status}}\nHeaders: {{headers}}\nBody (first 2000 chars): {{body}}\n\nLook for: error messages, stack traces, version disclosure, reflected input, security header gaps.',
    tags: ['url', 'status', 'headers', 'body']
  },
  {
    id: 'exploit-finding',
    name: 'Exploit Finding',
    category: 'exploitation',
    template: 'A {{vuln_type}} vulnerability was detected at {{url}} in the {{parameter}} parameter. The detection payload was: {{payload}}. Attempt to escalate this finding: extract data, achieve RCE, or demonstrate maximum impact. Follow the engagement config safety rules.',
    tags: ['vuln_type', 'url', 'parameter', 'payload']
  },
  {
    id: 'generate-report',
    name: 'Generate Report',
    category: 'reporting',
    template: 'Generate a security assessment report for {{target}}. Read all findings, assign CVSS scores, group by severity, and produce an executive summary followed by detailed technical findings with remediation recommendations.',
    tags: ['target']
  },
  {
    id: 'bypass-waf',
    name: 'Bypass WAF',
    category: 'exploitation',
    template: 'The {{vuln_type}} payload "{{payload}}" is being blocked at {{url}} (parameter: {{parameter}}). The response indicates {{waf_indicator}}. Try bypass techniques: encoding, obfuscation, alternative syntax, method switching. Document each attempt and result.',
    tags: ['vuln_type', 'payload', 'url', 'parameter', 'waf_indicator']
  },
  {
    id: 'judge-response',
    name: 'Judge Response',
    category: 'hybrid',
    template: 'You are a vulnerability judge. Given the HTTP exchange below, determine if {{vuln_type}} is present.\n\nPayload: {{payload}}\nURL: {{url}}\nHTTP Status: {{status}}\nResponse (first 2000 chars): {{response}}\nPattern matched: {{pattern}}\n\nRespond ONLY with JSON: {"vulnerable": true/false, "evidence": "exact text from response proving it", "confidence": 0.0-1.0}',
    tags: ['vuln_type', 'payload', 'url', 'status', 'response', 'pattern']
  },
  {
    id: 'refute-finding',
    name: 'Refute Finding',
    category: 'hybrid',
    template: 'A {{vuln_type}} finding was reported at {{url}}. Evidence: {{evidence}}. Payload: {{payload}}.\n\nActively look for reasons this could be a FALSE POSITIVE. Consider: is the reflection actually in a safe context? Could the pattern match be coincidental? Is the behavior normal for this application?\n\nRespond ONLY with JSON: {"false_positive": true/false, "reason": "explanation"}',
    tags: ['vuln_type', 'url', 'evidence', 'payload']
  }
];
