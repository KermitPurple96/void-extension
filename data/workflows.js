/**
 * Void Extension — Workflow DAG Definitions
 * Assigned to window.VOID_WORKFLOWS
 *
 * Each workflow contains:
 *   id          {string}   unique slug
 *   name        {string}   human label
 *   description {string}   one-liner
 *   category    {string}   'engagement' | 'composite'
 *   steps       {Step[]}   DAG nodes
 *
 * Step types: STEP (execution) or CONDITION (branching)
 *
 * STEP fields:
 *   id          {string}   unique within the workflow
 *   name        {string}   human label
 *   type        {string}   'STEP'
 *   agent       {string?}  agent to use for this step
 *   skills      {string[]} skill slugs to inject into context
 *   prompt      {string?}  prompt template id to use
 *   instructions {string?} free-text instructions from the user
 *   dependsOn   {string[]} ids of steps that must complete first
 *
 * CONDITION fields:
 *   id          {string}   unique within the workflow
 *   name        {string}   human label
 *   type        {string}   'CONDITION'
 *   condition   {string}   free-text for the AI to evaluate
 *   branches    {Branch[]} [{when: string, goto: string}]
 *   elseGoto    {string?}  default branch step id
 *   dependsOn   {string[]} ids of steps that must complete first
 *
 * The workflow engine maintains a memory object that accumulates across steps:
 *   - findings: all vulnerabilities found so far
 *   - notes: free-text notes from each step
 *   - requests: HTTP requests/responses captured
 *   - context: accumulated AI conversation history
 *   All tools remain available at every step.
 */

window.VOID_WORKFLOWS = [
  // ─────────────────────────────────────────────────────────────
  // 1. Full Penetration Test
  // ─────────────────────────────────────────────────────────────
  {
    id: 'full-pentest',
    name: 'Full Penetration Test',
    description: 'Complete security assessment covering recon, all major vuln classes, and a final report.',
    category: 'engagement',
    steps: [
      {
        id: 'recon',
        name: 'Reconnaissance',
        type: 'STEP',
        skills: ['basic-recon'],
        dependsOn: [],
      },
      {
        id: 'sqli',
        name: 'SQL Injection',
        type: 'STEP',
        skills: ['sqli'],
        dependsOn: ['recon'],
      },
      {
        id: 'xss',
        name: 'Cross-Site Scripting',
        type: 'STEP',
        skills: ['xss'],
        dependsOn: ['recon'],
      },
      {
        id: 'cmdi',
        name: 'Command Injection',
        type: 'STEP',
        skills: ['cmd-injection'],
        dependsOn: ['recon'],
      },
      {
        id: 'ssti',
        name: 'Server-Side Template Injection',
        type: 'STEP',
        skills: ['ssti'],
        dependsOn: ['recon'],
      },
      {
        id: 'lfi',
        name: 'Local File Inclusion',
        type: 'STEP',
        skills: ['lfi-rfi'],
        dependsOn: ['recon'],
      },
      {
        id: 'ssrf',
        name: 'Server-Side Request Forgery',
        type: 'STEP',
        skills: ['ssrf'],
        dependsOn: ['recon'],
      },
      {
        id: 'auth',
        name: 'Authentication / JWT Testing',
        type: 'STEP',
        skills: ['jwt'],
        dependsOn: ['recon'],
      },
      {
        id: 'idor',
        name: 'Insecure Direct Object Reference',
        type: 'STEP',
        skills: ['idor'],
        dependsOn: ['recon'],
      },
      {
        id: 'cors',
        name: 'CORS Misconfiguration',
        type: 'STEP',
        skills: ['cors'],
        dependsOn: ['recon'],
      },
      {
        id: 'csrf',
        name: 'Cross-Site Request Forgery',
        type: 'STEP',
        skills: ['csrf'],
        dependsOn: ['recon'],
      },
      {
        id: 'report',
        name: 'Generate Report',
        type: 'STEP',
        agent: 'auditor',
        skills: [],
        prompt: 'generate-report',
        instructions: 'Compile all findings from previous steps into a structured security report with CVSS scores and remediation.',
        dependsOn: ['sqli', 'xss', 'cmdi', 'ssti', 'lfi', 'ssrf', 'auth', 'idor', 'cors', 'csrf'],
      },
      {
        id: 'finish',
        name: 'Assessment Complete',
        type: 'FINISH',
        instructions: 'Save workflow memory, export findings, and notify the user that the assessment is complete.',
        dependsOn: ['report'],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────
  // 2. Quick Vulnerability Scan
  // ─────────────────────────────────────────────────────────────
  {
    id: 'quick-vuln-scan',
    name: 'Quick Vulnerability Scan',
    description: 'Fast scan targeting the most common web vulnerabilities.',
    category: 'engagement',
    steps: [
      {
        id: 'recon',
        name: 'Reconnaissance',
        type: 'STEP',
        skills: ['basic-recon'],
        dependsOn: [],
      },
      {
        id: 'sqli',
        name: 'SQL Injection',
        type: 'STEP',
        skills: ['sqli'],
        dependsOn: ['recon'],
      },
      {
        id: 'xss',
        name: 'Cross-Site Scripting',
        type: 'STEP',
        skills: ['xss'],
        dependsOn: ['recon'],
      },
      {
        id: 'cmdi',
        name: 'Command Injection',
        type: 'STEP',
        skills: ['cmd-injection'],
        dependsOn: ['recon'],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────
  // 3. Injection Testing Suite
  // ─────────────────────────────────────────────────────────────
  {
    id: 'injection-testing',
    name: 'Injection Testing Suite',
    description: 'Comprehensive sweep of all injection vulnerability classes, run in parallel.',
    category: 'composite',
    steps: [
      {
        id: 'sqli',
        name: 'SQL Injection',
        type: 'STEP',
        skills: ['sqli'],
        dependsOn: [],
      },
      {
        id: 'xss',
        name: 'Cross-Site Scripting',
        type: 'STEP',
        skills: ['xss'],
        dependsOn: [],
      },
      {
        id: 'cmdi',
        name: 'Command Injection',
        type: 'STEP',
        skills: ['cmd-injection'],
        dependsOn: [],
      },
      {
        id: 'ssti',
        name: 'Server-Side Template Injection',
        type: 'STEP',
        skills: ['ssti'],
        dependsOn: [],
      },
      {
        id: 'xxe',
        name: 'XML External Entity',
        type: 'STEP',
        skills: ['xxe'],
        dependsOn: [],
      },
      {
        id: 'nosql',
        name: 'NoSQL Injection',
        type: 'STEP',
        skills: ['nosql'],
        dependsOn: [],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────
  // 4. Auth & Session Testing
  // ─────────────────────────────────────────────────────────────
  {
    id: 'auth-session-testing',
    name: 'Auth & Session Testing',
    description: 'Parallel assessment of authentication and session management vulnerabilities.',
    category: 'composite',
    steps: [
      {
        id: 'jwt',
        name: 'JWT Security',
        type: 'STEP',
        skills: ['jwt'],
        dependsOn: [],
      },
      {
        id: 'csrf',
        name: 'Cross-Site Request Forgery',
        type: 'STEP',
        skills: ['csrf'],
        dependsOn: [],
      },
      {
        id: 'idor',
        name: 'Insecure Direct Object Reference',
        type: 'STEP',
        skills: ['idor'],
        dependsOn: [],
      },
      {
        id: 'cors',
        name: 'CORS Misconfiguration',
        type: 'STEP',
        skills: ['cors'],
        dependsOn: [],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────
  // 5. API Security Audit
  // ─────────────────────────────────────────────────────────────
  {
    id: 'api-security-audit',
    name: 'API Security Audit',
    description: 'Targeted security audit for REST and GraphQL APIs.',
    category: 'composite',
    steps: [
      {
        id: 'recon',
        name: 'API Reconnaissance',
        type: 'STEP',
        skills: ['basic-recon'],
        dependsOn: [],
      },
      {
        id: 'graphql',
        name: 'GraphQL Security',
        type: 'STEP',
        skills: ['graphql'],
        dependsOn: ['recon'],
      },
      {
        id: 'idor',
        name: 'Insecure Direct Object Reference',
        type: 'STEP',
        skills: ['idor'],
        dependsOn: ['recon'],
      },
      {
        id: 'jwt',
        name: 'API Auth / JWT',
        type: 'STEP',
        skills: ['jwt'],
        dependsOn: ['recon'],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────
  // 6. Bug Bounty Quick Wins
  // ─────────────────────────────────────────────────────────────
  {
    id: 'bug-bounty-quickwins',
    name: 'Bug Bounty Quick Wins',
    description: 'Rapid identification of high-impact, easy-to-find vulnerabilities popular in bug bounty programmes.',
    category: 'engagement',
    steps: [
      {
        id: 'recon',
        name: 'Reconnaissance',
        type: 'STEP',
        skills: ['basic-recon'],
        dependsOn: [],
      },
      {
        id: 'xss',
        name: 'Cross-Site Scripting',
        type: 'STEP',
        skills: ['xss'],
        dependsOn: ['recon'],
      },
      {
        id: 'idor',
        name: 'Insecure Direct Object Reference',
        type: 'STEP',
        skills: ['idor'],
        dependsOn: ['recon'],
      },
      {
        id: 'cors',
        name: 'CORS Misconfiguration',
        type: 'STEP',
        skills: ['cors'],
        dependsOn: ['recon'],
      },
      {
        id: 'open-redirect',
        name: 'Open Redirect',
        type: 'STEP',
        skills: ['open-redirect'],
        dependsOn: ['recon'],
      },
      {
        id: 'tech-fingerprint',
        name: 'Technology Fingerprinting',
        type: 'STEP',
        skills: ['tech-fingerprint'],
        dependsOn: ['recon'],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────
  // 7. Adaptive Scan (with conditionals)
  // ─────────────────────────────────────────────────────────
  {
    id: 'adaptive-scan',
    name: 'Adaptive Scan',
    description: 'Intelligent scan that adapts testing based on recon results — tests auth flows only if login detected, tests API vulns only if API endpoints found.',
    category: 'engagement',
    editable: true,
    steps: [
      {
        id: 'recon',
        name: 'Reconnaissance',
        type: 'STEP',
        skills: ['basic-recon'],
        dependsOn: [],
      },
      {
        id: 'check-auth',
        name: 'What did recon find?',
        type: 'CONDITION',
        condition: 'Based on the reconnaissance results, decide which testing path to follow',
        branches: [
          { when: 'Login page or authentication form detected', goto: 'auth-test' },
          { when: 'Only static content or simple pages found', goto: 'xss-test' },
        ],
        elseGoto: 'injection-test',
        dependsOn: ['recon'],
      },
      {
        id: 'auth-test',
        name: 'Authentication Testing',
        type: 'STEP',
        skills: ['jwt'],
        agent: 'authhunter',
        dependsOn: ['check-auth'],
      },
      {
        id: 'injection-test',
        name: 'Injection Testing',
        type: 'STEP',
        skills: ['sqli'],
        dependsOn: ['check-auth'],
      },
      {
        id: 'xss-test',
        name: 'XSS Testing',
        type: 'STEP',
        skills: ['xss'],
        dependsOn: ['check-auth'],
      },
      {
        id: 'check-api',
        name: 'What endpoints were found?',
        type: 'CONDITION',
        condition: 'Based on injection and XSS testing results, decide next steps',
        branches: [
          { when: 'REST or GraphQL API endpoints found', goto: 'api-test' },
        ],
        elseGoto: 'report',
        dependsOn: ['check-auth'],
      },
      {
        id: 'api-test',
        name: 'API Security Audit',
        type: 'STEP',
        skills: ['idor'],
        agent: 'apihunter',
        dependsOn: ['check-api'],
      },
      {
        id: 'report',
        name: 'Generate Report',
        type: 'STEP',
        agent: 'auditor',
        dependsOn: ['check-api'],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────
  // 8. OWASP Top 10 Comprehensive
  // ─────────────────────────────────────────────────────────
  {
    id: 'owasp-top10',
    name: 'OWASP Top 10',
    description: 'Systematic testing against all OWASP Top 10 2021 categories with conditional escalation.',
    category: 'engagement',
    steps: [
      {
        id: 'recon',
        name: 'Reconnaissance & Mapping',
        type: 'STEP',
        skills: ['basic-recon'],
        dependsOn: [],
      },
      {
        id: 'a01-broken-access',
        name: 'A01: Broken Access Control',
        type: 'STEP',
        skills: ['idor'],
        dependsOn: ['recon'],
      },
      {
        id: 'a02-crypto',
        name: 'A02: Cryptographic Failures',
        type: 'STEP',
        skills: ['crypto'],
        dependsOn: ['recon'],
      },
      {
        id: 'a03-injection',
        name: 'A03: Injection',
        type: 'STEP',
        skills: ['sqli'],
        dependsOn: ['recon'],
      },
      {
        id: 'a03-xss',
        name: 'A03: XSS',
        type: 'STEP',
        skills: ['xss'],
        dependsOn: ['recon'],
      },
      {
        id: 'a03-ssti',
        name: 'A03: SSTI',
        type: 'STEP',
        skills: ['ssti'],
        dependsOn: ['recon'],
      },
      {
        id: 'a04-insecure-design',
        name: 'A04: Insecure Design',
        type: 'STEP',
        skills: ['business-logic'],
        dependsOn: ['recon'],
      },
      {
        id: 'a05-misconfig',
        name: 'A05: Security Misconfiguration',
        type: 'STEP',
        skills: ['misconfig'],
        dependsOn: ['recon'],
      },
      {
        id: 'a07-auth',
        name: 'A07: Auth Failures',
        type: 'STEP',
        skills: ['jwt'],
        dependsOn: ['recon'],
      },
      {
        id: 'a08-integrity',
        name: 'A08: Software & Data Integrity',
        type: 'STEP',
        skills: ['deserialization'],
        dependsOn: ['recon'],
      },
      {
        id: 'a10-ssrf',
        name: 'A10: SSRF',
        type: 'STEP',
        skills: ['ssrf'],
        dependsOn: ['recon'],
      },
      {
        id: 'check-critical',
        name: 'Assess severity of findings',
        type: 'CONDITION',
        condition: 'Based on all findings so far, decide whether deep exploitation is warranted',
        branches: [
          { when: 'Critical or high severity vulnerabilities confirmed', goto: 'deep-exploit' },
        ],
        elseGoto: 'report',
        dependsOn: ['a01-broken-access', 'a03-injection', 'a03-xss', 'a10-ssrf'],
      },
      {
        id: 'deep-exploit',
        name: 'Deep Exploitation',
        type: 'STEP',
        agent: 'pentester',
        dependsOn: ['check-critical'],
      },
      {
        id: 'report',
        name: 'Generate Report',
        type: 'STEP',
        agent: 'auditor',
        dependsOn: ['a01-broken-access', 'a02-crypto', 'a03-injection', 'a03-xss', 'a03-ssti', 'a04-insecure-design', 'a05-misconfig', 'a07-auth', 'a08-integrity', 'a10-ssrf', 'check-critical'],
      },
    ],
  },
];
