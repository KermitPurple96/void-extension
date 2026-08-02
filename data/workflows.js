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
 * Each step:
 *   id          {string}   unique within the workflow
 *   name        {string}   human label
 *   type        {string}   'SKILL' | 'AGENT'
 *   skill       {string?}  skill reference (when type === 'SKILL')
 *   agent       {string?}  agent reference (when type === 'AGENT')
 *   dependsOn   {string[]} ids of steps that must complete first
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
        type: 'SKILL',
        skill: 'basic-recon',
        dependsOn: [],
      },
      {
        id: 'sqli',
        name: 'SQL Injection',
        type: 'SKILL',
        skill: 'sqli',
        dependsOn: ['recon'],
      },
      {
        id: 'xss',
        name: 'Cross-Site Scripting',
        type: 'SKILL',
        skill: 'xss',
        dependsOn: ['recon'],
      },
      {
        id: 'cmdi',
        name: 'Command Injection',
        type: 'SKILL',
        skill: 'cmdi',
        dependsOn: ['recon'],
      },
      {
        id: 'ssti',
        name: 'Server-Side Template Injection',
        type: 'SKILL',
        skill: 'ssti',
        dependsOn: ['recon'],
      },
      {
        id: 'lfi',
        name: 'Local File Inclusion',
        type: 'SKILL',
        skill: 'lfi',
        dependsOn: ['recon'],
      },
      {
        id: 'ssrf',
        name: 'Server-Side Request Forgery',
        type: 'SKILL',
        skill: 'ssrf',
        dependsOn: ['recon'],
      },
      {
        id: 'auth',
        name: 'Authentication / JWT Testing',
        type: 'SKILL',
        skill: 'jwt',
        dependsOn: ['recon'],
      },
      {
        id: 'idor',
        name: 'Insecure Direct Object Reference',
        type: 'SKILL',
        skill: 'idor',
        dependsOn: ['recon'],
      },
      {
        id: 'cors',
        name: 'CORS Misconfiguration',
        type: 'SKILL',
        skill: 'cors',
        dependsOn: ['recon'],
      },
      {
        id: 'csrf',
        name: 'Cross-Site Request Forgery',
        type: 'SKILL',
        skill: 'csrf',
        dependsOn: ['recon'],
      },
      {
        id: 'report',
        name: 'Generate Report',
        type: 'AGENT',
        agent: 'auditor',
        dependsOn: ['sqli', 'xss', 'cmdi', 'ssti', 'lfi', 'ssrf', 'auth', 'idor', 'cors', 'csrf'],
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
        type: 'SKILL',
        skill: 'basic-recon',
        dependsOn: [],
      },
      {
        id: 'sqli',
        name: 'SQL Injection',
        type: 'SKILL',
        skill: 'sqli',
        dependsOn: ['recon'],
      },
      {
        id: 'xss',
        name: 'Cross-Site Scripting',
        type: 'SKILL',
        skill: 'xss',
        dependsOn: ['recon'],
      },
      {
        id: 'cmdi',
        name: 'Command Injection',
        type: 'SKILL',
        skill: 'cmdi',
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
        type: 'SKILL',
        skill: 'sqli',
        dependsOn: [],
      },
      {
        id: 'xss',
        name: 'Cross-Site Scripting',
        type: 'SKILL',
        skill: 'xss',
        dependsOn: [],
      },
      {
        id: 'cmdi',
        name: 'Command Injection',
        type: 'SKILL',
        skill: 'cmdi',
        dependsOn: [],
      },
      {
        id: 'ssti',
        name: 'Server-Side Template Injection',
        type: 'SKILL',
        skill: 'ssti',
        dependsOn: [],
      },
      {
        id: 'xxe',
        name: 'XML External Entity',
        type: 'SKILL',
        skill: 'xxe',
        dependsOn: [],
      },
      {
        id: 'nosql',
        name: 'NoSQL Injection',
        type: 'SKILL',
        skill: 'nosql',
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
        type: 'SKILL',
        skill: 'jwt',
        dependsOn: [],
      },
      {
        id: 'csrf',
        name: 'Cross-Site Request Forgery',
        type: 'SKILL',
        skill: 'csrf',
        dependsOn: [],
      },
      {
        id: 'idor',
        name: 'Insecure Direct Object Reference',
        type: 'SKILL',
        skill: 'idor',
        dependsOn: [],
      },
      {
        id: 'cors',
        name: 'CORS Misconfiguration',
        type: 'SKILL',
        skill: 'cors',
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
        type: 'SKILL',
        skill: 'basic-recon',
        dependsOn: [],
      },
      {
        id: 'graphql',
        name: 'GraphQL Security',
        type: 'SKILL',
        skill: 'graphql',
        dependsOn: ['recon'],
      },
      {
        id: 'idor',
        name: 'Insecure Direct Object Reference',
        type: 'SKILL',
        skill: 'idor',
        dependsOn: ['recon'],
      },
      {
        id: 'jwt',
        name: 'API Auth / JWT',
        type: 'SKILL',
        skill: 'api-auth',
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
        type: 'SKILL',
        skill: 'basic-recon',
        dependsOn: [],
      },
      {
        id: 'xss',
        name: 'Cross-Site Scripting',
        type: 'SKILL',
        skill: 'xss',
        dependsOn: ['recon'],
      },
      {
        id: 'idor',
        name: 'Insecure Direct Object Reference',
        type: 'SKILL',
        skill: 'idor',
        dependsOn: ['recon'],
      },
      {
        id: 'cors',
        name: 'CORS Misconfiguration',
        type: 'SKILL',
        skill: 'cors',
        dependsOn: ['recon'],
      },
      {
        id: 'open-redirect',
        name: 'Open Redirect',
        type: 'SKILL',
        skill: 'open-redirect',
        dependsOn: ['recon'],
      },
      {
        id: 'tech-fingerprint',
        name: 'Technology Fingerprinting',
        type: 'SKILL',
        skill: 'tech-fingerprint',
        dependsOn: ['recon'],
      },
    ],
  },
];
