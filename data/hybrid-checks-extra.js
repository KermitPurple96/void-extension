// data/hybrid-checks-extra.js — Additional hybrid checks (upload, csrf, auth, idor, redirect, session, authz, csp)
// Extends window.VOID_HYBRID_CHECKS defined in hybrid-checks.js

Object.assign(window.VOID_HYBRID_CHECKS, {

  upload: {
    id: 'upload',
    name: 'File Upload',
    description: 'Detect insecure file upload by testing extension and content-type bypass',
    riskIfFound: 'critical',
    injectIn: 'file',
    method: 'POST',
    payloads: [
      'test.php', 'test.php.jpg', 'test.pHp', 'test.php%00.jpg',
      'test.asp', 'test.aspx', 'test.jsp',
      'test.svg', 'test.html', 'test.shtml',
    ],
    patterns: [
      /file.*uploaded.*successfully/i,
      /upload.*complete/i,
      /saved.*successfully/i,
    ],
    fileUpload: true,
  },

  csrf: {
    id: 'csrf',
    name: 'CSRF',
    description: 'Detect missing or weak CSRF protections on state-changing endpoints',
    riskIfFound: 'medium',
    injectIn: 'header',
    method: 'POST',
    payloads: [], // no injection payloads — this is a passive check
    patterns: [
      /csrf/i,
      /_token/i,
      /authenticity_token/i,
      /csrfmiddlewaretoken/i,
      /X-CSRF-Token/i,
      /X-XSRF-Token/i,
    ],
    passive: true, // check: are CSRF tokens present in forms/headers?
  },

  auth_brute: {
    id: 'auth_brute',
    name: 'Authentication Brute Force',
    description: 'Detect weak credentials by testing common username/password pairs on login endpoints',
    riskIfFound: 'high',
    injectIn: 'body',
    method: 'POST',
    payloads: [
      'admin:admin', 'admin:password', 'admin:123456', 'admin:admin123',
      'root:root', 'root:toor', 'test:test', 'user:user',
      'admin:changeme', 'admin:Password1',
    ],
    patterns: [
      /welcome/i,
      /dashboard/i,
      /logged in/i,
      /login successful/i,
      /302/,  // redirect after successful login
    ],
    authCheck: true,
  },

  idor: {
    id: 'idor',
    name: 'IDOR / BOLA',
    description: 'Detect insecure direct object references by incrementing/changing ID parameters',
    riskIfFound: 'medium',
    injectIn: 'param',
    method: 'GET',
    payloads: [
      '1', '2', '0', '-1', '999999',
      '00000000-0000-0000-0000-000000000001',
      '../1', '1;2',
    ],
    patterns: [],
    idor: true, // special: compare responses for different IDs to detect unauthorized access
  },

  open_redirect: {
    id: 'open_redirect',
    name: 'Open Redirect',
    description: 'Detect open redirect by injecting external URLs in redirect parameters',
    riskIfFound: 'low',
    injectIn: 'param',
    method: 'GET',
    payloads: [
      'https://evil.com',
      '//evil.com',
      'https://evil.com%2f%2f',
      '/\\evil.com',
      'https://evil.com%00.trusted.com',
      '//evil%252ecom',
      'https:evil.com',
      '////evil.com',
      'https://trusted.com@evil.com',
      'https://evil.com#trusted.com',
    ],
    patterns: [
      /location:\s*https?:\/\/evil\.com/i,
      /refresh:\s*\d+;\s*url=.*evil\.com/i,
    ],
    redirect: true, // check Location header and meta refresh for redirects to evil.com
  },

  weak_session: {
    id: 'weak_session',
    name: 'Weak Session Management',
    description: 'Detect weak session tokens by checking cookie flags and token entropy',
    riskIfFound: 'medium',
    injectIn: 'none',
    method: 'GET',
    payloads: [],
    patterns: [],
    sessionCheck: true, // passive: analyze Set-Cookie headers for HttpOnly, Secure, SameSite, entropy
  },

  authz_bypass: {
    id: 'authz_bypass',
    name: 'Authorization Bypass',
    description: 'Detect authorization bypass by accessing protected endpoints without proper credentials',
    riskIfFound: 'high',
    injectIn: 'header',
    method: 'GET',
    payloads: [
      '', // no auth header
      'Bearer invalid',
      'Bearer null',
      'Basic YWRtaW46YWRtaW4=', // admin:admin
    ],
    patterns: [
      /200 OK/,
      /admin/i,
      /dashboard/i,
      /unauthorized/i,
      /forbidden/i,
    ],
    authzCheck: true, // compare: request with valid auth vs request with manipulated/missing auth
  },

  csp: {
    id: 'csp',
    name: 'Content Security Policy',
    description: 'Analyze CSP header for unsafe directives that weaken XSS protections',
    riskIfFound: 'low',
    injectIn: 'none',
    method: 'GET',
    payloads: [],
    patterns: [
      /unsafe-inline/i,
      /unsafe-eval/i,
      /\*/,        // wildcard sources
      /data:/i,
      /blob:/i,
      /http:/i,    // non-HTTPS sources in CSP
    ],
    headerCheck: true, // passive: parse Content-Security-Policy header
  },

});
