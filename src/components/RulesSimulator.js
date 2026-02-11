import React, { useState } from 'react';
import yaml from 'js-yaml';
import { WAF_FLAGS, SEVERITY_COLORS } from '../data/wafData';
import './RulesSimulator.css';

const RulesSimulator = () => {
  const [cdnYaml, setCdnYaml] = useState('');
  const [testRequest, setTestRequest] = useState({
    path: '/jp/products/page',
    url: 'https://preview.your-domain.com/jp/products/page',
    queryString: '',
    method: 'GET',
    domain: 'preview.your-domain.com',
    tier: 'publish',
    clientIp: '203.0.113.50',
    clientCountry: 'US',
    clientRegion: 'CA',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    referer: '',
    protocol: 'https',
    headers: {}
  });
  
  const [simulationResults, setSimulationResults] = useState(null);
  const [parseError, setParseError] = useState(null);
  const [activeTab, setActiveTab] = useState('config');

  // Order of evaluation from Adobe docs
  const EVALUATION_ORDER = [
    { id: 'requestTransformations', name: 'Request Transformations', icon: '🔄', description: 'Modify incoming request headers, paths, parameters' },
    { id: 'trafficFilters', name: 'Traffic Filter Rules (WAF)', icon: '🛡️', description: 'Block or log malicious traffic' },
    { id: 'responseTransformations', name: 'Response Transformations', icon: '📤', description: 'Modify outgoing response headers' },
    { id: 'originSelectors', name: 'Origin Selectors', icon: '🎯', description: 'Route to different backend origins' },
    { id: 'redirects', name: 'Redirects', icon: '↪️', description: 'Server-side redirects (301/302)' }
  ];

  // Sample cdn.yaml with request transformation examples
  const SAMPLE_CDN_YAML = `kind: "CDN"
version: "1"
metadata:
  envTypes:
    - dev
    - stage
    - prod
data:
  # ---------------------------------------------------------------------------
  # TRAFFIC FILTER RULES - Security & Access Control
  # ---------------------------------------------------------------------------
  trafficFilters:
    rules:
      # IP Allowlist Example - Restrict access to specific IPs
      - name: "preview-ip-allowlist"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: domain, equals: "preview.your-domain.com" }
            - { reqProperty: clientIp, notIn: [
                "10.0.0.0/8",       # Private network
                "172.16.0.0/12",    # Private network
                "192.168.0.0/16",   # Private network
              ] }
        action:
          type: block

      # WAF - Block attacks from known bad IPs (Adobe recommended)
      - name: "block-attacks-from-bad-ips"
        when:
          reqProperty: tier
          in: ["author", "publish"]
        action:
          type: block
          wafFlags:
            - ATTACK-FROM-BAD-IP

      # WAF - Log all attack patterns (Adobe recommended)
      - name: "log-all-attacks"
        when:
          reqProperty: tier
          in: ["author", "publish"]
        action:
          type: log
          wafFlags:
            - ATTACK

      # Rate Limiting - Origin requests
      - name: "rate-limit-origin"
        when:
          reqProperty: tier
          equals: publish
        rateLimit:
          limit: 100
          window: 10
          count: fetches
          penalty: 300
          groupBy:
            - reqProperty: clientIp
        action: log

      # Rate Limiting - Edge requests
      - name: "rate-limit-edge"
        when:
          reqProperty: tier
          equals: publish
        rateLimit:
          limit: 500
          window: 10
          count: all
          penalty: 300
          groupBy:
            - reqProperty: clientIp
        action: log

      # Block OFAC sanctioned countries
      - name: "block-ofac-countries"
        when:
          allOf:
            - { reqProperty: tier, in: ["author", "publish"] }
            - reqProperty: clientCountry
              in: [SY, BY, MM, KP, IQ, CD, SD, IR, LR, ZW, CU, CI]
        action: block

      # Block admin paths on publish
      - name: "block-admin-paths"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: path, like: "/admin/*" }
        action: block

  # ---------------------------------------------------------------------------
  # REQUEST TRANSFORMATIONS - Modify incoming requests
  # ---------------------------------------------------------------------------
  requestTransformations:
    removeMarketingParams: true
    rules:
      # Set authorization header from secret
      - name: "set-auth-header"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: domain, equals: "preview.your-domain.com" }
        actions:
          - type: set
            reqHeader: authorization
            value: "\${{YOUR_SITE_TOKEN}}"
          - type: transform
            reqHeader: authorization
            op: replace
            match: "^(?!token\\\\s+)(.*)$"
            replacement: "token \\\\1"

      # Root path rewrite to default language
      - name: "rewrite-root-to-default-lang"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: path, equals: "/" }
        actions:
          - type: transform
            reqProperty: path
            op: replace
            match: "^/$"
            replacement: "/us/en"

      # Language prefix rewrite: /jp/* -> /jp/ja/*
      - name: "rewrite-jp-language"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: path, matches: "^/jp(/.*)?$" }
            - { reqProperty: path, doesNotMatch: "^/jp/ja(/.*)?$" }
            - { reqProperty: path, doesNotMatch: ".*\\\\.html$" }
            - { reqProperty: path, doesNotMatch: "^/(content|etc|media_).*$" }
        actions:
          - type: transform
            reqProperty: path
            op: replace
            match: "^/jp(/.*)?$"
            replacement: "/jp/ja\\\\1"

      # Catch-all language prefix: /* -> /us/en/*
      - name: "rewrite-default-language"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: path, doesNotMatch: "^/us/en(/.*)?$" }
            - { reqProperty: path, doesNotMatch: "^/jp(/.*)?$" }
            - { reqProperty: path, doesNotMatch: "^/$" }
            - { reqProperty: path, doesNotMatch: ".*\\\\.html$" }
            - { reqProperty: path, doesNotMatch: "^/(content|etc|media_).*$" }
        actions:
          - type: transform
            reqProperty: path
            op: replace
            match: "^/(.*)$"
            replacement: "/us/en/\\\\1"

  # ---------------------------------------------------------------------------
  # ORIGIN SELECTORS - Route to different backends
  # ---------------------------------------------------------------------------
  originSelectors:
    rules:
      - name: "route-to-preview-origin"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: domain, equals: "preview.your-domain.com" }
        action:
          type: selectOrigin
          originName: preview-origin

      - name: "route-to-live-origin"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: domain, equals: "www.your-domain.com" }
        action:
          type: selectOrigin
          originName: live-origin

    origins:
      - name: preview-origin
        domain: main--your-repo--your-org.aem.page
        forwardCookie: true
        forwardAuthorization: true

      - name: live-origin
        domain: main--your-repo--your-org.aem.live
        forwardCookie: true
        forwardAuthorization: true

  # ---------------------------------------------------------------------------
  # REDIRECTS - URL Normalization
  # ---------------------------------------------------------------------------
  redirects:
    rules:
      # Normalize case and underscores
      - name: "normalize-case-underscores"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: path, matches: ".*[A-Z_].*" }
            - { reqProperty: path, doesNotMatch: ".*\\\\.(png|jpg|css|js)$" }
        action:
          type: redirect
          status: 301
          location:
            reqProperty: path
            transform:
              - op: replace
                match: "_"
                replacement: "-"
              - op: tolower

      # Remove .html extension
      - name: "normalize-remove-html"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: path, matches: "^(?!.*?/index\\\\.html$).+\\\\.html$" }
        action:
          type: redirect
          status: 301
          location:
            reqProperty: path
            transform:
              - op: replace
                match: "\\\\.html$"
                replacement: ""

      # Remove trailing slash
      - name: "normalize-trailing-slash"
        when:
          allOf:
            - { reqProperty: tier, equals: "publish" }
            - { reqProperty: path, matches: "^.+/$" }
        action:
          type: redirect
          status: 301
          location:
            reqProperty: path
            transform:
              - op: replace
                match: "/$"
                replacement: ""

  # ---------------------------------------------------------------------------
  # RESPONSE TRANSFORMATIONS - Security Headers
  # ---------------------------------------------------------------------------
  responseTransformations:
    rules:
      - name: "security-headers"
        when:
          reqProperty: tier
          equals: publish
        actions:
          - type: set
            respHeader: Strict-Transport-Security
            value: "max-age=31536000; includeSubDomains; preload"
          - type: set
            respHeader: X-Content-Type-Options
            value: "nosniff"
          - type: set
            respHeader: X-Frame-Options
            value: "SAMEORIGIN"
          - type: set
            respHeader: Referrer-Policy
            value: "strict-origin-when-cross-origin"
          - type: set
            respHeader: Permissions-Policy
            value: "geolocation=(), microphone=(), camera=()"
`;

  // Helper function to check if IP is in CIDR range
  const ipInCidr = (ip, cidr) => {
    try {
      // Handle exact IP match (no CIDR notation)
      if (!cidr.includes('/')) {
        return ip === cidr;
      }
      
      const [range, bits] = cidr.split('/');
      const mask = ~(2 ** (32 - parseInt(bits)) - 1);
      
      const ipToInt = (ipStr) => {
        const parts = ipStr.split('.');
        if (parts.length !== 4) return 0;
        return parts.reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
      };
      
      const ipInt = ipToInt(ip);
      const rangeInt = ipToInt(range);
      
      return (ipInt & mask) === (rangeInt & mask);
    } catch (e) {
      return false;
    }
  };

  // Helper to check if IP matches any in a list (supports CIDR)
  const ipMatchesList = (ip, list) => {
    if (!Array.isArray(list)) return false;
    return list.some(entry => ipInCidr(ip, entry));
  };

  // Evaluate a single condition against request - returns detailed result
  const evaluateCondition = (condition, request, depth = 0) => {
    try {
      if (!condition) return { matches: true, reason: 'No condition (always matches)', details: [] };
      
      // Handle wildcard condition
      if (condition === '*') {
        return { matches: true, reason: 'Wildcard condition - matches all requests', details: [] };
      }
      
      // Handle allOf (AND logic)
      if (condition.allOf) {
        const results = condition.allOf.map((c, i) => ({
          index: i + 1,
          ...evaluateCondition(c, request, depth + 1)
        }));
        const allMatch = results.every(r => r.matches);
        const failedConditions = results.filter(r => !r.matches);
        
        return {
          matches: allMatch,
          type: 'allOf',
          reason: allMatch 
            ? `✓ ALL ${results.length} conditions matched` 
            : `✗ ${failedConditions.length} of ${results.length} conditions failed`,
          details: results,
          failedConditions
        };
      }
      
      // Handle anyOf (OR logic)
      if (condition.anyOf) {
        const results = condition.anyOf.map((c, i) => ({
          index: i + 1,
          ...evaluateCondition(c, request, depth + 1)
        }));
        const anyMatch = results.some(r => r.matches);
        const matchedConditions = results.filter(r => r.matches);
        
        return {
          matches: anyMatch,
          type: 'anyOf',
          reason: anyMatch 
            ? `✓ ${matchedConditions.length} of ${results.length} conditions matched (only 1 needed)` 
            : `✗ None of ${results.length} conditions matched`,
          details: results
        };
      }
      
      // Get the property name and value from request
      const propName = condition.reqProperty;
      let propValue = getPropertyValue(request, propName, condition);
    
    // Evaluate each operator type
    if (condition.equals !== undefined) {
      const matches = String(propValue) === String(condition.equals);
      return { 
        matches, 
        property: propName,
        operator: 'equals',
        expected: condition.equals,
        actual: propValue,
        reason: matches 
          ? `✓ ${propName} equals "${condition.equals}"` 
          : `✗ ${propName} "${propValue}" does not equal "${condition.equals}"`
      };
    }
    
    if (condition.notEquals !== undefined) {
      const matches = String(propValue) !== String(condition.notEquals);
      return { 
        matches, 
        property: propName,
        operator: 'notEquals',
        expected: condition.notEquals,
        actual: propValue,
        reason: matches 
          ? `✓ ${propName} "${propValue}" is not equal to "${condition.notEquals}"` 
          : `✗ ${propName} "${propValue}" equals "${condition.notEquals}" (should not)`
      };
    }
    
    if (condition.like !== undefined) {
      // Convert glob pattern to regex
      const pattern = condition.like
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.');
      const regex = new RegExp(`^${pattern}$`, 'i');
      const matches = regex.test(propValue);
      return { 
        matches, 
        property: propName,
        operator: 'like',
        pattern: condition.like,
        actual: propValue,
        reason: matches 
          ? `✓ ${propName} "${propValue}" matches glob pattern "${condition.like}"` 
          : `✗ ${propName} "${propValue}" does not match glob pattern "${condition.like}"`
      };
    }
    
    if (condition.notLike !== undefined) {
      const pattern = condition.notLike
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.');
      const regex = new RegExp(`^${pattern}$`, 'i');
      const matches = !regex.test(propValue);
      return { 
        matches, 
        property: propName,
        operator: 'notLike',
        pattern: condition.notLike,
        actual: propValue,
        reason: matches 
          ? `✓ ${propName} "${propValue}" does not match glob pattern "${condition.notLike}"` 
          : `✗ ${propName} "${propValue}" matches glob pattern "${condition.notLike}" (should not)`
      };
    }
    
    if (condition.matches !== undefined) {
      try {
        const regex = new RegExp(condition.matches);
        const matches = regex.test(propValue);
        return { 
          matches, 
          property: propName,
          operator: 'matches',
          pattern: condition.matches,
          actual: propValue,
          reason: matches 
            ? `✓ ${propName} "${propValue}" matches regex /${condition.matches}/` 
            : `✗ ${propName} "${propValue}" does not match regex /${condition.matches}/`
        };
      } catch (e) {
        return { matches: false, reason: `Invalid regex: ${condition.matches}`, error: e.message };
      }
    }
    
    if (condition.doesNotMatch !== undefined) {
      try {
        const regex = new RegExp(condition.doesNotMatch);
        const matches = !regex.test(propValue);
        return { 
          matches, 
          property: propName,
          operator: 'doesNotMatch',
          pattern: condition.doesNotMatch,
          actual: propValue,
          reason: matches 
            ? `✓ ${propName} "${propValue}" does not match regex /${condition.doesNotMatch}/` 
            : `✗ ${propName} "${propValue}" matches regex /${condition.doesNotMatch}/ (should not)`
        };
      } catch (e) {
        return { matches: false, reason: `Invalid regex`, error: e.message };
      }
    }
    
    if (condition.in !== undefined) {
      // Special handling for IP addresses with CIDR notation
      let matches;
      if (propName === 'clientIp') {
        matches = ipMatchesList(propValue, condition.in);
      } else {
        matches = condition.in.includes(propValue);
      }
      const listPreview = condition.in.length > 5 
        ? `[${condition.in.slice(0, 3).join(', ')}, ... +${condition.in.length - 3} more]`
        : `[${condition.in.join(', ')}]`;
      return { 
        matches, 
        property: propName,
        operator: 'in',
        expected: condition.in,
        actual: propValue,
        reason: matches 
          ? `✓ ${propName} "${propValue}" is in list ${listPreview}` 
          : `✗ ${propName} "${propValue}" is not in list ${listPreview}`
      };
    }
    
    if (condition.notIn !== undefined) {
      // Special handling for IP addresses with CIDR notation
      let matches;
      if (propName === 'clientIp') {
        matches = !ipMatchesList(propValue, condition.notIn);
      } else {
        matches = !condition.notIn.includes(propValue);
      }
      const listPreview = condition.notIn.length > 5 
        ? `[${condition.notIn.slice(0, 3).join(', ')}, ... +${condition.notIn.length - 3} more]`
        : `[${condition.notIn.join(', ')}]`;
      return { 
        matches, 
        property: propName,
        operator: 'notIn',
        expected: condition.notIn,
        actual: propValue,
        reason: matches 
          ? `✓ ${propName} "${propValue}" is not in list ${listPreview}` 
          : `✗ ${propName} "${propValue}" is in list ${listPreview} (should not be)`
      };
    }
    
    if (condition.exists !== undefined) {
      const exists = propValue !== undefined && propValue !== null && propValue !== '';
      const matches = condition.exists ? exists : !exists;
      return { 
        matches, 
        property: propName,
        operator: 'exists',
        expected: condition.exists,
        actual: propValue,
        reason: matches 
          ? `✓ ${propName} ${condition.exists ? 'exists' : 'does not exist'}` 
          : `✗ ${propName} ${exists ? 'exists' : 'does not exist'} (expected ${condition.exists ? 'to exist' : 'not to exist'})`
      };
    }
    
    return { matches: true, reason: 'Condition not recognized (defaulting to match)' };
    } catch (err) {
      return { 
        matches: false, 
        reason: `⚠️ Error evaluating condition: ${err.message}`,
        error: err.message
      };
    }
  };

  // Get property value from request
  const getPropertyValue = (request, propName, condition) => {
    // Handle headers
    if (propName === 'reqHeader' && condition?.name) {
      return request.headers?.[condition.name] || '';
    }
    
    // Map property names
    const propMap = {
      'path': request.path,
      'domain': request.domain,
      'host': request.domain,
      'tier': request.tier,
      'clientIp': request.clientIp,
      'clientCountry': request.clientCountry,
      'clientRegion': request.clientRegion,
      'method': request.method,
      'protocol': request.protocol,
      'queryString': request.queryString,
      'url': request.url,
      'userAgent': request.userAgent
    };
    
    return propMap[propName] !== undefined ? propMap[propName] : request[propName];
  };

  // Detect WAF attack patterns
  const detectWafPatterns = (request) => {
    const detected = [];
    const url = (request.path + '?' + (request.queryString || '')).toLowerCase();
    const ua = (request.userAgent || '').toLowerCase();
    const allData = url + ' ' + ua + ' ' + JSON.stringify(request.headers || {});

    // SQL Injection
    if (/('|"|;|--|union\s+select|select\s+.*from|insert\s+into|delete\s+from|drop\s+table|update\s+.*set)/i.test(allData)) {
      detected.push({ flag: 'SQLI', pattern: 'SQL injection keywords detected' });
    }
    
    // XSS
    if (/<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+on\w+\s*=/i.test(allData)) {
      detected.push({ flag: 'XSS', pattern: 'Cross-site scripting patterns detected' });
    }
    
    // Path Traversal
    if (/\.\.\/|\.\.\\|%2e%2e/i.test(url)) {
      detected.push({ flag: 'TRAVERSAL', pattern: 'Path traversal sequences detected' });
    }
    
    // Command Execution
    if (/;\s*(cat|ls|rm|wget|curl|bash|sh|nc)\s|`.*`|\$\(.*\)/i.test(allData)) {
      detected.push({ flag: 'CMDEXE', pattern: 'Command execution patterns detected' });
    }
    
    // Log4j
    if (/\$\{jndi:/i.test(allData)) {
      detected.push({ flag: 'LOG4J-JNDI', pattern: 'JNDI lookup patterns detected' });
    }
    
    // Scanner
    if (/nikto|sqlmap|nessus|acunetix|burp|owasp.?zap/i.test(ua)) {
      detected.push({ flag: 'SCANNER', pattern: 'Security scanner User-Agent detected' });
    }
    
    // No UA
    if (!request.userAgent || request.userAgent.trim() === '') {
      detected.push({ flag: 'NOUA', pattern: 'Missing User-Agent header' });
    }
    
    // General ATTACK flag if any detected
    if (detected.length > 0) {
      detected.unshift({ flag: 'ATTACK', pattern: 'General attack pattern detected' });
    }
    
    return detected;
  };

  // Helper to detect and format secret references
  const formatSecretValue = (value) => {
    if (typeof value === 'string' && value.includes('${{')) {
      const secretName = value.match(/\$\{\{(\w+)\}\}/)?.[1] || 'SECRET';
      return { 
        displayValue: `[Secret: ${secretName}]`, 
        isSecret: true,
        secretName
      };
    }
    return { displayValue: value, isSecret: false };
  };

  // Apply a single transformation action and return detailed result
  const applyTransformAction = (request, action) => {
    const result = {
      type: action.type,
      before: {},
      after: {},
      description: '',
      applied: false
    };
    
    try {
      if (action.type === 'transform') {
        const target = action.reqProperty || action.reqHeader || action.var || 'path';
        const targetType = action.reqProperty ? 'reqProperty' : (action.reqHeader ? 'reqHeader' : 'var');
        let beforeValue = targetType === 'reqHeader' ? request.headers?.[action.reqHeader] : request[target];
        
        // Handle undefined values
        if (beforeValue === undefined || beforeValue === null) {
          beforeValue = '';
        }
        
        result.target = target;
        result.targetType = targetType;
        result.before[target] = beforeValue;
        
        if (action.op === 'replace') {
          try {
            // Handle YAML backreferences - convert \1 to $1 for JavaScript regex
            // Adobe YAML uses \1, \2 etc. JavaScript replace() uses $1, $2 etc.
            const originalReplacement = action.replacement || '';
            let jsReplacement = originalReplacement.replace(/\\(\d+)/g, '$$$1');
            
            // Store debug info
            result.debug = {
              originalMatch: action.match,
              originalReplacement: originalReplacement,
              jsReplacement: jsReplacement,
              inputValue: beforeValue
            };
            
            const regex = new RegExp(action.match);
            const regexMatches = regex.test(String(beforeValue));
            result.debug.regexMatches = regexMatches;
            
            if (regexMatches) {
              // Get capture groups for debugging
              const matchResult = String(beforeValue).match(regex);
              result.debug.captureGroups = matchResult ? matchResult.slice(1) : [];
            }
            
            const afterValue = String(beforeValue).replace(regex, jsReplacement);
            result.debug.outputValue = afterValue;
            
            if (afterValue !== beforeValue) {
              result.applied = true;
              result.after[target] = afterValue;
              result.description = `Transform ${targetType === 'reqHeader' ? 'header ' : ''}${target}: "${beforeValue}" → "${afterValue}"`;
              result.regex = action.match;
              result.replacement = originalReplacement;
              result.jsReplacement = jsReplacement;
              
              // Apply to request
              if (targetType === 'reqHeader') {
                request.headers = { ...request.headers, [action.reqHeader]: afterValue };
              } else {
                request[target] = afterValue;
              }
            } else {
              result.applied = false;
              result.description = regexMatches 
                ? `Transform ${target}: Regex matched but replacement resulted in same value`
                : `Transform ${target}: No change (regex /${action.match}/ didn't match "${beforeValue}")`;
              result.regex = action.match;
            }
          } catch (e) {
            result.error = `Regex error: ${e.message}`;
            result.description = `Transform failed: Invalid regex "${action.match}" - ${e.message}`;
          }
        } else if (action.op === 'tolower') {
          const afterValue = String(beforeValue).toLowerCase();
          if (afterValue !== beforeValue) {
            result.applied = true;
            result.after[target] = afterValue;
            result.description = `Transform ${target} to lowercase: "${beforeValue}" → "${afterValue}"`;
            
            if (targetType === 'reqHeader') {
              request.headers = { ...request.headers, [action.reqHeader]: afterValue };
            } else {
              request[target] = afterValue;
            }
          } else {
            result.description = `Transform ${target}: Already lowercase`;
          }
        }
      } else if (action.type === 'set') {
        if (action.reqHeader) {
          let value = typeof action.value === 'object' ? JSON.stringify(action.value) : action.value;
          const secretInfo = formatSecretValue(value);
          
          result.target = action.reqHeader;
          result.targetType = 'reqHeader';
          result.before[action.reqHeader] = request.headers?.[action.reqHeader];
          result.after[action.reqHeader] = secretInfo.displayValue;
          result.applied = true;
          result.isSecret = secretInfo.isSecret;
          
          if (secretInfo.isSecret) {
            result.description = `Set header "${action.reqHeader}": ${secretInfo.displayValue} (secret reference - actual value from Cloud Manager)`;
            // Use a placeholder for simulation
            request.headers = { ...request.headers, [action.reqHeader]: `[${secretInfo.secretName}]` };
          } else {
            result.description = `Set header "${action.reqHeader}": "${value}"`;
            request.headers = { ...request.headers, [action.reqHeader]: value };
          }
        } else if (action.reqProperty) {
          const value = typeof action.value === 'object' ? JSON.stringify(action.value) : action.value;
          result.target = action.reqProperty;
          result.targetType = 'reqProperty';
          result.before[action.reqProperty] = request[action.reqProperty];
          result.after[action.reqProperty] = value;
          result.applied = true;
          result.description = `Set ${action.reqProperty}: "${value}"`;
          request[action.reqProperty] = value;
        } else if (action.queryParam) {
          result.target = action.queryParam;
          result.targetType = 'queryParam';
          result.applied = true;
          result.description = `Set query parameter "${action.queryParam}": "${action.value}"`;
        } else if (action.var) {
          result.target = action.var;
          result.targetType = 'variable';
          result.applied = true;
          result.description = `Set variable "${action.var}": "${action.value}"`;
        } else if (action.respHeader) {
          // Response header (for responseTransformations)
          result.target = action.respHeader;
          result.targetType = 'respHeader';
          result.applied = true;
          result.description = `Set response header "${action.respHeader}": "${action.value}"`;
        }
      } else if (action.type === 'unset') {
        if (action.reqHeader) {
          result.target = action.reqHeader;
          result.targetType = 'reqHeader';
          result.before[action.reqHeader] = request.headers?.[action.reqHeader];
          result.applied = true;
          result.description = `Unset header "${action.reqHeader}"`;
          const { [action.reqHeader]: removed, ...rest } = request.headers || {};
          request.headers = rest;
        } else if (action.queryParamMatch) {
          result.target = 'queryParams';
          result.targetType = 'queryParamMatch';
          result.applied = true;
          result.description = `Remove query params matching regex: ${action.queryParamMatch}`;
        } else if (action.respHeader) {
          result.target = action.respHeader;
          result.targetType = 'respHeader';
          result.applied = true;
          result.description = `Unset response header "${action.respHeader}"`;
        }
      }
    } catch (err) {
      result.error = err.message;
      result.description = `Action failed: ${err.message}`;
    }
    
    return result;
  };

  // Main simulation function
  const runSimulation = () => {
    setParseError(null);
    
    if (!cdnYaml.trim()) {
      setParseError('Please provide a cdn.yaml configuration. Click "Load Sample" for an example.');
      return;
    }
    
    let config;
    try {
      config = yaml.load(cdnYaml);
    } catch (e) {
      setParseError(`YAML Parse Error at line ${e.mark?.line || '?'}: ${e.message}`);
      return;
    }
    
    if (!config?.data) {
      setParseError('Invalid cdn.yaml: missing "data" section');
      return;
    }
    
    // Initialize results
    const results = {
      originalRequest: { ...testRequest, headers: { ...testRequest.headers } },
      currentRequest: { ...testRequest, headers: { ...testRequest.headers } },
      evaluationSteps: [],
      pathHistory: [{ path: testRequest.path, phase: 'Original Request' }],
      matchedRules: [],
      finalAction: 'allow',
      finalStatus: 200,
      redirectLocation: null,
      selectedOrigin: null,
      responseHeaders: {},
      warnings: [],
      blockingRule: null,
      blockingRuleDetails: null,
      wafFlagsDetected: []
    };
    
    // Detect WAF patterns in original request
    results.wafFlagsDetected = detectWafPatterns(testRequest);
    
    // ============================================
    // STEP 1: REQUEST TRANSFORMATIONS
    // ============================================
    const requestTransforms = config.data.requestTransformations;
    if (requestTransforms) {
      const stepResult = {
        phase: 'requestTransformations',
        name: '1. Request Transformations',
        icon: '🔄',
        description: 'Modifies incoming requests (headers, paths, parameters) before they reach origin',
        rules: [],
        globalActions: [],
        skipped: false
      };
      
      // Handle removeMarketingParams
      if (requestTransforms.removeMarketingParams) {
        stepResult.globalActions.push({
          type: 'removeMarketingParams',
          description: 'Marketing query parameters (utm_*, gclid, fbclid, etc.) will be automatically removed',
          applied: true
        });
      }
      
      // Process each transformation rule
      if (requestTransforms.rules) {
        for (const rule of requestTransforms.rules) {
          const conditionResult = evaluateCondition(rule.when, results.currentRequest);
          
          const ruleResult = {
            name: rule.name,
            matched: conditionResult.matches,
            conditionDetails: conditionResult,
            actions: [],
            pathBefore: results.currentRequest.path,
            pathAfter: null
          };
          
          if (conditionResult.matches) {
            results.matchedRules.push({ 
              phase: 'requestTransformations', 
              rule: rule.name,
              type: 'transform'
            });
            
            // Apply each action
            if (rule.actions) {
              for (const action of rule.actions) {
                const actionResult = applyTransformAction(results.currentRequest, action);
                ruleResult.actions.push(actionResult);
              }
            }
            
            ruleResult.pathAfter = results.currentRequest.path;
            
            // Track path changes
            if (ruleResult.pathBefore !== ruleResult.pathAfter) {
              results.pathHistory.push({
                path: results.currentRequest.path,
                phase: `After "${rule.name}"`,
                rule: rule.name,
                transform: `${ruleResult.pathBefore} → ${ruleResult.pathAfter}`
              });
            }
          }
          
          stepResult.rules.push(ruleResult);
        }
      }
      
      results.evaluationSteps.push(stepResult);
    }
    
    // ============================================
    // STEP 2: TRAFFIC FILTER RULES (WAF)
    // ============================================
    const trafficFilters = config.data.trafficFilters;
    if (trafficFilters?.rules) {
      const stepResult = {
        phase: 'trafficFilters',
        name: '2. Traffic Filter Rules (WAF)',
        icon: '🛡️',
        description: 'Evaluates security rules to block or log malicious traffic',
        rules: [],
        skipped: false
      };
      
      for (const rule of trafficFilters.rules) {
        // Evaluate condition against TRANSFORMED request
        const conditionResult = evaluateCondition(rule.when, results.currentRequest);
        
        // Check WAF flags if present
        let wafMatch = true;
        let wafFlags = [];
        let requiredWafMatch = false;
        
        if (rule.action?.wafFlags || rule.wafFlags) {
          wafFlags = rule.action?.wafFlags || rule.wafFlags;
          requiredWafMatch = true;
          wafMatch = wafFlags.some(flag => {
            if (flag === 'ATTACK-FROM-BAD-IP') {
              return results.wafFlagsDetected.some(d => d.flag === 'ATTACK') && 
                     (testRequest.clientIp.startsWith('185.') || testRequest.clientIp.startsWith('45.'));
            }
            return results.wafFlagsDetected.some(d => d.flag === flag);
          });
        }
        
        const matched = conditionResult.matches && wafMatch;
        
        const ruleResult = {
          name: rule.name,
          matched,
          conditionMatched: conditionResult.matches,
          conditionDetails: conditionResult,
          wafFlagsRequired: wafFlags,
          wafFlagsMatched: requiredWafMatch ? wafMatch : null,
          action: typeof rule.action === 'string' ? rule.action : rule.action?.type || 'unknown',
          rateLimit: rule.rateLimit,
          appliedAction: null,
          isBlocking: false
        };
        
        if (matched) {
          results.matchedRules.push({ 
            phase: 'trafficFilters', 
            rule: rule.name, 
            action: ruleResult.action 
          });
          
          const action = typeof rule.action === 'string' ? rule.action : rule.action?.type;
          
          if (action === 'block') {
            results.finalAction = 'block';
            results.finalStatus = 403;
            results.blockingRule = rule.name;
            ruleResult.appliedAction = 'BLOCKED';
            ruleResult.isBlocking = true;
            
            // Capture blocking details for explanation
            const suggestions = [];
            const conditionsList = [];
            
            // Analyze why this rule blocked
            if (conditionResult.details) {
              conditionResult.details.forEach(d => {
                if (d.matches) {
                  conditionsList.push({ matched: true, reason: d.reason });
                }
              });
            } else {
              conditionsList.push({ matched: true, reason: conditionResult.reason });
            }
            
            // Generate suggestions based on rule type
            if (rule.name.includes('ip-allowlist') || rule.name.includes('allowlist')) {
              suggestions.push(`Add client IP "${results.currentRequest.clientIp}" to the allowlist`);
              suggestions.push('Or access from an IP already in the allowlist');
            }
            if (rule.name.includes('ofac') || rule.name.includes('country')) {
              suggestions.push(`Client country "${results.currentRequest.clientCountry}" is blocked`);
              suggestions.push('Access from a non-restricted country');
            }
            if (wafFlags.length > 0) {
              suggestions.push(`WAF detected attack patterns: ${wafFlags.join(', ')}`);
              suggestions.push('Remove malicious patterns from the request');
            }
            if (rule.name.includes('admin') || rule.name.includes('block')) {
              suggestions.push(`Path "${results.currentRequest.path}" matches a blocked pattern`);
              suggestions.push('Change the request path or remove/modify the blocking rule');
            }
            if (suggestions.length === 0) {
              suggestions.push('Review the rule conditions and modify as needed');
            }
            
            results.blockingRuleDetails = {
              conditions: conditionsList,
              suggestions: suggestions
            };
          } else if (action === 'log') {
            ruleResult.appliedAction = 'LOGGED';
          } else if (action === 'allow') {
            ruleResult.appliedAction = 'ALLOWED';
          }
          
          if (rule.rateLimit) {
            const total = rule.rateLimit.limit * rule.rateLimit.window;
            ruleResult.rateLimitInfo = {
              limit: rule.rateLimit.limit,
              window: rule.rateLimit.window,
              total: total,
              penalty: rule.rateLimit.penalty || 0,
              description: `Allows ${rule.rateLimit.limit} req/sec × ${rule.rateLimit.window}s = ${total} total requests. Exceeding triggers ${rule.rateLimit.penalty}s penalty.`
            };
          }
        }
        
        stepResult.rules.push(ruleResult);
      }
      
      results.evaluationSteps.push(stepResult);
    }
    
    // ============================================
    // STEP 3: RESPONSE TRANSFORMATIONS (only if not blocked)
    // ============================================
    if (config.data.responseTransformations?.rules) {
      const stepResult = {
        phase: 'responseTransformations',
        name: '3. Response Transformations',
        icon: '📤',
        description: 'Modifies outgoing response headers back to the client (evaluated AFTER origin response)',
        rules: [],
        skipped: results.finalAction === 'block'
      };
      
      if (results.finalAction === 'block') {
        stepResult.skipReason = `Skipped - Request was blocked by rule "${results.blockingRule}"`;
      } else {
        for (const rule of config.data.responseTransformations.rules) {
          const conditionResult = evaluateCondition(rule.when, results.currentRequest);
          
          const ruleResult = {
            name: rule.name,
            matched: conditionResult.matches,
            conditionDetails: conditionResult,
            actions: []
          };
          
          if (conditionResult.matches) {
            results.matchedRules.push({ 
              phase: 'responseTransformations', 
              rule: rule.name 
            });
            
            if (rule.actions) {
              for (const action of rule.actions) {
                const actionResult = {
                  type: action.type,
                  applied: true,
                  description: ''
                };
                
                if (action.type === 'set' && action.respHeader) {
                  results.responseHeaders[action.respHeader] = action.value;
                  actionResult.description = `Set response header "${action.respHeader}": "${action.value}"`;
                } else if (action.type === 'unset' && action.respHeader) {
                  delete results.responseHeaders[action.respHeader];
                  actionResult.description = `Remove response header "${action.respHeader}"`;
                } else {
                  actionResult.description = `Action: ${action.type}`;
                }
                
                ruleResult.actions.push(actionResult);
              }
            }
          }
          
          stepResult.rules.push(ruleResult);
        }
      }
      
      results.evaluationSteps.push(stepResult);
    }
    
    // ============================================
    // STEP 4: ORIGIN SELECTORS (only if not blocked)
    // ============================================
    if (config.data.originSelectors?.rules) {
      const stepResult = {
        phase: 'originSelectors',
        name: '4. Origin Selectors',
        icon: '🎯',
        description: 'Routes traffic to different backend origins',
        rules: [],
        skipped: results.finalAction === 'block'
      };
      
      if (results.finalAction === 'block') {
        stepResult.skipReason = `Skipped - Request was blocked by rule "${results.blockingRule}"`;
      } else {
        for (const rule of config.data.originSelectors.rules) {
          const conditionResult = evaluateCondition(rule.when, results.currentRequest);
          
          const ruleResult = {
            name: rule.name,
            matched: conditionResult.matches,
            conditionDetails: conditionResult,
            originName: rule.action?.originName,
            originConfig: null,
            selected: false
          };
          
          if (conditionResult.matches && !results.selectedOrigin) {
            results.matchedRules.push({ 
              phase: 'originSelectors', 
              rule: rule.name 
            });
            results.selectedOrigin = rule.action?.originName;
            ruleResult.selected = true;
            
            // Find origin config
            const originConfig = config.data.originSelectors.origins?.find(
              o => o.name === rule.action?.originName
            );
            if (originConfig) {
              ruleResult.originConfig = originConfig;
            }
          }
          
          stepResult.rules.push(ruleResult);
        }
      }
      
      results.evaluationSteps.push(stepResult);
    }
    
    // ============================================
    // STEP 5: REDIRECTS (only if not blocked)
    // ============================================
    if (config.data.redirects?.rules) {
      const stepResult = {
        phase: 'redirects',
        name: '5. Server-side Redirects',
        icon: '↪️',
        description: 'CDN-level redirects (301, 302, etc.) before reaching origin',
        rules: [],
        skipped: results.finalAction === 'block'
      };
      
      if (results.finalAction === 'block') {
        stepResult.skipReason = `Skipped - Request was blocked by rule "${results.blockingRule}"`;
      } else {
        for (const rule of config.data.redirects.rules) {
          const conditionResult = evaluateCondition(rule.when, results.currentRequest);
          
          // Compute redirect location - can be string or object with transform
          let computedLocation = '';
          let locationTransforms = [];
          
          if (rule.action?.location) {
            if (typeof rule.action.location === 'string') {
              computedLocation = rule.action.location;
            } else if (typeof rule.action.location === 'object') {
              // Location with reqProperty and transform
              const propName = rule.action.location.reqProperty;
              let value = getPropertyValue(results.currentRequest, propName, {});
              
              // Apply transforms if present
              if (rule.action.location.transform && Array.isArray(rule.action.location.transform)) {
                for (const transform of rule.action.location.transform) {
                  const beforeTransform = value;
                  try {
                    if (transform.op === 'replace') {
                      // Handle YAML backreferences
                      let replacement = (transform.replacement || '').replace(/\\(\d+)/g, '$$$1');
                      const regex = new RegExp(transform.match, 'g');
                      value = String(value).replace(regex, replacement);
                    } else if (transform.op === 'tolower') {
                      value = String(value).toLowerCase();
                    }
                    locationTransforms.push({
                      op: transform.op,
                      before: beforeTransform,
                      after: value,
                      match: transform.match,
                      replacement: transform.replacement
                    });
                  } catch (e) {
                    locationTransforms.push({
                      op: transform.op,
                      error: e.message
                    });
                  }
                }
              }
              computedLocation = value;
            }
          }
          
          const ruleResult = {
            name: rule.name,
            matched: conditionResult.matches,
            conditionDetails: conditionResult,
            redirectStatus: rule.action?.status || 301,
            redirectLocation: computedLocation,
            locationTransforms: locationTransforms.length > 0 ? locationTransforms : null,
            originalLocationConfig: typeof rule.action?.location === 'object' ? rule.action.location : null,
            triggered: false
          };
          
          if (conditionResult.matches && !results.redirectLocation) {
            results.matchedRules.push({ 
              phase: 'redirects', 
              rule: rule.name 
            });
            results.finalAction = 'redirect';
            results.finalStatus = rule.action?.status || 301;
            results.redirectLocation = computedLocation;
            ruleResult.triggered = true;
          }
          
          stepResult.rules.push(ruleResult);
        }
      }
      
      results.evaluationSteps.push(stepResult);
    }
    
    // Add warnings for potential issues
    if (results.wafFlagsDetected.length > 0 && results.finalAction === 'allow') {
      const hasWafRule = trafficFilters?.rules?.some(r => r.action?.wafFlags || r.wafFlags);
      if (!hasWafRule) {
        results.warnings.push({
          type: 'security',
          severity: 'high',
          message: `Attack patterns detected (${results.wafFlagsDetected.map(d => d.flag).join(', ')}) but no WAF rules are configured to handle them!`
        });
      }
    }
    
    // Check if path was transformed
    if (results.originalRequest.path !== results.currentRequest.path) {
      results.warnings.push({
        type: 'info',
        severity: 'low',
        message: `Request path was transformed: "${results.originalRequest.path}" → "${results.currentRequest.path}"`
      });
    }
    
    setSimulationResults(results);
    setActiveTab('results');
  };

  const loadSampleConfig = () => {
    setCdnYaml(SAMPLE_CDN_YAML);
  };

  // Render condition details recursively
  const renderConditionDetails = (condition, depth = 0) => {
    if (!condition) return null;
    
    if (condition.type === 'allOf' || condition.type === 'anyOf') {
      return (
        <div className={`condition-group ${condition.type} ${condition.matches ? 'matched' : 'not-matched'}`}>
          <div className="condition-group-header">
            <span className={`condition-badge ${condition.matches ? 'pass' : 'fail'}`}>
              {condition.type === 'allOf' ? 'ALL OF' : 'ANY OF'}
            </span>
            <span className="condition-summary">{condition.reason}</span>
          </div>
          <div className="condition-children">
            {condition.details?.map((child, i) => (
              <div key={i} className={`condition-child ${child.matches ? 'matched' : 'not-matched'}`}>
                <span className="condition-index">#{child.index}</span>
                {child.type ? renderConditionDetails(child, depth + 1) : (
                  <span className="condition-simple">{child.reason}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      );
    }
    
    return <span className="condition-simple">{condition.reason}</span>;
  };

  return (
    <div className="rules-simulator">
      <div className="simulator-header">
        <div>
          <h1>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="5 3 19 12 5 21 5 3" />
            </svg>
            CDN Rules Simulator
          </h1>
          <p>Simulate how your cdn.yaml rules process requests step-by-step based on <a href="https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/content-delivery/cdn-configuring-traffic#order-of-evaluation" target="_blank" rel="noopener noreferrer">Adobe's order of evaluation</a></p>
        </div>
      </div>

      {/* Order of Evaluation Reference */}
      <div className="evaluation-order-bar">
        <span className="order-label">Evaluation Order:</span>
        {EVALUATION_ORDER.map((step, idx) => (
          <React.Fragment key={step.id}>
            <div className="order-step" title={step.description}>
              <span className="order-icon">{step.icon}</span>
              <span className="order-name">{step.name}</span>
            </div>
            {idx < EVALUATION_ORDER.length - 1 && <span className="order-arrow">→</span>}
          </React.Fragment>
        ))}
      </div>

      <div className="simulator-tabs">
        <button 
          className={`tab-btn ${activeTab === 'config' ? 'active' : ''}`}
          onClick={() => setActiveTab('config')}
        >
          📄 CDN Configuration
        </button>
        <button 
          className={`tab-btn ${activeTab === 'request' ? 'active' : ''}`}
          onClick={() => setActiveTab('request')}
        >
          📨 Test Request
        </button>
        <button 
          className={`tab-btn ${activeTab === 'results' ? 'active' : ''}`}
          onClick={() => setActiveTab('results')}
          disabled={!simulationResults}
        >
          📊 Results {simulationResults && `(${simulationResults.matchedRules.length} matched)`}
        </button>
      </div>

      {activeTab === 'config' && (
        <div className="config-panel card">
          <div className="card-header">
            <h3 className="card-title">cdn.yaml Configuration</h3>
            <button className="btn btn-ghost btn-sm" onClick={loadSampleConfig}>
              Load Sample with Transformations
            </button>
          </div>
          <textarea
            className="yaml-textarea"
            value={cdnYaml}
            onChange={(e) => setCdnYaml(e.target.value)}
            placeholder="Paste your cdn.yaml configuration here..."
            spellCheck="false"
          />
          {parseError && (
            <div className="parse-error">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="15" y1="9" x2="9" y2="15" />
                <line x1="9" y1="9" x2="15" y2="15" />
              </svg>
              {parseError}
            </div>
          )}
        </div>
      )}

      {activeTab === 'request' && (
        <div className="request-panel card">
          <div className="card-header">
            <h3 className="card-title">Test Request Configuration</h3>
            <p className="card-subtitle">Configure the incoming request to simulate</p>
          </div>
          
          <div className="request-form">
            <div className="form-section">
              <h4>📍 Request Properties</h4>
              <div className="form-grid">
                <div className="form-group">
                  <label>Path <span className="required">*</span></label>
                  <input
                    type="text"
                    className="form-input"
                    value={testRequest.path}
                    onChange={(e) => setTestRequest({ ...testRequest, path: e.target.value })}
                    placeholder="/jp/products/test.html"
                  />
                  <span className="form-hint">The URL path to test (e.g., /jp/products)</span>
                </div>
                <div className="form-group">
                  <label>Domain <span className="required">*</span></label>
                  <input
                    type="text"
                    className="form-input"
                    value={testRequest.domain}
                    onChange={(e) => setTestRequest({ ...testRequest, domain: e.target.value })}
                    placeholder="preview.example.com"
                  />
                </div>
                <div className="form-group">
                  <label>Method</label>
                  <select
                    className="form-select"
                    value={testRequest.method}
                    onChange={(e) => setTestRequest({ ...testRequest, method: e.target.value })}
                  >
                    {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label>Tier <span className="required">*</span></label>
                  <select
                    className="form-select"
                    value={testRequest.tier}
                    onChange={(e) => setTestRequest({ ...testRequest, tier: e.target.value })}
                  >
                    <option value="publish">Publish (Public)</option>
                    <option value="author">Author (Internal)</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Query String</label>
                  <input
                    type="text"
                    className="form-input"
                    value={testRequest.queryString}
                    onChange={(e) => setTestRequest({ ...testRequest, queryString: e.target.value })}
                    placeholder="utm_source=google&param=value"
                  />
                </div>
                <div className="form-group">
                  <label>Protocol</label>
                  <select
                    className="form-select"
                    value={testRequest.protocol}
                    onChange={(e) => setTestRequest({ ...testRequest, protocol: e.target.value })}
                  >
                    <option value="https">HTTPS</option>
                    <option value="http">HTTP</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="form-section">
              <h4>🌍 Client Properties</h4>
              <div className="form-grid">
                <div className="form-group">
                  <label>Client IP</label>
                  <input
                    type="text"
                    className="form-input"
                    value={testRequest.clientIp}
                    onChange={(e) => setTestRequest({ ...testRequest, clientIp: e.target.value })}
                    placeholder="192.168.1.100"
                  />
                </div>
                <div className="form-group">
                  <label>Country Code</label>
                  <input
                    type="text"
                    className="form-input"
                    value={testRequest.clientCountry}
                    onChange={(e) => setTestRequest({ ...testRequest, clientCountry: e.target.value.toUpperCase() })}
                    placeholder="US"
                    maxLength={2}
                  />
                  <span className="form-hint">ISO 3166-1 alpha-2 (e.g., US, JP, IR)</span>
                </div>
                <div className="form-group">
                  <label>Region</label>
                  <input
                    type="text"
                    className="form-input"
                    value={testRequest.clientRegion}
                    onChange={(e) => setTestRequest({ ...testRequest, clientRegion: e.target.value })}
                    placeholder="CA"
                  />
                </div>
              </div>
            </div>

            <div className="form-section">
              <h4>📋 Headers</h4>
              <div className="form-grid">
                <div className="form-group full-width">
                  <label>User-Agent</label>
                  <input
                    type="text"
                    className="form-input"
                    value={testRequest.userAgent}
                    onChange={(e) => setTestRequest({ ...testRequest, userAgent: e.target.value })}
                    placeholder="Mozilla/5.0..."
                  />
                </div>
                <div className="form-group">
                  <label>Referer</label>
                  <input
                    type="text"
                    className="form-input"
                    value={testRequest.referer}
                    onChange={(e) => setTestRequest({ ...testRequest, referer: e.target.value })}
                    placeholder="https://google.com"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Run Simulation Button */}
      <div className="simulation-controls">
        <button className="btn btn-primary btn-lg" onClick={runSimulation}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polygon points="5 3 19 12 5 21 5 3" />
          </svg>
          Run Simulation
        </button>
        <span className="simulation-hint">Simulates request through all CDN rule phases</span>
      </div>

      {activeTab === 'results' && simulationResults && (
        <div className="results-panel">
          {/* Final Result Summary */}
          <div className={`result-summary card ${simulationResults.finalAction}`}>
            <div className="result-icon">
              {simulationResults.finalAction === 'block' ? '🚫' : 
               simulationResults.finalAction === 'redirect' ? '↪️' : '✅'}
            </div>
            <div className="result-content">
              <h3>
                {simulationResults.finalAction === 'block' 
                  ? `Request BLOCKED (HTTP 403)` 
                  : simulationResults.finalAction === 'redirect' 
                    ? `Request REDIRECTED (HTTP ${simulationResults.finalStatus})` 
                    : 'Request ALLOWED (HTTP 200)'}
              </h3>
              {simulationResults.blockingRule && (
                <p className="blocking-rule">
                  <strong>Blocked by rule:</strong> <code>{simulationResults.blockingRule}</code>
                </p>
              )}
              {simulationResults.redirectLocation && (
                <p className="redirect-info">
                  <strong>Redirecting to:</strong> <code>{simulationResults.redirectLocation}</code>
                </p>
              )}
              {simulationResults.selectedOrigin && (
                <p className="origin-info">
                  <strong>Selected Origin:</strong> <code>{simulationResults.selectedOrigin}</code>
                </p>
              )}
              <p className="result-stats">
                {simulationResults.matchedRules.length} rule(s) matched across {simulationResults.evaluationSteps.length} evaluation phases
              </p>
            </div>
          </div>

          {/* 403 Explanation - Why was request blocked? */}
          {simulationResults.finalAction === 'block' && simulationResults.blockingRuleDetails && (
            <div className="block-explanation card">
              <h4>❓ Why Was This Request Blocked?</h4>
              <div className="block-details">
                <div className="block-rule-name">
                  <strong>Rule:</strong> <code>{simulationResults.blockingRule}</code>
                </div>
                <div className="block-conditions">
                  <strong>Conditions that triggered the block:</strong>
                  <ul>
                    {simulationResults.blockingRuleDetails.conditions?.map((c, i) => (
                      <li key={i} className={c.matched ? 'matched' : 'not-matched'}>
                        {c.reason}
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="block-suggestion">
                  <strong>💡 To Allow This Request:</strong>
                  <ul>
                    {simulationResults.blockingRuleDetails.suggestions?.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Path Transformation History */}
          {simulationResults.pathHistory.length > 1 && (
            <div className="path-history card">
              <h4>🔄 Path Transformation History</h4>
              <p className="section-description">Shows how the request path was modified through transformation rules</p>
              <div className="path-timeline">
                {simulationResults.pathHistory.map((entry, idx) => (
                  <div key={idx} className={`path-step ${idx === simulationResults.pathHistory.length - 1 ? 'final' : ''}`}>
                    <div className="path-step-marker">
                      {idx === 0 ? '📥' : idx === simulationResults.pathHistory.length - 1 ? '📤' : '🔄'}
                    </div>
                    <div className="path-step-content">
                      <div className="path-step-phase">{entry.phase}</div>
                      <code className="path-step-value">{entry.path}</code>
                      {entry.transform && (
                        <div className="path-step-transform">
                          Transform: <code>{entry.transform}</code>
                        </div>
                      )}
                    </div>
                    {idx < simulationResults.pathHistory.length - 1 && (
                      <div className="path-step-arrow">↓</div>
                    )}
                  </div>
                ))}
              </div>
              <div className="path-summary">
                <div className="path-summary-item before">
                  <span className="label">Original Path</span>
                  <code>{simulationResults.originalRequest.path}</code>
                </div>
                <span className="path-summary-arrow">→</span>
                <div className="path-summary-item after">
                  <span className="label">Final Path</span>
                  <code>{simulationResults.currentRequest.path}</code>
                </div>
              </div>
            </div>
          )}

          {/* Warnings */}
          {simulationResults.warnings.length > 0 && (
            <div className="warnings-card card">
              <h4>⚠️ Warnings & Potential Issues</h4>
              <ul>
                {simulationResults.warnings.map((w, i) => (
                  <li key={i} className={`warning-item ${w.severity}`}>
                    <span className="warning-type">{w.type.toUpperCase()}</span>
                    {w.message}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* WAF Patterns Detected */}
          {simulationResults.wafFlagsDetected.length > 0 && (
            <div className="waf-detected card">
              <h4>🛡️ WAF Attack Patterns Detected</h4>
              <p className="section-description">These patterns were detected in the request and may trigger WAF rules</p>
              <div className="waf-flags">
                {simulationResults.wafFlagsDetected.map((item, idx) => (
                  <div key={idx} className="waf-flag-item">
                    <span className="waf-flag-name">{item.flag}</span>
                    <span className="waf-flag-pattern">{item.pattern}</span>
                    {WAF_FLAGS[item.flag] && (
                      <span 
                        className="waf-flag-severity"
                        style={{
                          background: SEVERITY_COLORS[WAF_FLAGS[item.flag].severity]?.bg,
                          color: SEVERITY_COLORS[WAF_FLAGS[item.flag].severity]?.color
                        }}
                      >
                        {WAF_FLAGS[item.flag].severity}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Step-by-Step Evaluation */}
          <div className="evaluation-steps">
            <h4>📋 Step-by-Step Rule Evaluation</h4>
            <p className="section-description">
              Rules are evaluated in this exact order. Understanding this order is critical for debugging why requests are blocked or transformed.
            </p>
            
            {simulationResults.evaluationSteps.map((step, stepIdx) => (
              <details 
                key={step.phase} 
                className={`step-card ${step.skipped ? 'skipped' : ''}`} 
                open={!step.skipped && step.rules?.some(r => r.matched)}
              >
                <summary className="step-header">
                  <span className="step-icon">{step.icon}</span>
                  <span className="step-name">{step.name}</span>
                  {step.skipped ? (
                    <span className="step-badge skipped">SKIPPED</span>
                  ) : (
                    <span className="step-stats">
                      {step.rules?.filter(r => r.matched).length || 0} / {step.rules?.length || 0} matched
                    </span>
                  )}
                </summary>
                
                <div className="step-content">
                  <p className="step-description">{step.description}</p>
                  
                  {step.skipped && (
                    <div className="step-skip-reason">{step.skipReason}</div>
                  )}
                  
                  {/* Global actions (like removeMarketingParams) */}
                  {step.globalActions?.length > 0 && (
                    <div className="global-actions">
                      <h5>Global Actions</h5>
                      {step.globalActions.map((action, i) => (
                        <div key={i} className="global-action-item">
                          <span className="action-type">{action.type}</span>
                          <span className="action-desc">{action.description}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  
                  {/* Rules */}
                  {step.rules?.length > 0 && (
                    <div className="rules-list">
                      {step.rules.map((rule, ruleIdx) => (
                        <div 
                          key={ruleIdx} 
                          className={`rule-card ${rule.matched ? 'matched' : 'not-matched'} ${rule.isBlocking ? 'blocking' : ''}`}
                        >
                          <div className="rule-header">
                            <span className={`rule-match-badge ${rule.matched ? 'yes' : 'no'}`}>
                              {rule.matched ? '✓ MATCHED' : '✗ NOT MATCHED'}
                            </span>
                            <code className="rule-name">{rule.name}</code>
                            {rule.appliedAction && (
                              <span className={`rule-action-badge ${rule.appliedAction.toLowerCase()}`}>
                                {rule.appliedAction}
                              </span>
                            )}
                            {rule.triggered && (
                              <span className="rule-action-badge redirect">
                                {rule.redirectStatus} → {rule.redirectLocation}
                              </span>
                            )}
                          </div>
                          
                          {/* Condition evaluation details */}
                          <div className="rule-conditions">
                            <h6>Condition Evaluation:</h6>
                            {renderConditionDetails(rule.conditionDetails)}
                          </div>
                          
                          {/* WAF flags info */}
                          {rule.wafFlagsRequired?.length > 0 && (
                            <div className="rule-waf-info">
                              <h6>WAF Flags Required:</h6>
                              <div className="waf-flags-check">
                                {rule.wafFlagsRequired.map(flag => (
                                  <span key={flag} className="waf-flag-check">
                                    {flag}
                                    <span className={`check-result ${simulationResults.wafFlagsDetected.some(d => d.flag === flag) ? 'found' : 'not-found'}`}>
                                      {simulationResults.wafFlagsDetected.some(d => d.flag === flag) ? '✓' : '✗'}
                                    </span>
                                  </span>
                                ))}
                              </div>
                              <span className={`waf-match-result ${rule.wafFlagsMatched ? 'matched' : 'not-matched'}`}>
                                {rule.wafFlagsMatched ? '✓ WAF flags matched' : '✗ Required WAF flags not detected in request'}
                              </span>
                            </div>
                          )}
                          
                          {/* Actions applied (for transformations) */}
                          {rule.actions?.length > 0 && (
                            <div className="rule-actions">
                              <h6>Actions Applied:</h6>
                              {rule.actions.map((action, i) => (
                                <div key={i} className={`action-item ${action.applied ? 'applied' : 'not-applied'}`}>
                                  <span className="action-type-badge">{action.type}</span>
                                  <span className="action-description">{action.description}</span>
                                  {action.debug && (
                                    <div className="transform-debug">
                                      <div className="debug-row">
                                        <span className="debug-label">Input:</span>
                                        <code>{action.debug.inputValue}</code>
                                      </div>
                                      <div className="debug-row">
                                        <span className="debug-label">Regex Pattern:</span>
                                        <code>/{action.debug.originalMatch}/</code>
                                        <span className={`debug-match ${action.debug.regexMatches ? 'yes' : 'no'}`}>
                                          {action.debug.regexMatches ? '✓ Matched' : '✗ No Match'}
                                        </span>
                                      </div>
                                      {action.debug.captureGroups?.length > 0 && (
                                        <div className="debug-row">
                                          <span className="debug-label">Capture Groups:</span>
                                          {action.debug.captureGroups.map((g, gi) => (
                                            <code key={gi} className="capture-group">${gi + 1} = "{g || '(empty)'}"</code>
                                          ))}
                                        </div>
                                      )}
                                      <div className="debug-row">
                                        <span className="debug-label">Replacement (YAML):</span>
                                        <code>{action.debug.originalReplacement || '(empty)'}</code>
                                      </div>
                                      <div className="debug-row">
                                        <span className="debug-label">Replacement (JS):</span>
                                        <code>{action.debug.jsReplacement || '(empty)'}</code>
                                      </div>
                                      <div className="debug-row result">
                                        <span className="debug-label">Output:</span>
                                        <code className={action.applied ? 'changed' : ''}>{action.debug.outputValue}</code>
                                      </div>
                                      {action.error && (
                                        <div className="debug-error">⚠️ {action.error}</div>
                                      )}
                                    </div>
                                  )}
                                  {!action.debug && action.regex && (
                                    <div className="action-detail">
                                      <span>Regex:</span> <code>{action.regex}</code>
                                      <span>Replacement:</span> <code>{action.replacement}</code>
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}
                          
                          {/* Path before/after for transformations */}
                          {rule.pathBefore !== rule.pathAfter && rule.pathAfter && (
                            <div className="path-change">
                              <h6>Path Changed:</h6>
                              <div className="path-change-visual">
                                <code className="before">{rule.pathBefore}</code>
                                <span className="arrow">→</span>
                                <code className="after">{rule.pathAfter}</code>
                              </div>
                            </div>
                          )}
                          
                          {/* Rate limit info */}
                          {rule.rateLimitInfo && (
                            <div className="rate-limit-info">
                              <h6>Rate Limiting:</h6>
                              <p>{rule.rateLimitInfo.description}</p>
                            </div>
                          )}
                          
                          {/* Origin selector info */}
                          {rule.selected && rule.originConfig && (
                            <div className="origin-info-detail">
                              <h6>Selected Origin Configuration:</h6>
                              <ul>
                                <li><strong>Name:</strong> {rule.originConfig.name}</li>
                                <li><strong>Domain:</strong> {rule.originConfig.domain}</li>
                                {rule.originConfig.forwardHost && <li><strong>Forward Host:</strong> Yes</li>}
                                {rule.originConfig.forwardCookie && <li><strong>Forward Cookie:</strong> Yes</li>}
                                {rule.originConfig.forwardAuthorization && <li><strong>Forward Authorization:</strong> Yes</li>}
                              </ul>
                            </div>
                          )}
                          
                          {/* Redirect with transforms */}
                          {rule.triggered && rule.locationTransforms && (
                            <div className="redirect-transforms">
                              <h6>Redirect Location Computed:</h6>
                              <div className="transform-steps">
                                {rule.locationTransforms.map((t, i) => (
                                  <div key={i} className="transform-step-item">
                                    <span className="transform-op">{t.op}</span>
                                    {t.error ? (
                                      <span className="transform-error">Error: {t.error}</span>
                                    ) : (
                                      <>
                                        <code className="transform-before">{t.before}</code>
                                        <span className="transform-arrow">→</span>
                                        <code className="transform-after">{t.after}</code>
                                      </>
                                    )}
                                  </div>
                                ))}
                              </div>
                              <div className="final-location">
                                <strong>Final Location:</strong> <code>{rule.redirectLocation}</code>
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                  
                  {(!step.rules || step.rules.length === 0) && !step.skipped && (
                    <p className="no-rules">No rules configured for this phase</p>
                  )}
                </div>
              </details>
            ))}
          </div>

          {/* Final Request State */}
          <div className="final-state card">
            <h4>📝 Final Request State (After All Transformations)</h4>
            <div className="final-state-grid">
              <div className="state-item">
                <span className="state-label">Path</span>
                <code className="state-value">{simulationResults.currentRequest.path}</code>
                {simulationResults.originalRequest.path !== simulationResults.currentRequest.path && (
                  <span className="state-changed">Changed from: {simulationResults.originalRequest.path}</span>
                )}
              </div>
              <div className="state-item">
                <span className="state-label">Domain</span>
                <code className="state-value">{simulationResults.currentRequest.domain}</code>
              </div>
              <div className="state-item">
                <span className="state-label">Tier</span>
                <code className="state-value">{simulationResults.currentRequest.tier}</code>
              </div>
              <div className="state-item">
                <span className="state-label">Client IP</span>
                <code className="state-value">{simulationResults.currentRequest.clientIp}</code>
              </div>
              <div className="state-item">
                <span className="state-label">Country</span>
                <code className="state-value">{simulationResults.currentRequest.clientCountry}</code>
              </div>
            </div>
            
            {/* Request Headers Set */}
            {simulationResults.currentRequest.headers && Object.keys(simulationResults.currentRequest.headers).length > 0 && (
              <div className="headers-set">
                <h5>Request Headers (After Transformations)</h5>
                <div className="headers-list">
                  {Object.entries(simulationResults.currentRequest.headers).map(([key, value]) => (
                    <div key={key} className="header-item">
                      <span className="header-name">{key}:</span>
                      <code className="header-value">{value}</code>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Response Headers */}
          {Object.keys(simulationResults.responseHeaders).length > 0 && (
            <div className="response-headers card">
              <h4>📤 Response Headers (Will Be Set)</h4>
              <p className="section-description">These headers will be added to the response sent to the client</p>
              <div className="headers-list">
                {Object.entries(simulationResults.responseHeaders).map(([key, value]) => (
                  <div key={key} className="header-item">
                    <span className="header-name">{key}:</span>
                    <code className="header-value">{value}</code>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Simulated CDN Log */}
          <div className="cdn-log card">
            <h4>📝 Simulated CDN Log Entry</h4>
            <p className="section-description">This is what would appear in your CDN logs for this request</p>
            <pre className="log-output">
{JSON.stringify({
  timestamp: new Date().toISOString(),
  request: {
    method: simulationResults.currentRequest.method,
    originalPath: simulationResults.originalRequest.path,
    transformedPath: simulationResults.currentRequest.path,
    domain: simulationResults.currentRequest.domain,
    queryString: simulationResults.currentRequest.queryString || null
  },
  client: {
    ip: simulationResults.currentRequest.clientIp,
    country: simulationResults.currentRequest.clientCountry,
    userAgent: simulationResults.currentRequest.userAgent?.substring(0, 50) + '...'
  },
  tier: simulationResults.currentRequest.tier,
  response: {
    status: simulationResults.finalStatus,
    action: simulationResults.finalAction,
    blockingRule: simulationResults.blockingRule,
    redirectLocation: simulationResults.redirectLocation,
    selectedOrigin: simulationResults.selectedOrigin
  },
  waf: {
    flagsDetected: simulationResults.wafFlagsDetected.map(d => d.flag),
    rulesMatched: simulationResults.matchedRules
      .filter(r => r.phase === 'trafficFilters')
      .map(r => r.rule)
  },
  transformations: {
    pathChanged: simulationResults.originalRequest.path !== simulationResults.currentRequest.path,
    rulesApplied: simulationResults.matchedRules
      .filter(r => r.phase === 'requestTransformations')
      .map(r => r.rule)
  }
}, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default RulesSimulator;
