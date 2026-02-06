import React, { useState } from 'react';
import { WAF_FLAGS, SEVERITY_COLORS, SAMPLE_CDN_YAML, RULES_SYNTAX, EXAMPLE_RULES, OFAC_COUNTRIES, REQUEST_PROPERTIES, MATCH_OPERATORS } from '../data/wafData';
import './RulesAnalyzer.css';

const RulesAnalyzer = () => {
  const [yamlInput, setYamlInput] = useState('');
  const [analyzedRules, setAnalyzedRules] = useState([]);
  const [showWafReference, setShowWafReference] = useState(false);
  const [showSyntaxReference, setShowSyntaxReference] = useState(false);
  const [showExamples, setShowExamples] = useState(false);
  const [parseError, setParseError] = useState(null);
  const [analysisStats, setAnalysisStats] = useState(null);

  const parseYamlRules = (yaml) => {
    try {
      setParseError(null);
      const rules = [];
      
      const lines = yaml.split('\n');
      let currentRule = null;
      let inRules = false;
      let inWafFlags = false;
      let inGroupBy = false;
      let inCountryList = false;
      let inAllOf = false;
      let inAnyOf = false;
      let bracketDepth = 0;
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        const indent = line.search(/\S/);
        
        if (trimmed.includes('rules:') && !trimmed.startsWith('#')) {
          inRules = true;
          continue;
        }
        
        if (!inRules) continue;
        
        // Check for new rule (starts with - name:)
        if (trimmed.startsWith('- name:')) {
          if (currentRule) {
            rules.push(currentRule);
          }
          currentRule = {
            name: trimmed.replace('- name:', '').trim().replace(/['"]/g, ''),
            conditions: [],
            conditionLogic: null,
            action: null,
            actionType: null,
            wafFlags: [],
            rateLimit: null,
            geoBlock: null,
            alert: false,
            raw: [],
            lineStart: i + 1,
            tier: null,
            targetProperty: null,
            operator: null,
            warnings: [],
            recommendations: []
          };
          inWafFlags = false;
          inGroupBy = false;
          inCountryList = false;
          inAllOf = false;
          inAnyOf = false;
        }
        
        if (currentRule) {
          currentRule.raw.push(line);
          
          // Parse allOf/anyOf
          if (trimmed === 'allOf:') {
            currentRule.conditionLogic = 'AND';
            inAllOf = true;
            inAnyOf = false;
          }
          if (trimmed === 'anyOf:') {
            currentRule.conditionLogic = 'OR';
            inAnyOf = true;
            inAllOf = false;
          }
          
          // Parse conditions - inline format { reqProperty: path, equals: "/admin" }
          const inlineMatch = trimmed.match(/\{\s*reqProperty:\s*(\w+),?\s*(\w+)?:?\s*["']?([^"'}]+)?["']?\s*\}/);
          if (inlineMatch) {
            currentRule.conditions.push({
              property: inlineMatch[1],
              operator: inlineMatch[2] || 'equals',
              value: inlineMatch[3]?.trim()
            });
          }
          
          // Parse conditions - multi-line format
          if (trimmed.includes('reqProperty:') && !trimmed.includes('{')) {
            const prop = trimmed.replace('reqProperty:', '').trim().replace(/['"]/g, '');
            currentRule.targetProperty = prop;
          }
          
          // Parse operators
          const operators = ['equals', 'notEquals', 'like', 'notLike', 'matches', 'in', 'notIn'];
          operators.forEach(op => {
            if (trimmed.startsWith(op + ':') && !trimmed.includes('{')) {
              let val = trimmed.replace(op + ':', '').trim().replace(/['"]/g, '');
              // Handle array values for in/notIn
              if (val.startsWith('[') && val.endsWith(']')) {
                val = val.slice(1, -1).split(',').map(v => v.trim().replace(/['"]/g, ''));
              }
              if (currentRule.targetProperty) {
                currentRule.conditions.push({
                  property: currentRule.targetProperty,
                  operator: op,
                  value: val
                });
              }
              currentRule.operator = op;
            }
          });
          
          // Track tier specifically
          if (trimmed.includes('tier')) {
            const tierMatch = trimmed.match(/equals:\s*['"]?(author|publish)['"]?/);
            const tierInMatch = trimmed.match(/in:\s*\[.*?(author|publish).*?\]/);
            if (tierMatch) currentRule.tier = tierMatch[1];
            if (tierInMatch || trimmed.includes('"author"') || trimmed.includes('"publish"')) {
              if (trimmed.includes('author') && trimmed.includes('publish')) {
                currentRule.tier = 'both';
              }
            }
          }
          
          // Parse action
          if (trimmed.startsWith('action:') && !trimmed.includes('type')) {
            const action = trimmed.replace('action:', '').trim().replace(/['"]/g, '');
            if (['block', 'log', 'allow'].includes(action)) {
              currentRule.action = action;
              currentRule.actionType = action;
            }
          }
          if (trimmed.includes('type:') && !trimmed.includes('res_c')) {
            const typeMatch = trimmed.match(/type:\s*['"]?(block|log|allow)['"]?/);
            if (typeMatch) {
              currentRule.action = typeMatch[1];
              currentRule.actionType = typeMatch[1];
            }
          }
          
          // Parse WAF flags section
          if (trimmed === 'wafFlags:') {
            inWafFlags = true;
            inGroupBy = false;
            inCountryList = false;
          }
          
          // Parse WAF flag items
          if (inWafFlags && trimmed.startsWith('- ') && !trimmed.includes('name:')) {
            const flag = trimmed.replace('- ', '').trim().replace(/['"]/g, '');
            if (WAF_FLAGS[flag] || flag.match(/^[A-Z0-9-]+$/)) {
              currentRule.wafFlags.push(flag);
            }
          }
          
          // Parse inline wafFlags array
          const wafFlagsInline = trimmed.match(/wafFlags:\s*\[\s*([^\]]+)\s*\]/);
          if (wafFlagsInline) {
            const flags = wafFlagsInline[1].split(',').map(f => f.trim().replace(/['"]/g, ''));
            currentRule.wafFlags.push(...flags);
          }
          
          // Parse rate limit
          if (trimmed === 'rateLimit:') {
            currentRule.rateLimit = {};
            inWafFlags = false;
          }
          if (currentRule.rateLimit !== null) {
            if (trimmed.match(/limit:\s*\d+/)) {
              currentRule.rateLimit.limit = parseInt(trimmed.match(/limit:\s*(\d+)/)[1]);
            }
            if (trimmed.match(/window:\s*\d+/)) {
              currentRule.rateLimit.window = parseInt(trimmed.match(/window:\s*(\d+)/)[1]);
            }
            if (trimmed.match(/penalty:\s*\d+/)) {
              currentRule.rateLimit.penalty = parseInt(trimmed.match(/penalty:\s*(\d+)/)[1]);
            }
            if (trimmed.match(/count:\s*\w+/)) {
              currentRule.rateLimit.count = trimmed.match(/count:\s*(\w+)/)[1];
            }
            if (trimmed === 'groupBy:') {
              inGroupBy = true;
              inWafFlags = false;
              currentRule.rateLimit.groupBy = [];
            }
            if (inGroupBy && trimmed.startsWith('- reqProperty:')) {
              currentRule.rateLimit.groupBy.push(trimmed.replace('- reqProperty:', '').trim());
            }
          }
          
          // Parse country list for geo-blocking
          if (trimmed === 'in:' && currentRule.targetProperty === 'clientCountry') {
            inCountryList = true;
            currentRule.geoBlock = { countries: [] };
          }
          if (inCountryList && trimmed.startsWith('- ') && trimmed.length === 4) {
            const country = trimmed.replace('- ', '').trim();
            if (country.match(/^[A-Z]{2}$/)) {
              currentRule.geoBlock.countries.push(country);
            }
          }
          
          // Parse alert
          if (trimmed.match(/alert:\s*true/i)) {
            currentRule.alert = true;
          }
          
          // Stop parsing sections when we hit a new top-level item
          if (indent <= 8 && trimmed.startsWith('- name:') === false && trimmed !== '') {
            if (!trimmed.startsWith('-') && !trimmed.includes(':')) {
              // Might be end of section
            }
          }
        }
      }
      
      if (currentRule) {
        rules.push(currentRule);
      }
      
      // Post-process rules for analysis
      rules.forEach(rule => {
        // Add warnings and recommendations
        if (rule.wafFlags.length > 0 && rule.action === 'block') {
          if (rule.wafFlags.includes('ATTACK') && !rule.wafFlags.includes('ATTACK-FROM-BAD-IP')) {
            rule.warnings.push('ATTACK flag in block mode may cause false positives. Consider starting with LOG mode.');
          }
        }
        
        if (rule.rateLimit && rule.action === 'block') {
          rule.recommendations.push('Consider starting rate limit rules in LOG mode to validate thresholds before blocking.');
        }
        
        if (rule.wafFlags.length === 0 && !rule.rateLimit && !rule.geoBlock) {
          if (rule.action === 'block') {
            rule.recommendations.push('This is a simple path/property blocking rule. Ensure the pattern is specific enough to avoid blocking legitimate traffic.');
          }
        }
        
        if (rule.geoBlock && rule.geoBlock.countries.length > 0) {
          const ofacCodes = OFAC_COUNTRIES.map(c => c.code);
          const isOfacList = rule.geoBlock.countries.every(c => ofacCodes.includes(c));
          if (isOfacList) {
            rule.recommendations.push('Using OFAC sanctioned countries list. Verify compliance with your organization\'s legal requirements.');
          }
        }
      });
      
      return rules;
    } catch (error) {
      console.error('Parse error:', error);
      setParseError(`Failed to parse YAML: ${error.message}`);
      return [];
    }
  };

  const analyzeRules = () => {
    const parsed = parseYamlRules(yamlInput);
    setAnalyzedRules(parsed);
    
    // Calculate statistics
    const stats = {
      total: parsed.length,
      blocking: parsed.filter(r => r.action === 'block').length,
      logging: parsed.filter(r => r.action === 'log').length,
      allowing: parsed.filter(r => r.action === 'allow').length,
      wafRules: parsed.filter(r => r.wafFlags.length > 0).length,
      rateLimitRules: parsed.filter(r => r.rateLimit).length,
      geoBlockRules: parsed.filter(r => r.geoBlock).length,
      withAlerts: parsed.filter(r => r.alert).length,
      uniqueWafFlags: [...new Set(parsed.flatMap(r => r.wafFlags))],
      coverage: calculateCoverage(parsed)
    };
    setAnalysisStats(stats);
  };

  const calculateCoverage = (rules) => {
    const allFlags = Object.keys(WAF_FLAGS);
    const usedFlags = [...new Set(rules.flatMap(r => r.wafFlags))];
    return {
      used: usedFlags.length,
      total: allFlags.length,
      percentage: Math.round((usedFlags.length / allFlags.length) * 100),
      missing: allFlags.filter(f => !usedFlags.includes(f))
    };
  };

  const loadSampleConfig = () => {
    setYamlInput(SAMPLE_CDN_YAML);
  };

  const getRuleType = (rule) => {
    if (rule.wafFlags.length > 0) return { type: 'WAF Rule', color: 'purple', icon: '🛡️' };
    if (rule.rateLimit) return { type: 'Rate Limit', color: 'orange', icon: '⏱️' };
    if (rule.geoBlock) return { type: 'Geo-Block', color: 'blue', icon: '🌍' };
    if (rule.action === 'allow') return { type: 'Allow Rule', color: 'green', icon: '✅' };
    return { type: 'Traffic Filter', color: 'gray', icon: '🔒' };
  };

  const getRuleExplanation = (rule) => {
    const parts = [];
    const ruleType = getRuleType(rule);
    
    // Start with rule type
    parts.push(`**${ruleType.type}**: `);
    
    // Explain WAF flags
    if (rule.wafFlags.length > 0) {
      const flagDescriptions = rule.wafFlags.map(flag => {
        const flagData = WAF_FLAGS[flag];
        return flagData ? `**${flag}** (${flagData.attackType})` : flag;
      });
      parts.push(`Monitors for ${flagDescriptions.join(', ')} attack patterns. `);
      
      // Add specific WAF flag advice
      if (rule.wafFlags.includes('ATTACK-FROM-BAD-IP')) {
        parts.push(`\n\n💡 **Best Practice**: ATTACK-FROM-BAD-IP is safe to use in BLOCK mode immediately because it only triggers when both an attack pattern AND known malicious IP are detected. `);
      }
      if (rule.wafFlags.includes('ATTACK') && rule.action !== 'log') {
        parts.push(`\n\n⚠️ **Recommendation**: Consider using LOG mode initially for the ATTACK flag to avoid potential false positives, then switch to BLOCK after validating CDN logs. `);
      }
    }
    
    // Explain rate limiting
    if (rule.rateLimit) {
      const rl = rule.rateLimit;
      parts.push(`\n\n**Rate Limit Configuration**:\n`);
      parts.push(`- Maximum ${rl.limit} requests per ${rl.window} second window\n`);
      parts.push(`- Counting: ${rl.count === 'fetches' ? 'Only origin fetches (cache misses)' : rl.count === 'errors' ? 'Only error responses' : 'All requests'}\n`);
      if (rl.penalty) {
        parts.push(`- Penalty: Block violating clients for ${rl.penalty} seconds (${Math.round(rl.penalty / 60)} minutes)\n`);
      }
      if (rl.groupBy) {
        parts.push(`- Grouped by: ${rl.groupBy.join(', ')}\n`);
      }
    }
    
    // Explain geo-blocking
    if (rule.geoBlock && rule.geoBlock.countries.length > 0) {
      const countryNames = rule.geoBlock.countries.map(code => {
        const country = OFAC_COUNTRIES.find(c => c.code === code);
        return country ? `${country.name} (${code})` : code;
      });
      parts.push(`\n\n**Geographic Restrictions**:\n`);
      parts.push(`Blocks traffic from: ${countryNames.join(', ')}`);
    }
    
    // Explain conditions
    if (rule.conditions.length > 0) {
      parts.push(`\n\n**Conditions** (${rule.conditionLogic || 'single'}):\n`);
      rule.conditions.forEach(cond => {
        const propInfo = REQUEST_PROPERTIES.find(p => p.value === cond.property);
        const opInfo = MATCH_OPERATORS.find(o => o.value === cond.operator);
        parts.push(`- ${propInfo?.label || cond.property} ${opInfo?.label || cond.operator} "${Array.isArray(cond.value) ? cond.value.join(', ') : cond.value}"\n`);
      });
    }
    
    // Explain tier
    if (rule.tier) {
      const tierDesc = rule.tier === 'both' ? 'Both Author and Publish tiers' : 
                       rule.tier === 'author' ? 'Author tier only (content editors)' : 
                       'Publish tier only (public users)';
      parts.push(`\n\n**Applies to**: ${tierDesc}`);
    }
    
    // Explain action
    if (rule.action) {
      const actionDesc = {
        block: '🚫 **BLOCK**: Immediately rejects matching requests with 403 Forbidden',
        log: '📝 **LOG**: Records matching requests in CDN logs but allows them through. Useful for testing rules before blocking.',
        allow: '✅ **ALLOW**: Explicitly permits matching requests, bypassing subsequent blocking rules'
      };
      parts.push(`\n\n**Action**: ${actionDesc[rule.action] || rule.action}`);
    }
    
    // Alert status
    if (rule.alert) {
      parts.push(`\n\n🔔 **Alerts Enabled**: Notifications will be sent when this rule triggers.`);
    }
    
    return parts.join('');
  };

  const getTriggeredExamples = (rule) => {
    const examples = [];
    rule.wafFlags.forEach(flag => {
      const flagData = WAF_FLAGS[flag];
      if (flagData && flagData.examples) {
        flagData.examples.forEach(ex => {
          examples.push({
            attack: ex,
            flag: flag,
            type: flagData.attackType,
            severity: flagData.severity,
            mitigates: flagData.mitigates
          });
        });
      }
    });
    return examples;
  };

  const getSecurityScore = () => {
    if (!analysisStats) return null;
    
    let score = 0;
    const maxScore = 100;
    const details = [];
    
    // WAF coverage (40 points)
    const wafScore = Math.min(40, analysisStats.coverage.percentage * 0.4);
    score += wafScore;
    details.push({ label: 'WAF Coverage', score: wafScore, max: 40 });
    
    // Rate limiting (20 points)
    const rlScore = analysisStats.rateLimitRules > 0 ? 20 : 0;
    score += rlScore;
    details.push({ label: 'Rate Limiting', score: rlScore, max: 20 });
    
    // Geo-blocking (15 points)
    const geoScore = analysisStats.geoBlockRules > 0 ? 15 : 0;
    score += geoScore;
    details.push({ label: 'Geo-Blocking', score: geoScore, max: 15 });
    
    // Blocking rules (15 points)
    const blockScore = analysisStats.blocking > 0 ? 15 : 0;
    score += blockScore;
    details.push({ label: 'Active Blocking', score: blockScore, max: 15 });
    
    // Alerts (10 points)
    const alertScore = analysisStats.withAlerts > 0 ? 10 : 0;
    score += alertScore;
    details.push({ label: 'Alert Configuration', score: alertScore, max: 10 });
    
    return { score: Math.round(score), maxScore, details };
  };

  return (
    <div className="rules-analyzer">
      <div className="analyzer-header">
        <div>
          <h1>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.35-4.35" />
              <path d="M11 8v6" />
              <path d="M8 11h6" />
            </svg>
            WAF Rules Analyzer
          </h1>
          <p>Comprehensive analysis of your cdn.yaml traffic filter rules with detailed explanations</p>
        </div>
        <div className="analyzer-actions">
          <button className="btn btn-ghost" onClick={() => setShowExamples(!showExamples)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
            </svg>
            Examples
          </button>
          <button className="btn btn-ghost" onClick={() => setShowSyntaxReference(!showSyntaxReference)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="16 18 22 12 16 6" />
              <polyline points="8 6 2 12 8 18" />
            </svg>
            Syntax
          </button>
          <button className="btn btn-secondary" onClick={() => setShowWafReference(!showWafReference)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            WAF Flags
          </button>
        </div>
      </div>

      {showExamples && (
        <div className="examples-panel card animate-slide-up">
          <div className="card-header">
            <h3 className="card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              </svg>
              Rule Examples from Adobe Documentation
            </h3>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowExamples(false)}>×</button>
          </div>
          <div className="examples-grid">
            {EXAMPLE_RULES.map((example, idx) => (
              <div key={idx} className="example-card">
                <div className="example-header">
                  <span className="example-category">{example.category}</span>
                  <code className="example-name">{example.name}</code>
                </div>
                <pre className="example-yaml">{example.yaml}</pre>
                <p className="example-explanation">{example.explanation}</p>
                <button 
                  className="btn btn-ghost btn-sm"
                  onClick={() => setYamlInput(prev => prev + '\n' + example.yaml)}
                >
                  Add to Input
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {showSyntaxReference && (
        <div className="syntax-panel card animate-slide-up">
          <div className="card-header">
            <h3 className="card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="16 18 22 12 16 6" />
                <polyline points="8 6 2 12 8 18" />
              </svg>
              Rules Syntax Reference
            </h3>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowSyntaxReference(false)}>×</button>
          </div>
          
          <div className="syntax-sections">
            <div className="syntax-section">
              <h4>📋 Rule Properties</h4>
              <div className="syntax-table">
                {Object.entries(RULES_SYNTAX.properties).map(([key, prop]) => (
                  <div key={key} className="syntax-row">
                    <code className="syntax-key">{key}</code>
                    <span className="syntax-required">{prop.required ? 'Required' : 'Optional'}</span>
                    <span className="syntax-desc">{prop.description}</span>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="syntax-section">
              <h4>🔍 Match Operators</h4>
              <div className="syntax-table">
                {Object.entries(RULES_SYNTAX.operators).map(([key, op]) => (
                  <div key={key} className="syntax-row">
                    <code className="syntax-key">{key}</code>
                    <span className="syntax-desc">{op.description}</span>
                    <code className="syntax-example">{op.example}</code>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="syntax-section">
              <h4>📍 Request Properties</h4>
              <div className="syntax-table">
                {Object.entries(RULES_SYNTAX.requestProperties).map(([key, prop]) => (
                  <div key={key} className="syntax-row">
                    <code className="syntax-key">{key}</code>
                    <span className="syntax-desc">{prop.description}</span>
                    <span className="syntax-example-text">e.g., {prop.example}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {showWafReference && (
        <div className="waf-reference card animate-slide-up">
          <div className="card-header">
            <h3 className="card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              WAF Flags Reference (Requires Extended Security License)
            </h3>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowWafReference(false)}>×</button>
          </div>
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Flag</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Description</th>
                  <th>Recommended Action</th>
                  <th>Attack Examples</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(WAF_FLAGS).map(([key, flag]) => (
                  <tr key={key}>
                    <td>
                      <code className="code-inline">{flag.name}</code>
                      {flag.recommended && <span className="recommended-badge">★ Recommended</span>}
                    </td>
                    <td>{flag.category}</td>
                    <td>
                      <span 
                        className="badge"
                        style={{ 
                          background: SEVERITY_COLORS[flag.severity].bg,
                          color: SEVERITY_COLORS[flag.severity].color 
                        }}
                      >
                        {flag.severity}
                      </span>
                    </td>
                    <td className="desc-cell">{flag.description}</td>
                    <td>
                      <span className={`action-recommendation ${flag.recommendedAction || 'log'}`}>
                        {flag.recommendedAction?.toUpperCase() || 'LOG first'}
                      </span>
                    </td>
                    <td>
                      <div className="example-list">
                        {flag.examples.slice(0, 2).map((ex, i) => (
                          <code key={i} className="example-code">{ex}</code>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="analyzer-grid">
        <div className="input-panel card">
          <div className="card-header">
            <h3 className="card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
              </svg>
              cdn.yaml Configuration
            </h3>
            <button className="btn btn-ghost btn-sm" onClick={loadSampleConfig}>
              Load Sample
            </button>
          </div>
          <textarea
            className="form-textarea yaml-input"
            value={yamlInput}
            onChange={(e) => setYamlInput(e.target.value)}
            placeholder={`Paste your cdn.yaml content here...

kind: "CDN"
version: "1"
data:
  trafficFilters:
    rules:
      - name: my-rule
        when:
          reqProperty: tier
          equals: 'publish'
        action: block`}
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
          <button className="btn btn-primary btn-lg analyze-btn" onClick={analyzeRules}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.35-4.35" />
            </svg>
            Analyze Rules
          </button>
        </div>

        <div className="results-panel">
          {analysisStats && (
            <div className="stats-panel animate-slide-up">
              <div className="stats-header">
                <h3>Analysis Summary</h3>
                {getSecurityScore() && (
                  <div className="security-score">
                    <span className="score-label">Security Score</span>
                    <span className={`score-value ${getSecurityScore().score >= 70 ? 'good' : getSecurityScore().score >= 40 ? 'medium' : 'low'}`}>
                      {getSecurityScore().score}/{getSecurityScore().maxScore}
                    </span>
                  </div>
                )}
              </div>
              <div className="stats-grid">
                <div className="stat-item">
                  <span className="stat-value">{analysisStats.total}</span>
                  <span className="stat-label">Total Rules</span>
                </div>
                <div className="stat-item blocking">
                  <span className="stat-value">{analysisStats.blocking}</span>
                  <span className="stat-label">Blocking</span>
                </div>
                <div className="stat-item logging">
                  <span className="stat-value">{analysisStats.logging}</span>
                  <span className="stat-label">Logging</span>
                </div>
                <div className="stat-item waf">
                  <span className="stat-value">{analysisStats.wafRules}</span>
                  <span className="stat-label">WAF Rules</span>
                </div>
                <div className="stat-item rate">
                  <span className="stat-value">{analysisStats.rateLimitRules}</span>
                  <span className="stat-label">Rate Limits</span>
                </div>
                <div className="stat-item geo">
                  <span className="stat-value">{analysisStats.geoBlockRules}</span>
                  <span className="stat-label">Geo-Block</span>
                </div>
              </div>
              {analysisStats.coverage.missing.length > 0 && (
                <div className="coverage-warning">
                  <strong>⚠️ WAF Coverage Gap:</strong> {analysisStats.coverage.used}/{analysisStats.coverage.total} flags used ({analysisStats.coverage.percentage}%)
                  <div className="missing-flags">
                    Missing: {analysisStats.coverage.missing.slice(0, 5).join(', ')}
                    {analysisStats.coverage.missing.length > 5 && ` and ${analysisStats.coverage.missing.length - 5} more`}
                  </div>
                </div>
              )}
            </div>
          )}

          {analyzedRules.length > 0 ? (
            <div className="rules-list">
              <div className="results-header">
                <h3>{analyzedRules.length} Rule{analyzedRules.length !== 1 ? 's' : ''} Analyzed</h3>
              </div>
              {analyzedRules.map((rule, index) => {
                const ruleType = getRuleType(rule);
                return (
                  <div key={index} className="rule-card card animate-slide-up" style={{ animationDelay: `${index * 50}ms` }}>
                    <div className="rule-header">
                      <div className="rule-title">
                        <span className="rule-icon">{ruleType.icon}</span>
                        <span className="rule-number">#{index + 1}</span>
                        <code className="rule-name">{rule.name}</code>
                      </div>
                      <div className="rule-badges">
                        <span className={`badge badge-${ruleType.color}`}>{ruleType.type}</span>
                        {rule.action && (
                          <span className={`badge badge-${rule.action === 'block' ? 'red' : rule.action === 'log' ? 'blue' : 'green'}`}>
                            {rule.action.toUpperCase()}
                          </span>
                        )}
                        {rule.alert && (
                          <span className="badge badge-orange">🔔 Alert</span>
                        )}
                      </div>
                    </div>
                    
                    {(rule.warnings.length > 0 || rule.recommendations.length > 0) && (
                      <div className="rule-alerts">
                        {rule.warnings.map((warning, i) => (
                          <div key={i} className="alert-item warning">
                            <span className="alert-icon">⚠️</span>
                            {warning}
                          </div>
                        ))}
                        {rule.recommendations.map((rec, i) => (
                          <div key={i} className="alert-item recommendation">
                            <span className="alert-icon">💡</span>
                            {rec}
                          </div>
                        ))}
                      </div>
                    )}
                    
                    <div className="rule-explanation">
                      <h4>Detailed Explanation</h4>
                      <div className="explanation-content" dangerouslySetInnerHTML={{ __html: getRuleExplanation(rule).replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br/>') }} />
                    </div>

                    {rule.wafFlags.length > 0 && (
                      <div className="rule-flags">
                        <h4>WAF Protections Enabled</h4>
                        <div className="flag-cards">
                          {rule.wafFlags.map(flag => {
                            const flagData = WAF_FLAGS[flag];
                            return (
                              <div key={flag} className="flag-card">
                                <div className="flag-card-header">
                                  <code className="flag-name">{flag}</code>
                                  {flagData && (
                                    <span 
                                      className="flag-severity"
                                      style={{ 
                                        background: SEVERITY_COLORS[flagData.severity]?.bg,
                                        color: SEVERITY_COLORS[flagData.severity]?.color 
                                      }}
                                    >
                                      {flagData.severity}
                                    </span>
                                  )}
                                </div>
                                {flagData && (
                                  <>
                                    <p className="flag-desc">{flagData.description}</p>
                                    <p className="flag-mitigates"><strong>Mitigates:</strong> {flagData.mitigates}</p>
                                  </>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {getTriggeredExamples(rule).length > 0 && (
                      <div className="rule-examples">
                        <h4>Attack Patterns That Trigger This Rule</h4>
                        <div className="examples-table">
                          <table className="table">
                            <thead>
                              <tr>
                                <th>Attack Pattern</th>
                                <th>WAF Flag</th>
                                <th>Attack Type</th>
                                <th>Severity</th>
                              </tr>
                            </thead>
                            <tbody>
                              {getTriggeredExamples(rule).slice(0, 6).map((example, i) => (
                                <tr key={i}>
                                  <td><code className="attack-example">{example.attack}</code></td>
                                  <td><code className="code-inline">{example.flag}</code></td>
                                  <td>{example.type}</td>
                                  <td>
                                    <span 
                                      className="badge"
                                      style={{ 
                                        background: SEVERITY_COLORS[example.severity]?.bg,
                                        color: SEVERITY_COLORS[example.severity]?.color 
                                      }}
                                    >
                                      {example.severity}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {rule.rateLimit && (
                      <div className="rule-rate-limit">
                        <h4>Rate Limit Configuration</h4>
                        <div className="rate-limit-visual">
                          <div className="rate-limit-item">
                            <div className="rate-limit-icon">📊</div>
                            <div className="rate-limit-content">
                              <span className="rate-limit-value">{rule.rateLimit.limit}</span>
                              <span className="rate-limit-label">requests max</span>
                            </div>
                          </div>
                          <div className="rate-limit-arrow">→</div>
                          <div className="rate-limit-item">
                            <div className="rate-limit-icon">⏱️</div>
                            <div className="rate-limit-content">
                              <span className="rate-limit-value">{rule.rateLimit.window}s</span>
                              <span className="rate-limit-label">time window</span>
                            </div>
                          </div>
                          {rule.rateLimit.penalty && (
                            <>
                              <div className="rate-limit-arrow">→</div>
                              <div className="rate-limit-item penalty">
                                <div className="rate-limit-icon">🚫</div>
                                <div className="rate-limit-content">
                                  <span className="rate-limit-value">{rule.rateLimit.penalty}s</span>
                                  <span className="rate-limit-label">block penalty</span>
                                </div>
                              </div>
                            </>
                          )}
                        </div>
                        <p className="rate-limit-summary">
                          {rule.rateLimit.count === 'fetches' 
                            ? '📌 Only counting requests that reach origin (cache misses)'
                            : rule.rateLimit.count === 'errors'
                            ? '📌 Only counting error responses (4xx, 5xx)'
                            : '📌 Counting all requests including cached responses'}
                        </p>
                      </div>
                    )}

                    {rule.geoBlock && rule.geoBlock.countries.length > 0 && (
                      <div className="rule-geo-block">
                        <h4>🌍 Geographic Restrictions</h4>
                        <div className="country-list">
                          {rule.geoBlock.countries.map(code => {
                            const country = OFAC_COUNTRIES.find(c => c.code === code);
                            return (
                              <span key={code} className="country-badge">
                                {country ? `${country.name} (${code})` : code}
                              </span>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">
              <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.35-4.35" />
              </svg>
              <h3>No Rules Analyzed Yet</h3>
              <p>Paste your cdn.yaml configuration and click "Analyze Rules" to see a detailed breakdown.</p>
              <p className="hint">💡 Click "Load Sample" to try with Adobe's recommended starter rules, or check "Examples" for common patterns.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default RulesAnalyzer;
