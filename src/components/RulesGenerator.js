import React, { useState, useCallback } from 'react';
import { WAF_FLAGS, SEVERITY_COLORS, ACTION_TYPES, TIER_OPTIONS, RECOMMENDED_STARTER_RULES, RATE_LIMIT_COUNT_OPTIONS, OFAC_COUNTRIES, MATCH_OPERATORS } from '../data/wafData';
import { CDN_RULE_TYPES, CONDITION_OPERATORS, REQUEST_PROPERTIES, TEMPLATE_RULES, CONDITION_EXAMPLES, REDIRECT_STATUS_CODES, COMMON_RESPONSE_HEADERS, SECURITY_HEADERS_PRESETS } from '../data/cdnConfigData';
import './RulesGenerator.css';

const RulesGenerator = ({ onRulesGenerated }) => {
  const [activeRuleType, setActiveRuleType] = useState('trafficFilter');
  const [rules, setRules] = useState([]);
  const [generatedYaml, setGeneratedYaml] = useState('');
  const [activeTab, setActiveTab] = useState('builder');
  const [showTemplates, setShowTemplates] = useState(false);
  const [showConditionHelp, setShowConditionHelp] = useState(false);
  const [validationErrors, setValidationErrors] = useState({});

  // Create new rule based on type
  const createNewRule = (type = activeRuleType) => {
    const baseRule = {
      id: Date.now(),
      type,
      name: `${type}-rule-${rules.filter(r => r.type === type).length + 1}`,
      expanded: true,
      conditions: [{
        id: Date.now(),
        property: 'path',
        propertyType: 'reqProperty',
        operator: 'like',
        value: '/*'
      }],
      conditionLogic: 'allOf'
    };

    switch (type) {
      case 'trafficFilter':
        return {
          ...baseRule,
          tier: 'both',
          action: 'log',
          wafFlags: [],
          rateLimit: null,
          geoBlock: { enabled: false, countries: [] },
          alert: false
        };
      case 'requestTransformations':
        return {
          ...baseRule,
          actions: [{
            id: Date.now(),
            type: 'set',
            target: 'reqHeader',
            key: '',
            value: ''
          }]
        };
      case 'responseTransformations':
        return {
          ...baseRule,
          actions: [{
            id: Date.now(),
            type: 'set',
            target: 'respHeader',
            key: '',
            value: ''
          }]
        };
      case 'redirects':
        return {
          ...baseRule,
          status: 301,
          location: '',
          locationTransform: null
        };
      case 'originSelectors':
        return {
          ...baseRule,
          originName: '',
          originType: 'custom',
          originDomain: '',
          forwardHost: false,
          forwardCookie: false,
          forwardAuthorization: false,
          timeout: 60,
          skipCache: false
        };
      default:
        return baseRule;
    }
  };

  const addRule = () => {
    setRules([...rules, createNewRule()]);
  };

  const updateRule = useCallback((id, updates) => {
    setRules(prevRules =>
      prevRules.map(rule =>
        rule.id === id ? { ...rule, ...updates } : rule
      )
    );
  }, []);

  const deleteRule = (id) => {
    setRules(rules.filter(rule => rule.id !== id));
  };

  const duplicateRule = (id) => {
    const rule = rules.find(r => r.id === id);
    if (rule) {
      const newRule = {
        ...JSON.parse(JSON.stringify(rule)),
        id: Date.now(),
        name: `${rule.name}-copy`,
        expanded: true
      };
      setRules([...rules, newRule]);
    }
  };

  // Condition management
  const addCondition = (ruleId) => {
    const rule = rules.find(r => r.id === ruleId);
    if (rule) {
      updateRule(ruleId, {
        conditions: [...rule.conditions, {
          id: Date.now(),
          property: 'path',
          propertyType: 'reqProperty',
          operator: 'like',
          value: ''
        }]
      });
    }
  };

  const updateCondition = (ruleId, conditionId, updates) => {
    const rule = rules.find(r => r.id === ruleId);
    if (rule) {
      updateRule(ruleId, {
        conditions: rule.conditions.map(c =>
          c.id === conditionId ? { ...c, ...updates } : c
        )
      });
    }
  };

  const deleteCondition = (ruleId, conditionId) => {
    const rule = rules.find(r => r.id === ruleId);
    if (rule && rule.conditions.length > 1) {
      updateRule(ruleId, {
        conditions: rule.conditions.filter(c => c.id !== conditionId)
      });
    }
  };

  // Action management for transforms
  const addAction = (ruleId) => {
    const rule = rules.find(r => r.id === ruleId);
    if (rule && rule.actions) {
      updateRule(ruleId, {
        actions: [...rule.actions, {
          id: Date.now(),
          type: 'set',
          target: rule.type === 'requestTransformations' ? 'reqHeader' : 'respHeader',
          key: '',
          value: ''
        }]
      });
    }
  };

  const updateAction = (ruleId, actionId, updates) => {
    const rule = rules.find(r => r.id === ruleId);
    if (rule && rule.actions) {
      updateRule(ruleId, {
        actions: rule.actions.map(a =>
          a.id === actionId ? { ...a, ...updates } : a
        )
      });
    }
  };

  const deleteAction = (ruleId, actionId) => {
    const rule = rules.find(r => r.id === ruleId);
    if (rule && rule.actions && rule.actions.length > 1) {
      updateRule(ruleId, {
        actions: rule.actions.filter(a => a.id !== actionId)
      });
    }
  };

  // WAF flag toggle
  const toggleWafFlag = (ruleId, flag) => {
    const rule = rules.find(r => r.id === ruleId);
    if (rule) {
      const newFlags = rule.wafFlags.includes(flag)
        ? rule.wafFlags.filter(f => f !== flag)
        : [...rule.wafFlags, flag];
      updateRule(ruleId, { wafFlags: newFlags });
    }
  };

  // Apply template
  const applyTemplate = (templateKey) => {
    const template = TEMPLATE_RULES[templateKey];
    if (template) {
      // Add a marker comment to show this came from template
      const newRule = createNewRule(template.type);
      newRule.name = templateKey;
      newRule.templateYaml = template.yaml;
      newRule.explanation = template.explanation;
      setRules([...rules, newRule]);
    }
    setShowTemplates(false);
  };

  // Generate YAML
  const generateYaml = () => {
    let yaml = `kind: "CDN"\nversion: "1"\ndata:\n`;

    // Group rules by type
    const rulesByType = rules.reduce((acc, rule) => {
      if (!acc[rule.type]) acc[rule.type] = [];
      acc[rule.type].push(rule);
      return acc;
    }, {});

    // Generate Traffic Filter Rules
    if (rulesByType.trafficFilter?.length > 0) {
      yaml += `  trafficFilters:\n    rules:\n`;
      rulesByType.trafficFilter.forEach(rule => {
        yaml += generateTrafficFilterYaml(rule);
      });
    }

    // Generate Request Transformations
    if (rulesByType.requestTransformations?.length > 0) {
      yaml += `  requestTransformations:\n    rules:\n`;
      rulesByType.requestTransformations.forEach(rule => {
        yaml += generateRequestTransformYaml(rule);
      });
    }

    // Generate Response Transformations
    if (rulesByType.responseTransformations?.length > 0) {
      yaml += `  responseTransformations:\n    rules:\n`;
      rulesByType.responseTransformations.forEach(rule => {
        yaml += generateResponseTransformYaml(rule);
      });
    }

    // Generate Redirects
    if (rulesByType.redirects?.length > 0) {
      yaml += `  redirects:\n    rules:\n`;
      rulesByType.redirects.forEach(rule => {
        yaml += generateRedirectYaml(rule);
      });
    }

    // Generate Origin Selectors
    if (rulesByType.originSelectors?.length > 0) {
      yaml += `  originSelectors:\n    rules:\n`;
      const origins = [];
      rulesByType.originSelectors.forEach(rule => {
        yaml += generateOriginSelectorYaml(rule);
        if (rule.originType === 'custom' && rule.originName && rule.originDomain) {
          origins.push(rule);
        }
      });
      if (origins.length > 0) {
        yaml += `    origins:\n`;
        origins.forEach(rule => {
          yaml += `      - name: ${rule.originName}\n`;
          yaml += `        domain: ${rule.originDomain}\n`;
          if (rule.forwardHost) yaml += `        forwardHost: true\n`;
          if (rule.forwardCookie) yaml += `        forwardCookie: true\n`;
          if (rule.forwardAuthorization) yaml += `        forwardAuthorization: true\n`;
          if (rule.timeout !== 60) yaml += `        timeout: ${rule.timeout}\n`;
        });
      }
    }

    setGeneratedYaml(yaml);
    setActiveTab('output');
  };

  // Generate condition YAML
  const generateConditionYaml = (conditions, logic, indent = 8) => {
    const spaces = ' '.repeat(indent);
    if (conditions.length === 1) {
      const c = conditions[0];
      if (c.operator === 'in' || c.operator === 'notIn') {
        const values = c.value.split(',').map(v => `"${v.trim()}"`).join(', ');
        return `${spaces}when:\n${spaces}  ${c.propertyType}: ${c.property}\n${spaces}  ${c.operator}: [${values}]\n`;
      }
      return `${spaces}when:\n${spaces}  ${c.propertyType}: ${c.property}\n${spaces}  ${c.operator}: "${c.value}"\n`;
    }
    
    let yaml = `${spaces}when:\n${spaces}  ${logic}:\n`;
    conditions.forEach(c => {
      if (c.operator === 'in' || c.operator === 'notIn') {
        const values = c.value.split(',').map(v => `"${v.trim()}"`).join(', ');
        yaml += `${spaces}    - { ${c.propertyType}: ${c.property}, ${c.operator}: [${values}] }\n`;
      } else {
        yaml += `${spaces}    - { ${c.propertyType}: ${c.property}, ${c.operator}: "${c.value}" }\n`;
      }
    });
    return yaml;
  };

  // Generate Traffic Filter YAML
  const generateTrafficFilterYaml = (rule) => {
    let yaml = `      - name: ${rule.name}\n`;
    
    // Conditions
    const conditions = [...rule.conditions];
    if (rule.tier && rule.tier !== 'both') {
      conditions.unshift({
        propertyType: 'reqProperty',
        property: 'tier',
        operator: 'equals',
        value: rule.tier
      });
    } else if (rule.tier === 'both') {
      conditions.unshift({
        propertyType: 'reqProperty',
        property: 'tier',
        operator: 'in',
        value: 'author,publish'
      });
    }
    
    if (rule.geoBlock?.enabled && rule.geoBlock.countries?.length > 0) {
      conditions.push({
        propertyType: 'reqProperty',
        property: 'clientCountry',
        operator: 'in',
        value: rule.geoBlock.countries.join(',')
      });
    }
    
    yaml += generateConditionYaml(conditions, rule.conditionLogic);
    
    // Rate Limit
    if (rule.rateLimit?.limit) {
      yaml += `        rateLimit:\n`;
      yaml += `          limit: ${rule.rateLimit.limit}\n`;
      yaml += `          window: ${rule.rateLimit.window || 10}\n`;
      yaml += `          count: ${rule.rateLimit.count || 'all'}\n`;
      if (rule.rateLimit.penalty) yaml += `          penalty: ${rule.rateLimit.penalty}\n`;
      yaml += `          groupBy:\n            - reqProperty: clientIp\n`;
    }
    
    // Action
    if (rule.wafFlags?.length > 0) {
      yaml += `        action:\n`;
      yaml += `          type: ${rule.action}\n`;
      yaml += `          wafFlags:\n`;
      rule.wafFlags.forEach(flag => {
        yaml += `            - ${flag}\n`;
      });
    } else {
      yaml += `        action: ${rule.action}\n`;
    }
    
    if (rule.alert) yaml += `        alert: true\n`;
    yaml += '\n';
    return yaml;
  };

  // Generate Request Transform YAML
  const generateRequestTransformYaml = (rule) => {
    let yaml = `      - name: ${rule.name}\n`;
    yaml += generateConditionYaml(rule.conditions, rule.conditionLogic);
    yaml += `        actions:\n`;
    
    rule.actions?.forEach(action => {
      if (action.type === 'transform') {
        yaml += `          - type: transform\n`;
        yaml += `            ${action.target}: ${action.key}\n`;
        yaml += `            op: ${action.op || 'replace'}\n`;
        if (action.match) yaml += `            match: "${action.match}"\n`;
        if (action.replacement !== undefined) yaml += `            replacement: "${action.replacement}"\n`;
      } else {
        yaml += `          - type: ${action.type}\n`;
        yaml += `            ${action.target}: ${action.key}\n`;
        if (action.type === 'set' && action.value) {
          yaml += `            value: "${action.value}"\n`;
        }
      }
    });
    yaml += '\n';
    return yaml;
  };

  // Generate Response Transform YAML
  const generateResponseTransformYaml = (rule) => {
    let yaml = `      - name: ${rule.name}\n`;
    yaml += generateConditionYaml(rule.conditions, rule.conditionLogic);
    yaml += `        actions:\n`;
    
    rule.actions?.forEach(action => {
      yaml += `          - type: ${action.type}\n`;
      yaml += `            ${action.target}: ${action.key}\n`;
      if (action.type === 'set' && action.value) {
        yaml += `            value: "${action.value}"\n`;
      }
    });
    yaml += '\n';
    return yaml;
  };

  // Generate Redirect YAML
  const generateRedirectYaml = (rule) => {
    let yaml = `      - name: ${rule.name}\n`;
    yaml += generateConditionYaml(rule.conditions, rule.conditionLogic);
    yaml += `        action:\n`;
    yaml += `          type: redirect\n`;
    yaml += `          status: ${rule.status}\n`;
    yaml += `          location: "${rule.location}"\n`;
    yaml += '\n';
    return yaml;
  };

  // Generate Origin Selector YAML
  const generateOriginSelectorYaml = (rule) => {
    let yaml = `      - name: ${rule.name}\n`;
    yaml += generateConditionYaml(rule.conditions, rule.conditionLogic);
    yaml += `        action:\n`;
    if (rule.originType === 'aem') {
      yaml += `          type: selectAemOrigin\n`;
      yaml += `          originName: ${rule.originName || 'static'}\n`;
    } else {
      yaml += `          type: selectOrigin\n`;
      yaml += `          originName: ${rule.originName}\n`;
    }
    if (rule.skipCache) yaml += `          skipCache: true\n`;
    yaml += '\n';
    return yaml;
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(generatedYaml);
  };

  const downloadYaml = () => {
    const blob = new Blob([generatedYaml], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cdn.yaml';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const rulesOfCurrentType = rules.filter(r => r.type === activeRuleType);

  return (
    <div className="rules-generator">
      <div className="generator-header">
        <div>
          <h1>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
            </svg>
            CDN Configuration Generator
          </h1>
          <p>Build traffic filter rules, transformations, redirects, and origin selectors visually</p>
        </div>
        <div className="generator-actions">
          <button className="btn btn-ghost" onClick={() => setShowConditionHelp(!showConditionHelp)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            Condition Help
          </button>
          <button className="btn btn-secondary" onClick={() => setShowTemplates(!showTemplates)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
            </svg>
            Templates
          </button>
        </div>
      </div>

      {/* Rule Type Selector */}
      <div className="rule-type-selector">
        {Object.entries(CDN_RULE_TYPES).map(([key, type]) => (
          <button
            key={key}
            className={`rule-type-btn ${activeRuleType === key ? 'active' : ''}`}
            onClick={() => setActiveRuleType(key)}
          >
            <span className="rule-type-name">{type.name}</span>
            <span className="rule-type-desc">{type.description.slice(0, 50)}...</span>
            {rules.filter(r => r.type === key).length > 0 && (
              <span className="rule-type-count">{rules.filter(r => r.type === key).length}</span>
            )}
          </button>
        ))}
      </div>

      {/* Condition Help Panel */}
      {showConditionHelp && (
        <div className="help-panel card animate-slide-up">
          <div className="card-header">
            <h3 className="card-title">Condition Structure Reference</h3>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowConditionHelp(false)}>×</button>
          </div>
          <div className="help-grid">
            {Object.entries(CONDITION_EXAMPLES).map(([key, example]) => (
              <div key={key} className="help-example">
                <h4>{example.name}</h4>
                <pre>{example.yaml}</pre>
                <p>{example.explanation}</p>
              </div>
            ))}
          </div>
          <div className="help-section">
            <h4>Available Operators</h4>
            <div className="operators-grid">
              {Object.entries(CONDITION_OPERATORS).map(([key, op]) => (
                <div key={key} className="operator-item">
                  <code>{op.name}</code>
                  <span>{op.description}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Templates Panel */}
      {showTemplates && (
        <div className="templates-panel card animate-slide-up">
          <div className="card-header">
            <h3 className="card-title">Rule Templates</h3>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowTemplates(false)}>×</button>
          </div>
          <div className="templates-grid">
            {Object.entries(TEMPLATE_RULES)
              .filter(([, t]) => t.type === activeRuleType)
              .map(([key, template]) => (
                <div key={key} className="template-card" onClick={() => applyTemplate(key)}>
                  <h4>{template.name}</h4>
                  <p>{template.description}</p>
                  <pre>{template.yaml.slice(0, 150)}...</pre>
                  <span className="template-cta">Use Template →</span>
                </div>
              ))}
            {Object.entries(TEMPLATE_RULES).filter(([, t]) => t.type === activeRuleType).length === 0 && (
              <p className="no-templates">No templates for this rule type. Select another type or create a custom rule.</p>
            )}
          </div>
        </div>
      )}

      {/* Main Tabs */}
      <div className="generator-tabs">
        <button className={`tab ${activeTab === 'builder' ? 'active' : ''}`} onClick={() => setActiveTab('builder')}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
          </svg>
          Rule Builder
        </button>
        <button className={`tab ${activeTab === 'output' ? 'active' : ''}`} onClick={() => setActiveTab('output')}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
          </svg>
          Generated YAML
          {generatedYaml && <span className="tab-badge">Ready</span>}
        </button>
      </div>

      {activeTab === 'builder' && (
        <div className="builder-content">
          <div className="builder-toolbar">
            <button className="btn btn-primary" onClick={addRule}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
              Add {CDN_RULE_TYPES[activeRuleType].name.replace(' Rules', '')} Rule
            </button>
            {rules.length > 0 && (
              <button className="btn btn-secondary" onClick={generateYaml}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="16 18 22 12 16 6" />
                  <polyline points="8 6 2 12 8 18" />
                </svg>
                Generate YAML ({rules.length} rules)
              </button>
            )}
          </div>

          {rulesOfCurrentType.length === 0 ? (
            <div className="empty-state">
              <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
              </svg>
              <h3>No {CDN_RULE_TYPES[activeRuleType].name} Yet</h3>
              <p>{CDN_RULE_TYPES[activeRuleType].description}</p>
              <p className="hint">💡 Click "Add Rule" or use "Templates" for common patterns</p>
            </div>
          ) : (
            <div className="rules-list">
              {rulesOfCurrentType.map((rule, index) => (
                <RuleCard
                  key={rule.id}
                  rule={rule}
                  index={index}
                  updateRule={updateRule}
                  deleteRule={deleteRule}
                  duplicateRule={duplicateRule}
                  addCondition={addCondition}
                  updateCondition={updateCondition}
                  deleteCondition={deleteCondition}
                  addAction={addAction}
                  updateAction={updateAction}
                  deleteAction={deleteAction}
                  toggleWafFlag={toggleWafFlag}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'output' && (
        <div className="output-content card">
          <div className="card-header">
            <h3 className="card-title">cdn.yaml</h3>
            {generatedYaml && (
              <div className="output-actions">
                <button className="btn btn-secondary btn-sm" onClick={copyToClipboard}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                  Copy
                </button>
                <button className="btn btn-primary btn-sm" onClick={downloadYaml}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                  </svg>
                  Download
                </button>
              </div>
            )}
          </div>
          {generatedYaml ? (
            <>
              <div className="deployment-note">
                <strong>📋 Deployment Steps:</strong>
                <ol>
                  <li>Save as <code>cdn.yaml</code> in your <code>config</code> folder</li>
                  <li>Deploy via Cloud Manager config pipeline</li>
                  <li>Monitor CDN logs for rule matches</li>
                </ol>
              </div>
              <pre className="code-block yaml-output">{generatedYaml}</pre>
            </>
          ) : (
            <div className="empty-state">
              <h3>No YAML Generated Yet</h3>
              <p>Create rules and click "Generate YAML"</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Rule Card Component
const RuleCard = ({
  rule, index, updateRule, deleteRule, duplicateRule,
  addCondition, updateCondition, deleteCondition,
  addAction, updateAction, deleteAction, toggleWafFlag
}) => {
  const [expanded, setExpanded] = useState(rule.expanded);

  return (
    <div className="rule-builder-card card">
      <div className="rule-builder-header" onClick={() => setExpanded(!expanded)}>
        <div className="rule-builder-title">
          <span className="rule-number">#{index + 1}</span>
          <input
            type="text"
            className="rule-name-input"
            value={rule.name}
            onChange={(e) => updateRule(rule.id, { name: e.target.value.replace(/[^a-zA-Z0-9-_]/g, '') })}
            onClick={(e) => e.stopPropagation()}
            placeholder="rule-name"
            maxLength={64}
          />
          <span className={`badge badge-${rule.type}`}>{rule.type}</span>
        </div>
        <div className="rule-builder-actions">
          <button className="btn btn-ghost btn-icon" onClick={(e) => { e.stopPropagation(); duplicateRule(rule.id); }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
            </svg>
          </button>
          <button className="btn btn-ghost btn-icon delete" onClick={(e) => { e.stopPropagation(); deleteRule(rule.id); }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="3 6 5 6 21 6" />
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
            </svg>
          </button>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}>
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </div>
      </div>

      {expanded && (
        <div className="rule-builder-body animate-slide-up">
          {/* Conditions Section - Common to all rule types */}
          <div className="rule-section">
            <div className="section-header">
              <h4>When Conditions</h4>
              <select
                className="form-select-inline"
                value={rule.conditionLogic}
                onChange={(e) => updateRule(rule.id, { conditionLogic: e.target.value })}
              >
                <option value="allOf">ALL match (AND)</option>
                <option value="anyOf">ANY match (OR)</option>
              </select>
            </div>
            
            {rule.conditions?.map((condition, idx) => (
              <div key={condition.id} className="condition-row">
                <select
                  className="form-select"
                  value={condition.propertyType}
                  onChange={(e) => updateCondition(rule.id, condition.id, { propertyType: e.target.value })}
                >
                  <option value="reqProperty">Request Property</option>
                  <option value="reqHeader">Request Header</option>
                  <option value="queryParam">Query Parameter</option>
                  <option value="reqCookie">Cookie</option>
                </select>
                
                {condition.propertyType === 'reqProperty' ? (
                  <select
                    className="form-select"
                    value={condition.property}
                    onChange={(e) => updateCondition(rule.id, condition.id, { property: e.target.value })}
                  >
                    {Object.entries(REQUEST_PROPERTIES).map(([key, prop]) => (
                      <option key={key} value={key}>{prop.name} - {prop.description}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    className="form-input"
                    value={condition.property}
                    onChange={(e) => updateCondition(rule.id, condition.id, { property: e.target.value })}
                    placeholder={condition.propertyType === 'reqHeader' ? 'Header-Name' : 'param-name'}
                  />
                )}
                
                <select
                  className="form-select"
                  value={condition.operator}
                  onChange={(e) => updateCondition(rule.id, condition.id, { operator: e.target.value })}
                >
                  {Object.entries(CONDITION_OPERATORS).map(([key, op]) => (
                    <option key={key} value={key}>{op.name}</option>
                  ))}
                </select>
                
                {condition.operator !== 'exists' && (
                  <input
                    type="text"
                    className="form-input"
                    value={condition.value}
                    onChange={(e) => updateCondition(rule.id, condition.id, { value: e.target.value })}
                    placeholder={condition.operator === 'in' ? 'value1, value2' : 'value'}
                  />
                )}
                
                {rule.conditions.length > 1 && (
                  <button className="btn btn-ghost btn-icon delete" onClick={() => deleteCondition(rule.id, condition.id)}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <line x1="18" y1="6" x2="6" y2="18" />
                      <line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                  </button>
                )}
              </div>
            ))}
            
            <button className="btn btn-ghost btn-sm" onClick={() => addCondition(rule.id)}>
              + Add Condition
            </button>
          </div>

          {/* Type-specific sections */}
          {rule.type === 'trafficFilter' && (
            <TrafficFilterSection
              rule={rule}
              updateRule={updateRule}
              toggleWafFlag={toggleWafFlag}
            />
          )}

          {(rule.type === 'requestTransformations' || rule.type === 'responseTransformations') && (
            <TransformSection
              rule={rule}
              updateRule={updateRule}
              addAction={addAction}
              updateAction={updateAction}
              deleteAction={deleteAction}
            />
          )}

          {rule.type === 'redirects' && (
            <RedirectSection rule={rule} updateRule={updateRule} />
          )}

          {rule.type === 'originSelectors' && (
            <OriginSection rule={rule} updateRule={updateRule} />
          )}
        </div>
      )}
    </div>
  );
};

// Traffic Filter Section
const TrafficFilterSection = ({ rule, updateRule, toggleWafFlag }) => (
  <>
    <div className="rule-section">
      <h4>Action</h4>
      <div className="form-row">
        <div className="form-group">
          <label className="form-label">Action Type</label>
          <select
            className="form-select"
            value={rule.action}
            onChange={(e) => updateRule(rule.id, { action: e.target.value })}
          >
            {ACTION_TYPES.map(a => (
              <option key={a.value} value={a.value}>{a.label} - {a.description}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-checkbox">
            <input
              type="checkbox"
              checked={rule.alert}
              onChange={(e) => updateRule(rule.id, { alert: e.target.checked })}
            />
            <span>🔔 Alert Notifications</span>
          </label>
        </div>
      </div>
    </div>

    <div className="rule-section">
      <h4>WAF Protections <span className="license-badge">Extended Security</span></h4>
      <div className="waf-quick-actions">
        <button className="btn btn-ghost btn-sm" onClick={() => updateRule(rule.id, { wafFlags: ['ATTACK-FROM-BAD-IP', 'ATTACK'] })}>
          ⭐ Adobe Recommended
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => updateRule(rule.id, { wafFlags: Object.keys(WAF_FLAGS).filter(k => WAF_FLAGS[k].severity === 'critical') })}>
          Critical Only
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => updateRule(rule.id, { wafFlags: Object.keys(WAF_FLAGS) })}>
          All Flags
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => updateRule(rule.id, { wafFlags: [] })}>
          Clear
        </button>
      </div>
      <div className="waf-flags-compact">
        {Object.entries(WAF_FLAGS).map(([key, flag]) => (
          <label key={key} className={`waf-chip ${rule.wafFlags?.includes(key) ? 'selected' : ''}`}>
            <input
              type="checkbox"
              checked={rule.wafFlags?.includes(key)}
              onChange={() => toggleWafFlag(rule.id, key)}
            />
            <span style={{ background: SEVERITY_COLORS[flag.severity].bg, color: SEVERITY_COLORS[flag.severity].color }}>
              {key}
            </span>
          </label>
        ))}
      </div>
    </div>

    <div className="rule-section">
      <h4>Rate Limiting</h4>
      <div className="form-row four-col">
        <div className="form-group">
          <label className="form-label">Limit</label>
          <input
            type="number"
            className="form-input"
            placeholder="100"
            value={rule.rateLimit?.limit || ''}
            onChange={(e) => updateRule(rule.id, { rateLimit: { ...rule.rateLimit, limit: parseInt(e.target.value) || null } })}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Window (sec)</label>
          <input
            type="number"
            className="form-input"
            placeholder="10"
            value={rule.rateLimit?.window || ''}
            onChange={(e) => updateRule(rule.id, { rateLimit: { ...rule.rateLimit, window: parseInt(e.target.value) || null } })}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Count</label>
          <select
            className="form-select"
            value={rule.rateLimit?.count || 'all'}
            onChange={(e) => updateRule(rule.id, { rateLimit: { ...rule.rateLimit, count: e.target.value } })}
          >
            {RATE_LIMIT_COUNT_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Penalty (sec)</label>
          <input
            type="number"
            className="form-input"
            placeholder="300"
            value={rule.rateLimit?.penalty || ''}
            onChange={(e) => updateRule(rule.id, { rateLimit: { ...rule.rateLimit, penalty: parseInt(e.target.value) || null } })}
          />
        </div>
      </div>
    </div>

    <div className="rule-section">
      <h4>Geo-Blocking</h4>
      <label className="form-checkbox">
        <input
          type="checkbox"
          checked={rule.geoBlock?.enabled}
          onChange={(e) => updateRule(rule.id, { geoBlock: { ...rule.geoBlock, enabled: e.target.checked } })}
        />
        <span>Enable Country Blocking</span>
      </label>
      {rule.geoBlock?.enabled && (
        <div className="geo-section">
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => updateRule(rule.id, { geoBlock: { ...rule.geoBlock, countries: OFAC_COUNTRIES.map(c => c.code) } })}
          >
            Add OFAC Countries
          </button>
          <div className="country-tags">
            {rule.geoBlock?.countries?.map(code => (
              <span key={code} className="country-tag">
                {code}
                <button onClick={() => updateRule(rule.id, {
                  geoBlock: { ...rule.geoBlock, countries: rule.geoBlock.countries.filter(c => c !== code) }
                })}>×</button>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  </>
);

// Transform Section
const TransformSection = ({ rule, updateRule, addAction, updateAction, deleteAction }) => (
  <div className="rule-section">
    <h4>{rule.type === 'requestTransformations' ? 'Request' : 'Response'} Actions</h4>
    
    {rule.type === 'responseTransformations' && (
      <div className="security-headers-quick">
        <span>Quick Add:</span>
        {Object.entries(SECURITY_HEADERS_PRESETS).map(([key, preset]) => (
          <button
            key={key}
            className="btn btn-ghost btn-xs"
            onClick={() => {
              const newAction = { id: Date.now(), type: 'set', target: 'respHeader', key: preset.header, value: preset.value };
              updateRule(rule.id, { actions: [...(rule.actions || []), newAction] });
            }}
          >
            {preset.name}
          </button>
        ))}
      </div>
    )}
    
    {rule.actions?.map((action, idx) => (
      <div key={action.id} className="action-row">
        <select
          className="form-select"
          value={action.type}
          onChange={(e) => updateAction(rule.id, action.id, { type: e.target.value })}
        >
          <option value="set">Set</option>
          <option value="unset">Unset</option>
          <option value="transform">Transform</option>
        </select>
        
        <select
          className="form-select"
          value={action.target}
          onChange={(e) => updateAction(rule.id, action.id, { target: e.target.value })}
        >
          {rule.type === 'requestTransformations' ? (
            <>
              <option value="reqHeader">Request Header</option>
              <option value="reqProperty">Request Property</option>
              <option value="queryParam">Query Parameter</option>
              <option value="var">Variable</option>
            </>
          ) : (
            <>
              <option value="respHeader">Response Header</option>
              <option value="respProperty">Response Property</option>
              <option value="var">Variable</option>
            </>
          )}
        </select>
        
        <input
          type="text"
          className="form-input"
          value={action.key}
          onChange={(e) => updateAction(rule.id, action.id, { key: e.target.value })}
          placeholder="Header-Name or property"
        />
        
        {action.type === 'set' && (
          <input
            type="text"
            className="form-input"
            value={action.value || ''}
            onChange={(e) => updateAction(rule.id, action.id, { value: e.target.value })}
            placeholder="value"
          />
        )}
        
        {action.type === 'transform' && (
          <>
            <select
              className="form-select form-select-sm"
              value={action.op || 'replace'}
              onChange={(e) => updateAction(rule.id, action.id, { op: e.target.value })}
            >
              <option value="replace">Replace</option>
              <option value="tolower">To Lower</option>
            </select>
            {action.op !== 'tolower' && (
              <>
                <input
                  type="text"
                  className="form-input"
                  value={action.match || ''}
                  onChange={(e) => updateAction(rule.id, action.id, { match: e.target.value })}
                  placeholder="regex pattern"
                />
                <input
                  type="text"
                  className="form-input"
                  value={action.replacement || ''}
                  onChange={(e) => updateAction(rule.id, action.id, { replacement: e.target.value })}
                  placeholder="replacement"
                />
              </>
            )}
          </>
        )}
        
        {rule.actions.length > 1 && (
          <button className="btn btn-ghost btn-icon delete" onClick={() => deleteAction(rule.id, action.id)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        )}
      </div>
    ))}
    
    <button className="btn btn-ghost btn-sm" onClick={() => addAction(rule.id)}>
      + Add Action
    </button>
  </div>
);

// Redirect Section
const RedirectSection = ({ rule, updateRule }) => (
  <div className="rule-section">
    <h4>Redirect Configuration</h4>
    <div className="form-row">
      <div className="form-group">
        <label className="form-label">Status Code</label>
        <select
          className="form-select"
          value={rule.status}
          onChange={(e) => updateRule(rule.id, { status: parseInt(e.target.value) })}
        >
          {REDIRECT_STATUS_CODES.map(s => (
            <option key={s.code} value={s.code}>{s.code} - {s.name}</option>
          ))}
        </select>
      </div>
      <div className="form-group" style={{ flex: 2 }}>
        <label className="form-label">Location (URL)</label>
        <input
          type="text"
          className="form-input"
          value={rule.location}
          onChange={(e) => updateRule(rule.id, { location: e.target.value })}
          placeholder="https://example.com/new-path or /relative-path"
        />
      </div>
    </div>
    <p className="form-hint">
      💡 Use <code>{'{reqProperty: path}'}</code> to reference request properties in location
    </p>
  </div>
);

// Origin Section
const OriginSection = ({ rule, updateRule }) => (
  <div className="rule-section">
    <h4>Origin Configuration</h4>
    <div className="form-row">
      <div className="form-group">
        <label className="form-label">Origin Type</label>
        <select
          className="form-select"
          value={rule.originType}
          onChange={(e) => updateRule(rule.id, { originType: e.target.value })}
        >
          <option value="custom">Custom Backend</option>
          <option value="aem">AEM Origin (static)</option>
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Origin Name</label>
        <input
          type="text"
          className="form-input"
          value={rule.originName}
          onChange={(e) => updateRule(rule.id, { originName: e.target.value })}
          placeholder={rule.originType === 'aem' ? 'static' : 'my-backend'}
        />
      </div>
    </div>
    
    {rule.originType === 'custom' && (
      <>
        <div className="form-row">
          <div className="form-group" style={{ flex: 2 }}>
            <label className="form-label">Backend Domain</label>
            <input
              type="text"
              className="form-input"
              value={rule.originDomain || ''}
              onChange={(e) => updateRule(rule.id, { originDomain: e.target.value })}
              placeholder="api.example.com"
            />
          </div>
          <div className="form-group">
            <label className="form-label">Timeout (sec)</label>
            <input
              type="number"
              className="form-input"
              value={rule.timeout || 60}
              onChange={(e) => updateRule(rule.id, { timeout: parseInt(e.target.value) })}
            />
          </div>
        </div>
        
        <div className="form-row">
          <label className="form-checkbox">
            <input
              type="checkbox"
              checked={rule.forwardHost}
              onChange={(e) => updateRule(rule.id, { forwardHost: e.target.checked })}
            />
            <span>Forward Host Header</span>
          </label>
          <label className="form-checkbox">
            <input
              type="checkbox"
              checked={rule.forwardCookie}
              onChange={(e) => updateRule(rule.id, { forwardCookie: e.target.checked })}
            />
            <span>Forward Cookies</span>
          </label>
          <label className="form-checkbox">
            <input
              type="checkbox"
              checked={rule.forwardAuthorization}
              onChange={(e) => updateRule(rule.id, { forwardAuthorization: e.target.checked })}
            />
            <span>Forward Authorization</span>
          </label>
        </div>
      </>
    )}
    
    <label className="form-checkbox">
      <input
        type="checkbox"
        checked={rule.skipCache}
        onChange={(e) => updateRule(rule.id, { skipCache: e.target.checked })}
      />
      <span>Skip CDN Cache</span>
    </label>
  </div>
);

export default RulesGenerator;
