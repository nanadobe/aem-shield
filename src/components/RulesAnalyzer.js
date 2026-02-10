import React, { useState } from 'react';
import yaml from 'js-yaml';
import { WAF_FLAGS, SEVERITY_COLORS, SAMPLE_CDN_YAML, RULES_SYNTAX, EXAMPLE_RULES, OFAC_COUNTRIES, REQUEST_PROPERTIES, MATCH_OPERATORS } from '../data/wafData';
import './RulesAnalyzer.css';

// =====================================================
// COMPREHENSIVE VALID VALUES FROM ADOBE DOCUMENTATION
// Reference: https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/content-delivery/cdn-configuring-traffic
// =====================================================
const VALID_VALUES = {
  // Traffic Filter Actions (trafficFilters.rules)
  trafficFilterActions: ['allow', 'block', 'log'],
  
  // Traffic Filter Action Types with wafFlags or rateLimit
  trafficFilterActionTypes: ['block', 'log', 'allow'],
  
  // Request Transformation Actions (requestTransformations.rules.actions)
  requestTransformActions: ['set', 'unset', 'transform'],
  
  // Response Transformation Actions (responseTransformations.rules.actions)
  responseTransformActions: ['set', 'unset'],
  
  // Redirect Action Types (redirects.rules.action)
  redirectActionTypes: ['redirect'],
  
  // Origin Selector Action Types (originSelectors.rules.action)
  originSelectorActionTypes: ['selectOrigin', 'selectAemOrigin'],
  
  // Authentication Action (special traffic filter)
  authenticationActions: ['authenticate'],
  
  // ALL valid action values combined (for loose validation)
  allActionTypes: [
    'allow', 'block', 'log',           // Traffic filters
    'set', 'unset', 'transform',        // Transformations
    'redirect',                          // Redirects
    'selectOrigin', 'selectAemOrigin', // Origin selectors
    'authenticate'                       // Edge authentication
  ],
  
  // Transform operations
  transformOperations: ['replace', 'tolower', 'toupper'],
  
  // Operators for conditions
  operators: [
    'equals', 'notEquals', 
    'like', 'notLike', 
    'matches', 'doesNotMatch',
    'in', 'notIn', 
    'exists', 'doesNotExist'
  ],
  
  // Request Properties (reqProperty)
  requestProperties: [
    'path', 'url', 'queryString', 'method', 'tier', 'domain',
    'clientIp', 'clientCountry', 'clientAsn', 'clientRegion',
    'userAgent', 'referer', 'protocol',
    // CIDR notation variants
    'clientIp/8', 'clientIp/16', 'clientIp/24'
  ],
  
  // Valid for reqHeader, respHeader
  headerTargets: ['reqHeader', 'respHeader'],
  
  // Valid for cookies
  cookieTargets: ['reqCookie', 'respCookie'],
  
  // Valid for query params
  queryTargets: ['queryParam', 'queryParamValue', 'queryParamMatch', 'queryParamDoesNotMatch'],
  
  // Valid for response properties
  responseProperties: ['respProperty', 'respHeader', 'respCookie'],
  
  // Variables and logging
  specialTargets: ['var', 'logProperty'],
  
  // AEM tiers
  tiers: ['author', 'publish'],
  
  // HTTP methods
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'],
  
  // Rate limit count types
  rateCountTypes: ['all', 'fetches', 'errors'],
  
  // Rate limit groupBy properties
  rateLimitGroupByProps: ['clientIp', 'clientIp/8', 'clientIp/16', 'clientIp/24', 'clientCountry', 'clientAsn', 'path', 'domain'],
  
  // WAF flags (from wafData)
  wafFlags: Object.keys(WAF_FLAGS),
  
  // CDN config kind
  kindTypes: ['CDN'],
  
  // Redirect status codes
  redirectStatuses: [301, 302, 303, 307, 308],
  
  // Origin properties
  originProperties: ['domain', 'timeout', 'forwardHost', 'forwardAuthorization', 'headers'],
  
  // AEM Origin names
  aemOriginNames: ['static', 'aem'],
  
  // Configuration sections in data
  configSections: [
    'trafficFilters', 
    'requestTransformations', 
    'responseTransformations', 
    'redirects', 
    'originSelectors',
    'origins'
  ],
  
  // Special boolean properties
  booleanProperties: [
    'removeMarketingParams',
    'forwardHost', 
    'forwardAuthorization',
    'exists'
  ]
};

const RulesAnalyzer = () => {
  const [yamlInput, setYamlInput] = useState('');
  const [analyzedRules, setAnalyzedRules] = useState([]);
  const [showWafReference, setShowWafReference] = useState(false);
  const [showSyntaxReference, setShowSyntaxReference] = useState(false);
  const [showExamples, setShowExamples] = useState(false);
  const [parseError, setParseError] = useState(null);
  const [analysisStats, setAnalysisStats] = useState(null);
  const [validationResults, setValidationResults] = useState(null);
  const [activeTab, setActiveTab] = useState('analysis'); // 'analysis', 'validation', or 'format'
  const [formatMessage, setFormatMessage] = useState(null);

  // =====================================================
  // YAML FORMATTER FUNCTIONS
  // =====================================================
  
  const formatYaml = () => {
    try {
      setFormatMessage(null);
      
      if (!yamlInput.trim()) {
        setFormatMessage({ type: 'error', text: 'No YAML content to format' });
        return;
      }
      
      // Parse the YAML
      const parsed = yaml.load(yamlInput);
      
      // Re-serialize with proper formatting
      const formatted = yaml.dump(parsed, {
        indent: 2,
        lineWidth: 120,
        noRefs: true,
        sortKeys: false,
        quotingType: '"',
        forceQuotes: false
      });
      
      setYamlInput(formatted);
      setFormatMessage({ type: 'success', text: 'YAML formatted successfully!' });
      
    } catch (error) {
      setFormatMessage({ 
        type: 'error', 
        text: `Format failed: ${error.message}`,
        details: error.mark ? `Error at line ${error.mark.line + 1}, column ${error.mark.column + 1}` : null
      });
    }
  };

  const minifyYaml = () => {
    try {
      setFormatMessage(null);
      
      if (!yamlInput.trim()) {
        setFormatMessage({ type: 'error', text: 'No YAML content to minify' });
        return;
      }
      
      // Parse the YAML
      const parsed = yaml.load(yamlInput);
      
      // Re-serialize with minimal formatting
      const minified = yaml.dump(parsed, {
        indent: 2,
        lineWidth: -1,
        flowLevel: 2,
        noRefs: true
      });
      
      setYamlInput(minified);
      setFormatMessage({ type: 'success', text: 'YAML minified successfully!' });
      
    } catch (error) {
      setFormatMessage({ 
        type: 'error', 
        text: `Minify failed: ${error.message}` 
      });
    }
  };

  const sortRules = () => {
    try {
      setFormatMessage(null);
      
      const parsed = yaml.load(yamlInput);
      
      // Sort rules alphabetically by name within each section
      if (parsed?.data?.trafficFilters?.rules) {
        parsed.data.trafficFilters.rules.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      }
      if (parsed?.data?.requestTransformations?.rules) {
        parsed.data.requestTransformations.rules.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      }
      if (parsed?.data?.responseTransformations?.rules) {
        parsed.data.responseTransformations.rules.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      }
      if (parsed?.data?.redirects?.rules) {
        parsed.data.redirects.rules.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      }
      if (parsed?.data?.originSelectors?.rules) {
        parsed.data.originSelectors.rules.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      }
      
      const formatted = yaml.dump(parsed, { indent: 2, lineWidth: 120 });
      setYamlInput(formatted);
      setFormatMessage({ type: 'success', text: 'Rules sorted alphabetically by name!' });
      
    } catch (error) {
      setFormatMessage({ type: 'error', text: `Sort failed: ${error.message}` });
    }
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(yamlInput);
      setFormatMessage({ type: 'success', text: 'Copied to clipboard!' });
    } catch (error) {
      setFormatMessage({ type: 'error', text: 'Failed to copy to clipboard' });
    }
  };

  // Detect current configuration context
  const detectConfigContext = (yaml, lineNum) => {
    const lines = yaml.split('\n').slice(0, lineNum);
    let context = 'unknown';
    let inActionsArray = false;
    
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i].trim();
      
      // Check if we're inside an actions: array (transformations use plural)
      if (line === 'actions:' || line.startsWith('actions:')) {
        inActionsArray = true;
      }
      
      // Detect main configuration section
      if (line.startsWith('trafficFilters:')) {
        context = 'trafficFilters';
        break;
      } else if (line.startsWith('requestTransformations:')) {
        context = 'requestTransformations';
        break;
      } else if (line.startsWith('responseTransformations:')) {
        context = 'responseTransformations';
        break;
      } else if (line.startsWith('redirects:')) {
        context = 'redirects';
        break;
      } else if (line.startsWith('originSelectors:')) {
        context = 'originSelectors';
        break;
      } else if (line.startsWith('origins:')) {
        context = 'origins';
        break;
      }
    }
    
    // If we detected we're in an actions array but context is trafficFilters,
    // it might actually be a transformation - but trafficFilters can also have nested action
    return context;
  };

  // Get valid action types based on context
  const getValidActionsForContext = (context) => {
    switch (context) {
      case 'trafficFilters':
        return [...VALID_VALUES.trafficFilterActions, ...VALID_VALUES.authenticationActions];
      case 'requestTransformations':
        return VALID_VALUES.requestTransformActions;
      case 'responseTransformations':
        return VALID_VALUES.responseTransformActions;
      case 'redirects':
        return VALID_VALUES.redirectActionTypes;
      case 'originSelectors':
        return VALID_VALUES.originSelectorActionTypes;
      default:
        return VALID_VALUES.allActionTypes;
    }
  };

  // =====================================================
  // SYNTAX VALIDATION FUNCTIONS
  // =====================================================
  
  const validateYamlSyntax = (yaml) => {
    const errors = [];
    const warnings = [];
    const suggestions = [];
    const lines = yaml.split('\n');
    
    // Track state for context-aware validation
    let currentIndent = 0;
    let expectedIndent = 0;
    let inRules = false;
    let inRule = false;
    let currentRuleName = null;
    let currentRuleStartLine = 0;
    let hasWhen = false;
    let hasAction = false;
    let hasName = false;
    let bracketStack = [];
    let inMultilineString = false;
    
    // Basic YAML structure checks
    const basicChecks = validateBasicStructure(yaml, lines);
    errors.push(...basicChecks.errors);
    warnings.push(...basicChecks.warnings);
    
    // Line-by-line validation
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      const trimmed = line.trim();
      
      // Skip empty lines and comments
      if (trimmed === '' || trimmed.startsWith('#')) continue;
      
      // Check for tabs (YAML should use spaces)
      if (line.includes('\t')) {
        errors.push({
          line: lineNum,
          type: 'syntax',
          severity: 'error',
          message: 'YAML uses spaces for indentation, not tabs',
          suggestion: 'Replace tabs with spaces (typically 2 spaces per indent level)'
        });
      }
      
      // Check bracket/brace matching
      const bracketResult = checkBrackets(trimmed, bracketStack, lineNum);
      if (bracketResult.error) {
        errors.push(bracketResult.error);
      }
      bracketStack = bracketResult.stack;
      
      // Check for common YAML syntax errors
      const yamlErrors = checkYamlSyntax(line, trimmed, lineNum, lines, i);
      errors.push(...yamlErrors);
      
      // CDN config specific validation
      if (trimmed.startsWith('kind:')) {
        const kindValue = trimmed.replace('kind:', '').trim().replace(/['"]/g, '');
        if (!VALID_VALUES.kindTypes.includes(kindValue)) {
          errors.push({
            line: lineNum,
            type: 'value',
            severity: 'error',
            message: `Invalid kind: "${kindValue}". Must be "CDN"`,
            suggestion: 'Use kind: "CDN"'
          });
        }
      }
      
      // Rules section detection
      if (trimmed === 'rules:' || trimmed.includes('rules:')) {
        inRules = true;
      }
      
      // Rule start detection
      if (inRules && trimmed.startsWith('- name:')) {
        // Validate previous rule completeness
        if (inRule && currentRuleName) {
          const ruleValidation = validateRuleCompleteness(hasName, hasWhen, hasAction, currentRuleName, currentRuleStartLine);
          errors.push(...ruleValidation.errors);
          warnings.push(...ruleValidation.warnings);
        }
        
        // Start new rule
        inRule = true;
        currentRuleName = trimmed.replace('- name:', '').trim().replace(/['"]/g, '');
        currentRuleStartLine = lineNum;
        hasWhen = false;
        hasAction = false;
        hasName = true;
        
        // Validate rule name
        const nameValidation = validateRuleName(currentRuleName, lineNum);
        errors.push(...nameValidation.errors);
        warnings.push(...nameValidation.warnings);
      }
      
      // Track 'when' presence
      if (inRule && trimmed === 'when:') {
        hasWhen = true;
      }
      
      // Track 'action' or 'actions' presence (singular for trafficFilters, plural for transformations)
      if (inRule && (trimmed.startsWith('action:') || trimmed === 'action:' || 
                     trimmed.startsWith('actions:') || trimmed === 'actions:')) {
        hasAction = true;
        
        // Validate action value if inline - CONTEXT AWARE
        if (trimmed.includes(':') && trimmed !== 'action:') {
          const actionValue = trimmed.replace('action:', '').trim().replace(/['"]/g, '');
          const context = detectConfigContext(yaml, lineNum);
          const validActions = getValidActionsForContext(context);
          
          // Only validate simple action values, not object actions
          if (actionValue && !actionValue.includes('{') && !validActions.includes(actionValue)) {
            // Check if it's ANY valid action type (for loose validation)
            if (!VALID_VALUES.allActionTypes.includes(actionValue)) {
              errors.push({
                line: lineNum,
                type: 'value',
                severity: 'error',
                message: `Invalid action: "${actionValue}"`,
                suggestion: `Valid actions for ${context || 'this context'} are: ${validActions.join(', ')}`
              });
            }
          }
        }
      }
      
      // Validate action type property (type: block, type: set, type: redirect, etc.)
      if (trimmed.startsWith('type:') && inRule) {
        const typeValue = trimmed.replace('type:', '').trim().replace(/['"]/g, '');
        const context = detectConfigContext(yaml, lineNum);
        const validActions = getValidActionsForContext(context);
        
        // Check against context-specific valid action types first
        if (typeValue && !validActions.includes(typeValue)) {
          // If not valid for context, check if it's valid for ANY context (might be misdetected context)
          if (!VALID_VALUES.allActionTypes.includes(typeValue)) {
            errors.push({
              line: lineNum,
              type: 'value',
              severity: 'error',
              message: `Invalid action type: "${typeValue}"`,
              suggestion: `Valid types for ${context || 'CDN config'}: ${validActions.join(', ')}`
            });
          }
          // Don't warn if it's valid in another context - context detection might be imperfect
        }
      }
      
      // Validate reqProperty values
      if (trimmed.includes('reqProperty:')) {
        const propMatch = trimmed.match(/reqProperty:\s*['"]?(\w+(?:\/\d+)?)['"]?/);
        if (propMatch) {
          const propValue = propMatch[1];
          if (!VALID_VALUES.requestProperties.includes(propValue)) {
            warnings.push({
              line: lineNum,
              type: 'value',
              severity: 'warning',
              message: `Unknown request property: "${propValue}"`,
              suggestion: `Common properties: ${VALID_VALUES.requestProperties.slice(0, 8).join(', ')}`
            });
          }
        }
      }
      
      // Validate operators
      VALID_VALUES.operators.forEach(op => {
        if (trimmed.startsWith(op + ':')) {
          // Valid operator found - no action needed
        }
      });
      
      // Validate tier values - supports both equals: and in: syntax
      if (trimmed.includes('tier') && trimmed.includes('equals:')) {
        const tierMatch = trimmed.match(/equals:\s*['"]?(\w+)['"]?/);
        if (tierMatch && !VALID_VALUES.tiers.includes(tierMatch[1])) {
          errors.push({
            line: lineNum,
            type: 'value',
            severity: 'error',
            message: `Invalid tier value: "${tierMatch[1]}"`,
            suggestion: `Valid tiers are: ${VALID_VALUES.tiers.join(', ')}`
          });
        }
      }
      // Skip validation for tier with in: [] - array values are harder to validate inline
      
      // Validate WAF flags
      if (trimmed === 'wafFlags:' || trimmed.includes('wafFlags:')) {
        // Check if WAF flags section exists - subsequent lines should contain valid flags
      }
      if (inRule && trimmed.startsWith('- ') && !trimmed.includes(':')) {
        const flagValue = trimmed.replace('- ', '').trim().replace(/['"]/g, '');
        // Check if this looks like a WAF flag (all caps with possible hyphens)
        if (flagValue.match(/^[A-Z][A-Z0-9-]*$/)) {
          if (!VALID_VALUES.wafFlags.includes(flagValue)) {
            warnings.push({
              line: lineNum,
              type: 'value',
              severity: 'warning',
              message: `Unknown WAF flag: "${flagValue}"`,
              suggestion: `Valid WAF flags include: SQLI, XSS, CMDEXE, TRAVERSAL, ATTACK, etc.`
            });
          }
        }
      }
      
      // Validate rate limit values
      if (trimmed.match(/window:\s*(\d+)/)) {
        const windowValue = parseInt(trimmed.match(/window:\s*(\d+)/)[1]);
        if (windowValue < 1 || windowValue > 120) {
          errors.push({
            line: lineNum,
            type: 'value',
            severity: 'error',
            message: `Rate limit window must be between 1 and 120 seconds, got: ${windowValue}`,
            suggestion: 'Use a value between 1 and 120'
          });
        }
      }
      
      if (trimmed.match(/limit:\s*(\d+)/)) {
        const limitValue = parseInt(trimmed.match(/limit:\s*(\d+)/)[1]);
        if (limitValue < 1) {
          errors.push({
            line: lineNum,
            type: 'value',
            severity: 'error',
            message: `Rate limit must be a positive number, got: ${limitValue}`,
            suggestion: 'Use a positive integer'
          });
        }
      }
      
      if (trimmed.match(/count:\s*(\w+)/)) {
        const countValue = trimmed.match(/count:\s*(\w+)/)[1];
        if (!VALID_VALUES.rateCountTypes.includes(countValue)) {
          errors.push({
            line: lineNum,
            type: 'value',
            severity: 'error',
            message: `Invalid rate limit count type: "${countValue}"`,
            suggestion: `Valid count types are: ${VALID_VALUES.rateCountTypes.join(', ')}`
          });
        }
      }
      
      // Validate redirect status codes
      if (trimmed.match(/status:\s*(\d+)/)) {
        const statusValue = parseInt(trimmed.match(/status:\s*(\d+)/)[1]);
        // Check if in redirects context
        if (yaml.includes('redirects:') && !VALID_VALUES.redirectStatuses.includes(statusValue)) {
          warnings.push({
            line: lineNum,
            type: 'value',
            severity: 'warning',
            message: `Unusual redirect status code: ${statusValue}`,
            suggestion: `Standard redirect codes are: ${VALID_VALUES.redirectStatuses.join(', ')}`
          });
        }
      }
    }
    
    // Validate last rule completeness
    if (inRule && currentRuleName) {
      const ruleValidation = validateRuleCompleteness(hasName, hasWhen, hasAction, currentRuleName, currentRuleStartLine);
      errors.push(...ruleValidation.errors);
      warnings.push(...ruleValidation.warnings);
    }
    
    // Check unclosed brackets
    if (bracketStack.length > 0) {
      errors.push({
        line: bracketStack[bracketStack.length - 1].line,
        type: 'syntax',
        severity: 'error',
        message: `Unclosed ${bracketStack[bracketStack.length - 1].char}`,
        suggestion: 'Add matching closing bracket/brace'
      });
    }
    
    // Add best practice suggestions
    suggestions.push(...generateSuggestions(yaml, analyzedRules));
    
    return {
      isValid: errors.filter(e => e.severity === 'error').length === 0,
      errors: errors.sort((a, b) => a.line - b.line),
      warnings: warnings.sort((a, b) => a.line - b.line),
      suggestions,
      stats: {
        totalErrors: errors.filter(e => e.severity === 'error').length,
        totalWarnings: warnings.length,
        totalSuggestions: suggestions.length
      }
    };
  };

  const validateBasicStructure = (yaml, lines) => {
    const errors = [];
    const warnings = [];
    
    // Check for required top-level keys
    if (!yaml.includes('kind:')) {
      errors.push({
        line: 1,
        type: 'structure',
        severity: 'error',
        message: 'Missing required "kind" field',
        suggestion: 'Add kind: "CDN" at the top of your configuration'
      });
    }
    
    if (!yaml.includes('version:')) {
      warnings.push({
        line: 1,
        type: 'structure',
        severity: 'warning',
        message: 'Missing "version" field',
        suggestion: 'Add version: "1" for clarity'
      });
    }
    
    if (!yaml.includes('data:')) {
      errors.push({
        line: 1,
        type: 'structure',
        severity: 'error',
        message: 'Missing required "data" section',
        suggestion: 'Add data: section containing your configuration'
      });
    }
    
    // Check for at least one configuration type
    const hasConfig = yaml.includes('trafficFilters:') || 
                      yaml.includes('requestTransformations:') ||
                      yaml.includes('responseTransformations:') ||
                      yaml.includes('redirects:') ||
                      yaml.includes('originSelectors:');
    
    if (yaml.includes('data:') && !hasConfig) {
      warnings.push({
        line: 1,
        type: 'structure',
        severity: 'warning',
        message: 'No configuration rules found in data section',
        suggestion: 'Add trafficFilters, requestTransformations, responseTransformations, redirects, or originSelectors'
      });
    }
    
    return { errors, warnings };
  };

  const checkBrackets = (line, stack, lineNum) => {
    const newStack = [...stack];
    const brackets = { '{': '}', '[': ']' };
    const closingBrackets = { '}': '{', ']': '[' };
    
    for (const char of line) {
      if (brackets[char]) {
        newStack.push({ char, line: lineNum });
      } else if (closingBrackets[char]) {
        if (newStack.length === 0) {
          return {
            stack: newStack,
            error: {
              line: lineNum,
              type: 'syntax',
              severity: 'error',
              message: `Unexpected closing ${char}`,
              suggestion: 'Remove extra closing bracket or add matching opening bracket'
            }
          };
        }
        const last = newStack.pop();
        if (last.char !== closingBrackets[char]) {
          return {
            stack: newStack,
            error: {
              line: lineNum,
              type: 'syntax',
              severity: 'error',
              message: `Mismatched brackets: expected ${brackets[last.char]} but found ${char}`,
              suggestion: 'Check bracket pairing'
            }
          };
        }
      }
    }
    return { stack: newStack, error: null };
  };

  const checkYamlSyntax = (line, trimmed, lineNum, lines, index) => {
    const errors = [];
    
    // Check for colon in key-value pairs
    if (trimmed.length > 0 && !trimmed.startsWith('-') && !trimmed.startsWith('#')) {
      // Check for missing colon in what looks like a key
      if (!trimmed.includes(':') && !trimmed.includes('{') && !trimmed.includes('[') &&
          !trimmed.startsWith('"') && !trimmed.startsWith("'") &&
          index > 0 && !lines[index - 1].trim().endsWith(':')) {
        // This might be a continuation or a value, check context
        const prevLine = lines[index - 1].trim();
        if (!prevLine.endsWith(':') && !prevLine.endsWith('|') && !prevLine.endsWith('>')) {
          // Could be an error, but need more context
        }
      }
    }
    
    // Check for duplicate colons
    if ((trimmed.match(/:/g) || []).length > 2 && !trimmed.includes('http')) {
      // Multiple colons might indicate formatting issue
    }
    
    // Check for improper string quoting
    if (trimmed.includes(': "') && !trimmed.endsWith('"') && !trimmed.includes('",')) {
      const quoteCount = (trimmed.match(/"/g) || []).length;
      if (quoteCount % 2 !== 0) {
        errors.push({
          line: lineNum,
          type: 'syntax',
          severity: 'error',
          message: 'Unclosed string quote',
          suggestion: 'Add closing double quote'
        });
      }
    }
    
    if (trimmed.includes(": '") && !trimmed.endsWith("'") && !trimmed.includes("',")) {
      const quoteCount = (trimmed.match(/'/g) || []).length;
      if (quoteCount % 2 !== 0) {
        errors.push({
          line: lineNum,
          type: 'syntax',
          severity: 'error',
          message: 'Unclosed string quote',
          suggestion: 'Add closing single quote'
        });
      }
    }
    
    // Check for special characters that need quoting
    if (trimmed.includes(': ') && !trimmed.includes('"') && !trimmed.includes("'")) {
      const value = trimmed.split(': ')[1];
      if (value && /[{}[\]&*!|>%@`]/.test(value)) {
        errors.push({
          line: lineNum,
          type: 'syntax',
          severity: 'warning',
          message: 'Value contains special characters that should be quoted',
          suggestion: 'Wrap the value in quotes: "value"'
        });
      }
    }
    
    return errors;
  };

  const validateRuleName = (name, lineNum) => {
    const errors = [];
    const warnings = [];
    
    // Check name format
    if (name.length === 0) {
      errors.push({
        line: lineNum,
        type: 'value',
        severity: 'error',
        message: 'Rule name cannot be empty',
        suggestion: 'Provide a descriptive name for the rule'
      });
    }
    
    if (name.length > 60) {
      warnings.push({
        line: lineNum,
        type: 'value',
        severity: 'warning',
        message: 'Rule name is quite long',
        suggestion: 'Consider using a shorter, more concise name'
      });
    }
    
    // Check for invalid characters
    if (/[^a-zA-Z0-9-_]/.test(name)) {
      warnings.push({
        line: lineNum,
        type: 'value',
        severity: 'warning',
        message: 'Rule name contains special characters',
        suggestion: 'Use only alphanumeric characters, hyphens, and underscores'
      });
    }
    
    return { errors, warnings };
  };

  const validateRuleCompleteness = (hasName, hasWhen, hasAction, ruleName, lineNum) => {
    const errors = [];
    const warnings = [];
    
    if (!hasWhen) {
      errors.push({
        line: lineNum,
        type: 'structure',
        severity: 'error',
        message: `Rule "${ruleName}" is missing required "when" condition`,
        suggestion: 'Add a "when:" section with conditions'
      });
    }
    
    if (!hasAction) {
      errors.push({
        line: lineNum,
        type: 'structure',
        severity: 'error',
        message: `Rule "${ruleName}" is missing required "action" or "actions"`,
        suggestion: 'For trafficFilters use "action:", for transformations use "actions:"'
      });
    }
    
    return { errors, warnings };
  };

  const generateSuggestions = (yaml, rules) => {
    const suggestions = [];
    
    // Check for security best practices
    if (yaml.includes('action: block') && !yaml.includes('action: log')) {
      suggestions.push({
        type: 'best-practice',
        severity: 'info',
        message: 'Consider adding LOG rules alongside BLOCK rules',
        suggestion: 'Start with LOG mode to validate rules before blocking to avoid false positives'
      });
    }
    
    if (!yaml.includes('ATTACK-FROM-BAD-IP') && yaml.includes('wafFlags')) {
      suggestions.push({
        type: 'best-practice',
        severity: 'info',
        message: 'Consider adding ATTACK-FROM-BAD-IP flag',
        suggestion: 'ATTACK-FROM-BAD-IP is safe to use in BLOCK mode immediately'
      });
    }
    
    if (!yaml.includes('rateLimit') && yaml.includes('trafficFilters')) {
      suggestions.push({
        type: 'best-practice',
        severity: 'info',
        message: 'Consider adding rate limiting rules',
        suggestion: 'Rate limits protect against DoS attacks and traffic spikes'
      });
    }
    
    if (yaml.includes('clientCountry') && !yaml.includes('alert: true')) {
      suggestions.push({
        type: 'best-practice',
        severity: 'info',
        message: 'Consider enabling alerts for geo-blocking rules',
        suggestion: 'Add alert: true to receive notifications when geo-block rules trigger'
      });
    }
    
    return suggestions;
  };

  // =====================================================
  // EXISTING ANALYSIS FUNCTIONS
  // =====================================================

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
    // Run validation first
    const validation = validateYamlSyntax(yamlInput);
    setValidationResults(validation);
    
    // Then parse and analyze
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
    
    // Auto-switch to validation tab if there are errors
    if (validation.errors.filter(e => e.severity === 'error').length > 0) {
      setActiveTab('validation');
    } else {
      setActiveTab('analysis');
    }
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

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'error': return '❌';
      case 'warning': return '⚠️';
      case 'info': return '💡';
      default: return 'ℹ️';
    }
  };

  const getSeverityClass = (severity) => {
    switch (severity) {
      case 'error': return 'validation-error';
      case 'warning': return 'validation-warning';
      case 'info': return 'validation-info';
      default: return 'validation-info';
    }
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
            WAF Rules Analyzer & Validator
          </h1>
          <p>Comprehensive analysis and syntax validation of your cdn.yaml configuration</p>
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
          <div className="input-with-lines">
            <div className="line-numbers">
              {yamlInput.split('\n').map((_, i) => (
                <div 
                  key={i} 
                  className={`line-number ${
                    validationResults?.errors.some(e => e.line === i + 1) ? 'has-error' :
                    validationResults?.warnings.some(w => w.line === i + 1) ? 'has-warning' : ''
                  }`}
                >
                  {i + 1}
                </div>
              ))}
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
          </div>
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
            Analyze & Validate
          </button>
        </div>

        <div className="results-panel">
          {/* Validation Status Banner */}
          {validationResults && (
            <div className={`validation-banner ${validationResults.isValid ? 'valid' : 'invalid'}`}>
              <div className="validation-status">
                {validationResults.isValid ? (
                  <>
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                      <polyline points="22 4 12 14.01 9 11.01" />
                    </svg>
                    <span>Configuration is valid</span>
                  </>
                ) : (
                  <>
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="15" y1="9" x2="9" y2="15" />
                      <line x1="9" y1="9" x2="15" y2="15" />
                    </svg>
                    <span>Configuration has issues</span>
                  </>
                )}
              </div>
              <div className="validation-counts">
                <span className="count-error">{validationResults.stats.totalErrors} errors</span>
                <span className="count-warning">{validationResults.stats.totalWarnings} warnings</span>
                <span className="count-suggestion">{validationResults.stats.totalSuggestions} suggestions</span>
              </div>
            </div>
          )}

          {/* Tab Navigation */}
          {(validationResults || analysisStats || yamlInput.trim()) && (
            <div className="results-tabs">
              <button 
                className={`tab-btn ${activeTab === 'validation' ? 'active' : ''}`}
                onClick={() => setActiveTab('validation')}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M9 11l3 3L22 4" />
                  <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" />
                </svg>
                Validation
                {validationResults && validationResults.stats.totalErrors > 0 && (
                  <span className="tab-badge error">{validationResults.stats.totalErrors}</span>
                )}
              </button>
              <button 
                className={`tab-btn ${activeTab === 'analysis' ? 'active' : ''}`}
                onClick={() => setActiveTab('analysis')}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="8" />
                  <path d="m21 21-4.35-4.35" />
                </svg>
                Analysis
                {analysisStats && (
                  <span className="tab-badge">{analysisStats.total}</span>
                )}
              </button>
              <button 
                className={`tab-btn ${activeTab === 'format' ? 'active' : ''}`}
                onClick={() => setActiveTab('format')}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M4 7V4h16v3" />
                  <path d="M9 20h6" />
                  <path d="M12 4v16" />
                </svg>
                Format
              </button>
            </div>
          )}

          {/* Validation Results Tab */}
          {activeTab === 'validation' && validationResults && (
            <div className="validation-results animate-slide-up">
              {/* Errors Section */}
              {validationResults.errors.length > 0 && (
                <div className="validation-section errors-section">
                  <h4 className="section-title error-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="15" y1="9" x2="9" y2="15" />
                      <line x1="9" y1="9" x2="15" y2="15" />
                    </svg>
                    Errors ({validationResults.errors.filter(e => e.severity === 'error').length})
                  </h4>
                  <div className="validation-list">
                    {validationResults.errors.filter(e => e.severity === 'error').map((error, idx) => (
                      <div key={idx} className={`validation-item ${getSeverityClass(error.severity)}`}>
                        <div className="validation-item-header">
                          <span className="validation-icon">{getSeverityIcon(error.severity)}</span>
                          <span className="validation-line">Line {error.line}</span>
                          <span className="validation-type">{error.type}</span>
                        </div>
                        <div className="validation-message">{error.message}</div>
                        {error.suggestion && (
                          <div className="validation-suggestion">
                            <span className="suggestion-label">💡 Fix:</span> {error.suggestion}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Warnings Section */}
              {validationResults.warnings.length > 0 && (
                <div className="validation-section warnings-section">
                  <h4 className="section-title warning-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                      <line x1="12" y1="9" x2="12" y2="13" />
                      <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    Warnings ({validationResults.warnings.length})
                  </h4>
                  <div className="validation-list">
                    {validationResults.warnings.map((warning, idx) => (
                      <div key={idx} className={`validation-item ${getSeverityClass(warning.severity)}`}>
                        <div className="validation-item-header">
                          <span className="validation-icon">{getSeverityIcon(warning.severity)}</span>
                          <span className="validation-line">Line {warning.line}</span>
                          <span className="validation-type">{warning.type}</span>
                        </div>
                        <div className="validation-message">{warning.message}</div>
                        {warning.suggestion && (
                          <div className="validation-suggestion">
                            <span className="suggestion-label">💡 Suggestion:</span> {warning.suggestion}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Suggestions Section */}
              {validationResults.suggestions.length > 0 && (
                <div className="validation-section suggestions-section">
                  <h4 className="section-title suggestion-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
                      <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    Best Practice Suggestions ({validationResults.suggestions.length})
                  </h4>
                  <div className="validation-list">
                    {validationResults.suggestions.map((suggestion, idx) => (
                      <div key={idx} className={`validation-item ${getSeverityClass(suggestion.severity)}`}>
                        <div className="validation-item-header">
                          <span className="validation-icon">{getSeverityIcon(suggestion.severity)}</span>
                          <span className="validation-type">{suggestion.type}</span>
                        </div>
                        <div className="validation-message">{suggestion.message}</div>
                        {suggestion.suggestion && (
                          <div className="validation-suggestion">
                            <span className="suggestion-label">💡 Recommendation:</span> {suggestion.suggestion}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* All Clear Message */}
              {validationResults.isValid && validationResults.errors.length === 0 && validationResults.warnings.length === 0 && (
                <div className="validation-success">
                  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                    <polyline points="22 4 12 14.01 9 11.01" />
                  </svg>
                  <h3>Configuration looks good! 🎉</h3>
                  <p>No syntax errors or warnings detected. Your cdn.yaml is ready for deployment.</p>
                </div>
              )}
            </div>
          )}

          {/* Analysis Results Tab */}
          {activeTab === 'analysis' && (
            <>
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
                            <span className="rule-line-info">Line {rule.lineStart}</span>
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
                  <p>Paste your cdn.yaml configuration and click "Analyze & Validate" to see a detailed breakdown.</p>
                  <p className="hint">💡 Click "Load Sample" to try with Adobe's recommended starter rules, or check "Examples" for common patterns.</p>
                </div>
              )}
            </>
          )}

          {/* Format Tab */}
          {activeTab === 'format' && (
            <div className="format-tab animate-slide-up">
              <div className="format-header">
                <h3>YAML Formatter & Tools</h3>
                <p>Format, minify, and organize your cdn.yaml configuration</p>
              </div>
              
              {formatMessage && (
                <div className={`format-message ${formatMessage.type}`}>
                  {formatMessage.type === 'success' ? (
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                      <polyline points="22 4 12 14.01 9 11.01" />
                    </svg>
                  ) : (
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="15" y1="9" x2="9" y2="15" />
                      <line x1="9" y1="9" x2="15" y2="15" />
                    </svg>
                  )}
                  <div>
                    <span>{formatMessage.text}</span>
                    {formatMessage.details && <span className="format-message-details">{formatMessage.details}</span>}
                  </div>
                </div>
              )}
              
              <div className="format-actions-grid">
                <button className="format-action-btn primary" onClick={formatYaml}>
                  <div className="format-action-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M4 7V4h16v3" />
                      <path d="M9 20h6" />
                      <path d="M12 4v16" />
                    </svg>
                  </div>
                  <div className="format-action-content">
                    <span className="format-action-title">Format / Prettify</span>
                    <span className="format-action-desc">Auto-indent and format YAML structure</span>
                  </div>
                </button>
                
                <button className="format-action-btn" onClick={minifyYaml}>
                  <div className="format-action-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M4 4h16v16H4z" />
                      <path d="M9 9h6v6H9z" />
                    </svg>
                  </div>
                  <div className="format-action-content">
                    <span className="format-action-title">Compact / Minify</span>
                    <span className="format-action-desc">Use inline format where possible</span>
                  </div>
                </button>
                
                <button className="format-action-btn" onClick={sortRules}>
                  <div className="format-action-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M11 5h10" />
                      <path d="M11 9h7" />
                      <path d="M11 13h4" />
                      <path d="M3 17l3 3 3-3" />
                      <path d="M6 18V4" />
                    </svg>
                  </div>
                  <div className="format-action-content">
                    <span className="format-action-title">Sort Rules A-Z</span>
                    <span className="format-action-desc">Sort rules alphabetically by name</span>
                  </div>
                </button>
                
                <button className="format-action-btn" onClick={copyToClipboard}>
                  <div className="format-action-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                    </svg>
                  </div>
                  <div className="format-action-content">
                    <span className="format-action-title">Copy to Clipboard</span>
                    <span className="format-action-desc">Copy formatted YAML to clipboard</span>
                  </div>
                </button>
              </div>
              
              <div className="format-tips">
                <h4>💡 Formatting Tips</h4>
                <ul>
                  <li><strong>Standard Indentation:</strong> Uses 2 spaces per level (Adobe standard)</li>
                  <li><strong>Inline Objects:</strong> Short conditions are formatted inline: <code>{`{ reqProperty: path, equals: "/" }`}</code></li>
                  <li><strong>Multi-line:</strong> Complex conditions expand to multiple lines for readability</li>
                  <li><strong>Comments:</strong> Comments are preserved during formatting</li>
                </ul>
              </div>
              
              <div className="format-valid-types">
                <h4>📋 Valid Action Types by Configuration</h4>
                <div className="valid-types-grid">
                  <div className="valid-type-card">
                    <h5>Traffic Filters</h5>
                    <div className="type-badges">
                      {['allow', 'block', 'log', 'authenticate'].map(t => (
                        <code key={t} className="type-badge">{t}</code>
                      ))}
                    </div>
                  </div>
                  <div className="valid-type-card">
                    <h5>Request Transformations</h5>
                    <div className="type-badges">
                      {['set', 'unset', 'transform'].map(t => (
                        <code key={t} className="type-badge">{t}</code>
                      ))}
                    </div>
                  </div>
                  <div className="valid-type-card">
                    <h5>Response Transformations</h5>
                    <div className="type-badges">
                      {['set', 'unset'].map(t => (
                        <code key={t} className="type-badge">{t}</code>
                      ))}
                    </div>
                  </div>
                  <div className="valid-type-card">
                    <h5>Redirects</h5>
                    <div className="type-badges">
                      {['redirect'].map(t => (
                        <code key={t} className="type-badge">{t}</code>
                      ))}
                    </div>
                    <div className="type-badges" style={{ marginTop: '8px' }}>
                      <span className="type-label">Status:</span>
                      {[301, 302, 303, 307, 308].map(s => (
                        <code key={s} className="type-badge">{s}</code>
                      ))}
                    </div>
                  </div>
                  <div className="valid-type-card">
                    <h5>Origin Selectors</h5>
                    <div className="type-badges">
                      {['selectOrigin', 'selectAemOrigin'].map(t => (
                        <code key={t} className="type-badge">{t}</code>
                      ))}
                    </div>
                  </div>
                  <div className="valid-type-card">
                    <h5>Transform Operations</h5>
                    <div className="type-badges">
                      {['replace', 'tolower', 'toupper'].map(t => (
                        <code key={t} className="type-badge">{t}</code>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default RulesAnalyzer;
