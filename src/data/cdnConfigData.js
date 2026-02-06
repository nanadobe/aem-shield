// CDN Configuration Data based on Adobe Documentation
// Reference: https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/content-delivery/cdn-configuring-traffic

// ============================================
// RULE TYPES
// ============================================
export const CDN_RULE_TYPES = {
  trafficFilter: {
    name: 'Traffic Filter Rules',
    description: 'Control what traffic is allowed or denied by the CDN. Includes WAF rules for attack protection.',
    icon: 'shield',
    category: 'Security',
    license: 'Standard (WAF requires Extended Security)',
    examples: ['Block IP addresses', 'Rate limiting', 'Geo-blocking', 'WAF protection']
  },
  requestTransformations: {
    name: 'Request Transformations',
    description: 'Modify incoming requests including headers, paths, query parameters, and cookies.',
    icon: 'edit',
    category: 'Transform',
    license: 'Standard',
    examples: ['URL rewriting', 'Header manipulation', 'Query parameter filtering', 'Marketing parameter removal']
  },
  responseTransformations: {
    name: 'Response Transformations',
    description: 'Modify outgoing responses including headers and cookies before sending to the client.',
    icon: 'arrow-right',
    category: 'Transform',
    license: 'Standard',
    examples: ['Set security headers', 'CORS headers', 'Cache headers', 'Cookie management']
  },
  redirects: {
    name: 'Server-side Redirects',
    description: 'Trigger browser redirects (301, 302, etc.) at the CDN layer for fast, efficient redirects.',
    icon: 'external-link',
    category: 'Routing',
    license: 'Standard',
    examples: ['Domain redirects', 'Path redirects', 'Country-based redirects', 'HTTPS enforcement']
  },
  originSelectors: {
    name: 'Origin Selectors',
    description: 'Route traffic to different backend origins based on request properties.',
    icon: 'git-branch',
    category: 'Routing',
    license: 'Standard',
    examples: ['Proxy to external APIs', 'Edge Delivery Services', 'Static content routing', 'A/B testing']
  }
};

// ============================================
// CONDITION OPERATORS
// ============================================
export const CONDITION_OPERATORS = {
  equals: {
    name: 'equals',
    description: 'Exact string match',
    example: '{ reqProperty: path, equals: "/admin" }',
    valueType: 'string'
  },
  notEquals: {
    name: 'notEquals',
    description: 'Does not equal the value',
    example: '{ reqProperty: tier, notEquals: "author" }',
    valueType: 'string'
  },
  like: {
    name: 'like',
    description: 'Wildcard pattern match (* for any characters)',
    example: '{ reqProperty: path, like: "/api/*" }',
    valueType: 'string'
  },
  notLike: {
    name: 'notLike',
    description: 'Does not match wildcard pattern',
    example: '{ reqProperty: path, notLike: "*.html" }',
    valueType: 'string'
  },
  matches: {
    name: 'matches',
    description: 'Regular expression match (Java regex syntax)',
    example: '{ reqProperty: path, matches: "^/content/.*\\.json$" }',
    valueType: 'regex'
  },
  doesNotMatch: {
    name: 'doesNotMatch',
    description: 'Does not match regular expression',
    example: '{ reqProperty: path, doesNotMatch: "^/api/.*" }',
    valueType: 'regex'
  },
  in: {
    name: 'in',
    description: 'Value is in provided list',
    example: '{ reqProperty: clientCountry, in: ["US", "CA", "GB"] }',
    valueType: 'array'
  },
  notIn: {
    name: 'notIn',
    description: 'Value is not in provided list',
    example: '{ reqProperty: method, notIn: ["GET", "HEAD"] }',
    valueType: 'array'
  },
  exists: {
    name: 'exists',
    description: 'Property exists (true/false)',
    example: '{ reqHeader: Authorization, exists: true }',
    valueType: 'boolean'
  }
};

// ============================================
// REQUEST PROPERTIES
// ============================================
export const REQUEST_PROPERTIES = {
  path: {
    name: 'path',
    description: 'Request URI path without query string',
    example: '/content/dam/image.jpg',
    category: 'URL'
  },
  queryString: {
    name: 'queryString',
    description: 'Query string portion of the URL',
    example: '?id=123&sort=asc',
    category: 'URL'
  },
  url: {
    name: 'url',
    description: 'Full request URL including query string',
    example: '/page.html?ref=home',
    category: 'URL'
  },
  method: {
    name: 'method',
    description: 'HTTP method (GET, POST, PUT, DELETE, etc.)',
    example: 'GET',
    category: 'Request'
  },
  tier: {
    name: 'tier',
    description: 'AEM tier - "author" or "publish"',
    example: 'publish',
    category: 'AEM'
  },
  domain: {
    name: 'domain',
    description: 'Request domain/hostname',
    example: 'www.example.com',
    category: 'URL'
  },
  clientIp: {
    name: 'clientIp',
    description: 'Client IP address (supports CIDR notation)',
    example: '192.168.1.100 or 10.0.0.0/8',
    category: 'Client'
  },
  clientCountry: {
    name: 'clientCountry',
    description: 'ISO 3166-1 alpha-2 country code',
    example: 'US',
    category: 'Client'
  },
  clientAsn: {
    name: 'clientAsn',
    description: 'Autonomous System Number of client network',
    example: '15169 (Google)',
    category: 'Client'
  },
  userAgent: {
    name: 'userAgent',
    description: 'User-Agent header value',
    example: 'Mozilla/5.0...',
    category: 'Headers'
  }
};

// ============================================
// REQUEST TRANSFORMATION ACTIONS
// ============================================
export const REQUEST_TRANSFORM_ACTIONS = {
  set: {
    name: 'set',
    description: 'Set a value',
    targets: ['reqProperty', 'reqHeader', 'queryParam', 'reqCookie', 'logProperty', 'var'],
    requiresValue: true
  },
  unset: {
    name: 'unset',
    description: 'Remove/unset a value',
    targets: ['reqProperty', 'reqHeader', 'queryParam', 'reqCookie', 'logProperty', 'var', 'queryParamMatch', 'queryParamDoesNotMatch'],
    requiresValue: false
  },
  transform: {
    name: 'transform',
    description: 'Transform using replace or tolower',
    targets: ['reqProperty', 'reqHeader', 'queryParam', 'reqCookie', 'var'],
    operations: ['replace', 'tolower'],
    requiresValue: true
  }
};

// ============================================
// RESPONSE TRANSFORMATION ACTIONS
// ============================================
export const RESPONSE_TRANSFORM_ACTIONS = {
  set: {
    name: 'set',
    description: 'Set a response value',
    targets: ['respProperty', 'respHeader', 'respCookie', 'logProperty', 'var'],
    requiresValue: true
  },
  unset: {
    name: 'unset',
    description: 'Remove a response value',
    targets: ['respHeader', 'respCookie', 'logProperty', 'var'],
    requiresValue: false
  }
};

// ============================================
// REDIRECT STATUS CODES
// ============================================
export const REDIRECT_STATUS_CODES = [
  { code: 301, name: 'Moved Permanently', description: 'Permanent redirect, browsers cache this' },
  { code: 302, name: 'Found', description: 'Temporary redirect, not cached by default' },
  { code: 303, name: 'See Other', description: 'Redirect after POST, forces GET method' },
  { code: 307, name: 'Temporary Redirect', description: 'Temporary, preserves request method' },
  { code: 308, name: 'Permanent Redirect', description: 'Permanent, preserves request method' }
];

// ============================================
// COMMON HEADERS
// ============================================
export const COMMON_REQUEST_HEADERS = [
  'Host', 'User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding',
  'Authorization', 'Cookie', 'Content-Type', 'Content-Length',
  'X-Forwarded-For', 'X-Forwarded-Host', 'X-Real-IP', 'Referer', 'Origin'
];

export const COMMON_RESPONSE_HEADERS = [
  'Content-Type', 'Content-Length', 'Cache-Control', 'Expires', 'ETag',
  'Last-Modified', 'Location', 'Set-Cookie', 'Access-Control-Allow-Origin',
  'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers',
  'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection',
  'Content-Security-Policy', 'Strict-Transport-Security'
];

export const SECURITY_HEADERS_PRESETS = {
  'hsts': {
    name: 'HSTS (HTTP Strict Transport Security)',
    header: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains',
    description: 'Force HTTPS connections for 1 year'
  },
  'nosniff': {
    name: 'X-Content-Type-Options',
    header: 'X-Content-Type-Options',
    value: 'nosniff',
    description: 'Prevent MIME type sniffing'
  },
  'xss': {
    name: 'X-XSS-Protection',
    header: 'X-XSS-Protection',
    value: '1; mode=block',
    description: 'Enable browser XSS filtering'
  },
  'frame': {
    name: 'X-Frame-Options',
    header: 'X-Frame-Options',
    value: 'SAMEORIGIN',
    description: 'Prevent clickjacking attacks'
  },
  'csp': {
    name: 'Content Security Policy',
    header: 'Content-Security-Policy',
    value: "default-src 'self'",
    description: 'Restrict resource loading sources'
  }
};

// ============================================
// TEMPLATE RULES
// ============================================
export const TEMPLATE_RULES = {
  // Request Transformations
  removeMarketingParams: {
    type: 'requestTransformations',
    name: 'Remove Marketing Parameters',
    description: 'Remove common marketing/tracking query parameters to improve cache hit ratio',
    yaml: `requestTransformations:
  removeMarketingParams: true`,
    explanation: 'Built-in feature that removes common UTM and tracking parameters'
  },
  urlRewrite: {
    type: 'requestTransformations',
    name: 'URL Rewrite (.html removal)',
    description: 'Remove .html extension from URLs for cleaner paths',
    yaml: `requestTransformations:
  rules:
    - name: remove-html-extension
      when:
        reqProperty: path
        like: "*.html"
      actions:
        - type: transform
          reqProperty: path
          op: replace
          match: '\\.html$'
          replacement: ""`,
    explanation: 'Transforms /page.html to /page using regex replacement'
  },
  setCustomHeader: {
    type: 'requestTransformations',
    name: 'Set Custom Request Header',
    description: 'Add a custom header to incoming requests',
    yaml: `requestTransformations:
  rules:
    - name: set-custom-header
      when:
        reqProperty: path
        like: "/api/*"
      actions:
        - type: set
          reqHeader: X-Custom-Header
          value: "custom-value"`,
    explanation: 'Sets a custom header on all API requests'
  },
  extractCountryCode: {
    type: 'requestTransformations',
    name: 'Extract Country from Path',
    description: 'Extract country code from path and store in variable',
    yaml: `requestTransformations:
  rules:
    - name: extract-country-code
      when:
        reqProperty: path
        matches: "^/([a-zA-Z]{2})(/.*|$)"
      actions:
        - type: set
          var: country-code
          value:
            reqProperty: path
        - type: transform
          var: country-code
          op: replace
          match: "^/([a-zA-Z]{2})(/.*|$)"
          replacement: "\\1"`,
    explanation: 'Extracts country code from /us/page to variable for later use'
  },

  // Response Transformations
  corsHeaders: {
    type: 'responseTransformations',
    name: 'CORS Headers',
    description: 'Add Cross-Origin Resource Sharing headers',
    yaml: `responseTransformations:
  rules:
    - name: add-cors-headers
      when:
        reqProperty: path
        like: "/api/*"
      actions:
        - type: set
          respHeader: Access-Control-Allow-Origin
          value: "*"
        - type: set
          respHeader: Access-Control-Allow-Methods
          value: "GET, POST, OPTIONS"
        - type: set
          respHeader: Access-Control-Allow-Headers
          value: "Content-Type, Authorization"`,
    explanation: 'Enables cross-origin requests for API endpoints'
  },
  securityHeaders: {
    type: 'responseTransformations',
    name: 'Security Headers',
    description: 'Add recommended security headers to responses',
    yaml: `responseTransformations:
  rules:
    - name: security-headers
      when: { reqProperty: tier, equals: publish }
      actions:
        - type: set
          respHeader: X-Content-Type-Options
          value: "nosniff"
        - type: set
          respHeader: X-Frame-Options
          value: "SAMEORIGIN"
        - type: set
          respHeader: X-XSS-Protection
          value: "1; mode=block"
        - type: set
          respHeader: Strict-Transport-Security
          value: "max-age=31536000; includeSubDomains"`,
    explanation: 'Adds essential security headers to prevent common attacks'
  },
  setCacheHeaders: {
    type: 'responseTransformations',
    name: 'Cache Control Headers',
    description: 'Set caching headers for static assets',
    yaml: `responseTransformations:
  rules:
    - name: cache-static-assets
      when:
        reqProperty: path
        matches: "\\.(css|js|png|jpg|gif|svg|woff2?)$"
      actions:
        - type: set
          respHeader: Cache-Control
          value: "public, max-age=31536000, immutable"`,
    explanation: 'Sets long cache for static assets (1 year)'
  },

  // Redirects
  wwwRedirect: {
    type: 'redirects',
    name: 'WWW Redirect',
    description: 'Redirect non-www to www domain',
    yaml: `redirects:
  rules:
    - name: www-redirect
      when:
        reqProperty: domain
        equals: "example.com"
      action:
        type: redirect
        status: 301
        location:
          reqProperty: url
          transform:
            - op: replace
              match: "^(.*)$"
              replacement: "https://www.example.com\\1"`,
    explanation: 'Redirects example.com to www.example.com preserving path'
  },
  httpsRedirect: {
    type: 'redirects',
    name: 'HTTPS Redirect',
    description: 'Redirect HTTP to HTTPS',
    yaml: `redirects:
  rules:
    - name: https-redirect
      when:
        reqHeader: X-Forwarded-Proto
        equals: "http"
      action:
        type: redirect
        status: 301
        location: "https://{reqProperty: domain}{reqProperty: url}"`,
    explanation: 'Forces all traffic to use HTTPS'
  },
  countryRedirect: {
    type: 'redirects',
    name: 'Country-based Redirect',
    description: 'Redirect users to country-specific pages',
    yaml: `redirects:
  rules:
    - name: country-redirect
      when:
        allOf:
          - { reqProperty: path, equals: "/" }
          - { reqProperty: clientCountry, in: ["DE", "AT", "CH"] }
      action:
        type: redirect
        status: 302
        location: "/de/home"`,
    explanation: 'Redirects German-speaking countries to German homepage'
  },
  pathRedirect: {
    type: 'redirects',
    name: 'Legacy Path Redirect',
    description: 'Redirect old URLs to new structure',
    yaml: `redirects:
  rules:
    - name: legacy-redirect
      when:
        reqProperty: path
        like: "/old-section/*"
      action:
        type: redirect
        status: 301
        location:
          reqProperty: path
          transform:
            - op: replace
              match: "^/old-section/(.*)$"
              replacement: "/new-section/\\1"`,
    explanation: 'Maps old URL structure to new paths'
  },

  // Origin Selectors
  apiProxy: {
    type: 'originSelectors',
    name: 'API Proxy',
    description: 'Proxy API requests to external backend',
    yaml: `originSelectors:
  rules:
    - name: api-proxy
      when:
        reqProperty: path
        like: "/api/external/*"
      action:
        type: selectOrigin
        originName: external-api
  origins:
    - name: external-api
      domain: api.external-service.com
      forwardHost: false
      forwardAuthorization: true
      timeout: 30`,
    explanation: 'Routes /api/external/* to external API backend'
  },
  edgeDelivery: {
    type: 'originSelectors',
    name: 'Edge Delivery Services',
    description: 'Route static assets to Edge Delivery Services',
    yaml: `originSelectors:
  rules:
    - name: edge-delivery
      when:
        allOf:
          - { reqProperty: tier, equals: publish }
          - reqProperty: path
            matches: "^(/scripts/.*|/styles/.*|/fonts/.*|/blocks/.*|/icons/.*)"
      action:
        type: selectOrigin
        originName: aem-live
  origins:
    - name: aem-live
      domain: main--repo--owner.aem.live`,
    explanation: 'Routes front-end assets to Edge Delivery Services'
  },
  staticOrigin: {
    type: 'originSelectors',
    name: 'AEM Static Origin',
    description: 'Route to AEM static content tier',
    yaml: `originSelectors:
  rules:
    - name: static-assets
      when:
        reqProperty: path
        like: "/static/*"
      action:
        type: selectAemOrigin
        originName: static`,
    explanation: 'Routes to AEM static tier for front-end pipeline content'
  }
};

// ============================================
// CONDITION STRUCTURE EXAMPLES
// ============================================
export const CONDITION_EXAMPLES = {
  simple: {
    name: 'Simple Condition',
    yaml: `when:
  reqProperty: path
  equals: "/admin"`,
    explanation: 'Single property match'
  },
  allOf: {
    name: 'AND Conditions (allOf)',
    yaml: `when:
  allOf:
    - { reqProperty: tier, equals: publish }
    - { reqProperty: path, like: "/api/*" }
    - { reqProperty: method, in: ["GET", "POST"] }`,
    explanation: 'ALL conditions must match'
  },
  anyOf: {
    name: 'OR Conditions (anyOf)',
    yaml: `when:
  anyOf:
    - { reqProperty: path, like: "/admin/*" }
    - { reqProperty: path, like: "/console/*" }`,
    explanation: 'ANY condition must match'
  },
  nested: {
    name: 'Nested Conditions',
    yaml: `when:
  allOf:
    - { reqProperty: tier, equals: publish }
    - anyOf:
        - { reqProperty: clientCountry, in: ["US", "CA"] }
        - { reqHeader: X-Internal, equals: "true" }`,
    explanation: 'Complex nested AND/OR logic'
  },
  headerCondition: {
    name: 'Header Condition',
    yaml: `when:
  reqHeader: Authorization
  exists: true`,
    explanation: 'Check if header exists'
  },
  queryParamCondition: {
    name: 'Query Parameter Condition',
    yaml: `when:
  queryParam: debug
  equals: "true"`,
    explanation: 'Match specific query parameter value'
  },
  cookieCondition: {
    name: 'Cookie Condition',
    yaml: `when:
  reqCookie: session
  exists: true`,
    explanation: 'Check if cookie exists'
  }
};
