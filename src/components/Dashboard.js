import React, { useState } from 'react';
import { WAF_FLAGS, SEVERITY_COLORS, RULE_CATEGORIES, OWASP_TOP_10, DEPLOYMENT_WORKFLOW, ADVANCED_USE_CASES } from '../data/wafData';
import './Dashboard.css';

const Dashboard = ({ onNavigate }) => {
  const [showOwasp, setShowOwasp] = useState(false);
  const [showWorkflow, setShowWorkflow] = useState(false);
  const [showUseCases, setShowUseCases] = useState(false);

  const flagStats = Object.values(WAF_FLAGS).reduce((acc, flag) => {
    acc[flag.severity] = (acc[flag.severity] || 0) + 1;
    return acc;
  }, {});

  const quickStats = [
    {
      label: 'WAF Flags Available',
      value: Object.keys(WAF_FLAGS).length,
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      ),
      color: 'accent'
    },
    {
      label: 'Critical Protections',
      value: flagStats.critical || 0,
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      ),
      color: 'red'
    },
    {
      label: 'OWASP Top 10 Coverage',
      value: Object.keys(OWASP_TOP_10).filter(k => OWASP_TOP_10[k].wafFlags.length > 0).length + '/10',
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
          <polyline points="22 4 12 14.01 9 11.01" />
        </svg>
      ),
      color: 'green'
    },
    {
      label: 'Advanced Use Cases',
      value: ADVANCED_USE_CASES.length,
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="3" width="7" height="7" />
          <rect x="14" y="3" width="7" height="7" />
          <rect x="14" y="14" width="7" height="7" />
          <rect x="3" y="14" width="7" height="7" />
        </svg>
      ),
      color: 'blue'
    }
  ];

  const featureCards = [
    {
      id: 'analyzer',
      title: 'Rules Analyzer',
      description: 'Paste your existing cdn.yaml configuration and get a human-friendly breakdown of all rules with explanations.',
      icon: (
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.35-4.35" />
          <path d="M11 8v6" />
          <path d="M8 11h6" />
        </svg>
      ),
      features: ['Parse YAML configuration', 'Explain each rule', 'Show attack examples', 'Security score']
    },
    {
      id: 'generator',
      title: 'Rules Generator',
      description: 'Build WAF rules visually with our intuitive interface. Select protections and export valid cdn.yaml.',
      icon: (
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
        </svg>
      ),
      features: ['Visual rule builder', 'Adobe templates', 'OWASP protection', 'Rate limiting']
    },
    {
      id: 'simulator',
      title: 'Rules Simulator',
      description: 'Test your WAF rules by simulating various attack patterns and see how they would be handled.',
      icon: (
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <polygon points="5 3 19 12 5 21 5 3" />
        </svg>
      ),
      features: ['Attack simulation', 'Rule matching', 'OWASP scenarios', 'CDN log preview']
    }
  ];

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <div className="dashboard-intro">
          <h1>Welcome to AEM Shield</h1>
          <p>Professional WAF rules management for Adobe Experience Manager Cloud Service. 
             Protect your AEM websites from DoS, DDoS, malicious traffic and sophisticated attacks.</p>
        </div>
      </div>

      <div className="stats-grid">
        {quickStats.map((stat, index) => (
          <div key={index} className={`stat-card stat-${stat.color}`}>
            <div className="stat-icon">{stat.icon}</div>
            <div className="stat-content">
              <span className="stat-value">{stat.value}</span>
              <span className="stat-label">{stat.label}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Rule Categories */}
      <section className="dashboard-section">
        <h2 className="section-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          Rule Categories
        </h2>
        <div className="category-grid">
          {Object.entries(RULE_CATEGORIES).map(([key, category]) => (
            <div key={key} className={`category-card ${key}`}>
              <div className="category-header">
                <span className={`category-badge ${key}`}>{key === 'standard' ? 'Included' : 'License Required'}</span>
              </div>
              <h3>{category.name}</h3>
              <p>{category.description}</p>
              <div className="category-use-cases">
                <strong>Use Cases:</strong>
                <ul>
                  {category.useCases.slice(0, 3).map((useCase, i) => (
                    <li key={i}>{useCase}</li>
                  ))}
                </ul>
              </div>
              <div className="category-mode">
                <span className="mode-label">Recommended:</span>
                <span className="mode-value">{category.recommendedMode}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Quick Links */}
      <section className="dashboard-section">
        <h2 className="section-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
          </svg>
          Quick Access
        </h2>
        <div className="quick-links">
          <button className="quick-link" onClick={() => setShowWorkflow(!showWorkflow)}>
            <span className="quick-link-icon">📋</span>
            <span className="quick-link-text">Deployment Workflow</span>
          </button>
          <button className="quick-link" onClick={() => setShowOwasp(!showOwasp)}>
            <span className="quick-link-icon">🔒</span>
            <span className="quick-link-text">OWASP Top 10 Coverage</span>
          </button>
          <button className="quick-link" onClick={() => setShowUseCases(!showUseCases)}>
            <span className="quick-link-icon">💡</span>
            <span className="quick-link-text">Advanced Use Cases</span>
          </button>
          <a className="quick-link" href="https://experienceleague.adobe.com/en/docs/experience-manager-learn/cloud-service/security/traffic-filter-and-waf-rules/overview" target="_blank" rel="noopener noreferrer">
            <span className="quick-link-icon">📚</span>
            <span className="quick-link-text">Adobe Tutorials ↗</span>
          </a>
        </div>
      </section>

      {/* Deployment Workflow */}
      {showWorkflow && (
        <section className="dashboard-section animate-slide-up">
          <div className="panel-header">
            <h2 className="section-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
              </svg>
              Deployment Workflow
            </h2>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowWorkflow(false)}>×</button>
          </div>
          <div className="workflow-steps">
            {DEPLOYMENT_WORKFLOW.steps.map((step, index) => (
              <div key={index} className="workflow-step">
                <div className="step-number">{step.step}</div>
                <div className="step-content">
                  <h4>{step.title}</h4>
                  <p>{step.description}</p>
                  <span className="step-action">{step.action}</span>
                </div>
                {index < DEPLOYMENT_WORKFLOW.steps.length - 1 && (
                  <div className="step-arrow">→</div>
                )}
              </div>
            ))}
          </div>
          <div className="workflow-exception">
            <strong>⚡ Exception:</strong> {DEPLOYMENT_WORKFLOW.exceptions[0].flag} is safe to deploy in BLOCK mode immediately.
          </div>
        </section>
      )}

      {/* OWASP Top 10 */}
      {showOwasp && (
        <section className="dashboard-section animate-slide-up">
          <div className="panel-header">
            <h2 className="section-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              OWASP Top 10 (2021) Coverage
            </h2>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowOwasp(false)}>×</button>
          </div>
          <div className="owasp-grid">
            {Object.entries(OWASP_TOP_10).map(([code, item]) => (
              <div key={code} className={`owasp-card ${item.wafFlags.length > 0 ? 'covered' : 'partial'}`}>
                <div className="owasp-header">
                  <span className="owasp-code">{code}</span>
                  <span className={`owasp-status ${item.wafFlags.length > 0 ? 'covered' : 'partial'}`}>
                    {item.wafFlags.length > 0 ? '✓ Protected' : '○ Partial'}
                  </span>
                </div>
                <h4>{item.name}</h4>
                <p>{item.description}</p>
                {item.wafFlags.length > 0 && (
                  <div className="owasp-flags">
                    <strong>WAF Flags:</strong>
                    <div className="flag-tags">
                      {item.wafFlags.map(flag => (
                        <code key={flag} className="flag-tag">{flag}</code>
                      ))}
                    </div>
                  </div>
                )}
                <div className="owasp-mitigations">
                  <strong>Mitigations:</strong> {item.mitigations.join(', ')}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Advanced Use Cases */}
      {showUseCases && (
        <section className="dashboard-section animate-slide-up">
          <div className="panel-header">
            <h2 className="section-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
              </svg>
              Advanced Use Cases
            </h2>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowUseCases(false)}>×</button>
          </div>
          <div className="use-cases-grid">
            {ADVANCED_USE_CASES.map((useCase) => (
              <div key={useCase.id} className="use-case-card">
                <div className="use-case-header">
                  <span className="use-case-category">{useCase.category}</span>
                </div>
                <h4>{useCase.title}</h4>
                <p>{useCase.description}</p>
                <pre className="use-case-yaml">{useCase.yaml}</pre>
                <div className="use-case-explanation">
                  <strong>Explanation:</strong> {useCase.explanation}
                </div>
                <div className="use-case-tag">
                  <strong>Use Case:</strong> {useCase.useCase}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="dashboard-section">
        <h2 className="section-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
          Get Started
        </h2>
        <div className="feature-grid">
          {featureCards.map((card) => (
            <div key={card.id} className="feature-card" onClick={() => onNavigate(card.id)}>
              <div className="feature-icon">{card.icon}</div>
              <h3>{card.title}</h3>
              <p>{card.description}</p>
              <ul className="feature-list">
                {card.features.map((feature, i) => (
                  <li key={i}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    {feature}
                  </li>
                ))}
              </ul>
              <span className="feature-cta">
                Get Started
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="5" y1="12" x2="19" y2="12" />
                  <polyline points="12 5 19 12 12 19" />
                </svg>
              </span>
            </div>
          ))}
        </div>
      </section>

      <section className="dashboard-section">
        <h2 className="section-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          WAF Protections Preview
        </h2>
        <div className="protection-grid">
          {Object.entries(WAF_FLAGS).slice(0, 8).map(([key, flag]) => (
            <div key={key} className="protection-card">
              <div className="protection-header">
                <span 
                  className="protection-severity"
                  style={{ 
                    background: SEVERITY_COLORS[flag.severity].bg,
                    color: SEVERITY_COLORS[flag.severity].color 
                  }}
                >
                  {flag.severity}
                </span>
                <span className="protection-category">{flag.category}</span>
              </div>
              <h4>{flag.name}</h4>
              <p>{flag.description}</p>
              {flag.recommended && (
                <span className="protection-recommended">⭐ Recommended</span>
              )}
            </div>
          ))}
        </div>
        <button className="btn btn-secondary view-all-btn" onClick={() => onNavigate('analyzer')}>
          View All {Object.keys(WAF_FLAGS).length} Protections
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="5" y1="12" x2="19" y2="12" />
            <polyline points="12 5 19 12 12 19" />
          </svg>
        </button>
      </section>
    </div>
  );
};

export default Dashboard;
