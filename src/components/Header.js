import React, { useState, useEffect } from 'react';
import './Header.css';

const Header = () => {
  const [theme, setTheme] = useState('dark');

  useEffect(() => {
    // Check for saved theme preference or default to dark
    const savedTheme = localStorage.getItem('aem-shield-theme') || 'dark';
    setTheme(savedTheme);
    document.documentElement.setAttribute('data-theme', savedTheme);
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    localStorage.setItem('aem-shield-theme', newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
  };

  const openDocs = () => {
    window.open('https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/security/traffic-filter-rules-including-waf', '_blank');
  };

  return (
    <header className="header">
      <div className="header-brand">
        <div className="header-logo">
          <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect width="32" height="32" rx="6" fill="url(#logo-gradient)" />
            <path
              d="M16 6L8 26h4l2-5h4l2 5h4L16 6zm0 7l2 5h-4l2-5z"
              fill="white"
            />
            <path
              d="M23 11l3 3-3 3"
              stroke="white"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M9 11l-3 3 3 3"
              stroke="white"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <defs>
              <linearGradient id="logo-gradient" x1="0" y1="0" x2="32" y2="32" gradientUnits="userSpaceOnUse">
                <stop stopColor="#e94560" />
                <stop offset="1" stopColor="#0f3460" />
              </linearGradient>
            </defs>
          </svg>
        </div>
        <div className="header-title">
          <h1>AEM Shield</h1>
          <span className="header-subtitle">WAF Rules Studio</span>
        </div>
      </div>
      
      <div className="header-center">
        <span className="header-env-badge">
          <span className="env-indicator"></span>
          Adobe Experience Manager Cloud Service
        </span>
      </div>
      
      <div className="header-actions">
        <button 
          className="header-btn" 
          title="Adobe Documentation"
          onClick={openDocs}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
          </svg>
        </button>
        <button 
          className={`header-btn ${theme === 'light' ? 'active' : ''}`}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          onClick={toggleTheme}
        >
          {theme === 'dark' ? (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="5" />
              <line x1="12" y1="1" x2="12" y2="3" />
              <line x1="12" y1="21" x2="12" y2="23" />
              <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
              <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
              <line x1="1" y1="12" x2="3" y2="12" />
              <line x1="21" y1="12" x2="23" y2="12" />
              <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
              <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
            </svg>
          ) : (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
            </svg>
          )}
        </button>
      </div>
    </header>
  );
};

export default Header;
