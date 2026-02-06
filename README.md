# 🛡️ AEM Shield

**Professional WAF Rules Management Studio for Adobe Experience Manager Cloud Service**

![React](https://img.shields.io/badge/React-18.2-blue)
![License](https://img.shields.io/badge/License-MIT-green)

AEM Shield is a comprehensive tool for creating, analyzing, and testing WAF (Web Application Firewall) rules and CDN configurations for Adobe Experience Manager as a Cloud Service.

## ✨ Features

### 📊 Dashboard
- OWASP Top 10 coverage mapping
- WAF flags overview with severity levels
- Deployment workflow guidance
- Advanced use cases library

### 🔍 Rules Analyzer
- Parse and analyze `cdn.yaml` configurations
- Human-friendly explanations for each rule
- Attack pattern examples
- Security scoring

### 🛠️ CDN Configuration Generator
- **Traffic Filter Rules** - WAF protection, rate limiting, geo-blocking
- **Request Transformations** - URL rewriting, header manipulation
- **Response Transformations** - CORS, security headers
- **Server-side Redirects** - 301/302 redirects at CDN layer
- **Origin Selectors** - Route to different backends

### 🎯 Rules Simulator
- Test attack patterns against your rules
- OWASP-aligned attack scenarios
- CDN log preview
- Adobe-recommended action guidance

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build
```

## 📦 Free Hosting

Deploy AEM Shield for free using any of these platforms:

| Platform | Command | URL |
|----------|---------|-----|
| **Vercel** | Connect GitHub repo | `aem-shield.vercel.app` |
| **Netlify** | Drag `build` folder | `aem-shield.netlify.app` |
| **GitHub Pages** | `npm run deploy` | `username.github.io/aem-shield` |
| **Cloudflare** | Connect GitHub repo | `aem-shield.pages.dev` |

See [HOSTING.md](./HOSTING.md) for detailed instructions.

## 📚 Documentation

- [Adobe Traffic Filter Rules Documentation](https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/security/traffic-filter-rules-including-waf)
- [CDN Configuration Guide](https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/content-delivery/cdn-configuring-traffic)
- [AEM Security Tutorials](https://experienceleague.adobe.com/en/docs/experience-manager-learn/cloud-service/security/traffic-filter-and-waf-rules/overview)

## 🏗️ Project Structure

```
aem-shield/
├── public/
│   └── index.html
├── src/
│   ├── components/
│   │   ├── Dashboard.js        # Main dashboard with stats
│   │   ├── Header.js           # App header with theme toggle
│   │   ├── Sidebar.js          # Navigation sidebar
│   │   ├── RulesAnalyzer.js    # YAML analyzer
│   │   ├── RulesGenerator.js   # CDN config builder
│   │   └── RulesSimulator.js   # Attack simulator
│   ├── data/
│   │   ├── wafData.js          # WAF flags, OWASP mapping
│   │   └── cdnConfigData.js    # CDN config templates
│   ├── App.js
│   ├── App.css
│   └── index.css               # Global styles & themes
├── package.json
└── README.md
```

## 🎨 Themes

AEM Shield supports both **dark** and **light** themes. Toggle using the sun/moon button in the header. Your preference is saved automatically.

## 📄 License

MIT License - feel free to use this for your AEM projects!

---

Built with ❤️ for the AEM community
