import React, { useState } from 'react';
import './App.css';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import RulesAnalyzer from './components/RulesAnalyzer';
import RulesGenerator from './components/RulesGenerator';
import RulesSimulator from './components/RulesSimulator';
import Dashboard from './components/Dashboard';

function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [generatedRules, setGeneratedRules] = useState([]);

  const renderView = () => {
    switch (activeView) {
      case 'dashboard':
        return <Dashboard onNavigate={setActiveView} />;
      case 'analyzer':
        return <RulesAnalyzer />;
      case 'generator':
        return <RulesGenerator onRulesGenerated={setGeneratedRules} />;
      case 'simulator':
        return <RulesSimulator rules={generatedRules} />;
      default:
        return <Dashboard onNavigate={setActiveView} />;
    }
  };

  return (
    <div className="app">
      <Header />
      <div className="app-container">
        <Sidebar activeView={activeView} onViewChange={setActiveView} />
        <main className="main-content">
          {renderView()}
        </main>
      </div>
    </div>
  );
}

export default App;
