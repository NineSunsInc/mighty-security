import React, { useState } from 'react';
import { Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import { Settings, Shield, AlertTriangle, BookOpen, Zap } from 'lucide-react';
import HowItWorks from './HowItWorks/HowItWorks';
import ThreatsProtection from './ThreatsProtection/ThreatsProtection';
import './AboutPage.css';

const AboutPage = () => {
  const location = useLocation();
  
  const tabs = [
    {
      path: '/about/how-it-works',
      label: 'How It Works',
      icon: Settings,
      description: 'Architecture & Process'
    },
    {
      path: '/about/threats-protection',
      label: 'Threats & Protection',
      icon: Shield,
      description: 'Security Features'
    }
  ];

  const currentTab = location.pathname;

  return (
    <div className="about-page">
      <div className="about-header">
        <div className="about-title-section">
          <BookOpen className="about-icon" size={32} />
          <div>
            <h1 className="about-title">MCP Security Learning Center</h1>
            <p className="about-subtitle">
              Learn how we protect your Model Context Protocol tools from security threats
            </p>
          </div>
        </div>
        
        <div className="about-stats">
          <div className="stat-card">
            <Shield className="stat-icon" size={24} />
            <div>
              <div className="stat-number">21+</div>
              <div className="stat-label">Threat Patterns</div>
            </div>
          </div>
          <div className="stat-card">
            <Zap className="stat-icon" size={24} />
            <div>
              <div className="stat-number">Fast</div>
              <div className="stat-label">Scan Speed</div>
            </div>
          </div>
          <div className="stat-card">
            <AlertTriangle className="stat-icon" size={24} />
            <div>
              <div className="stat-number">OSS</div>
              <div className="stat-label">Open Source</div>
            </div>
          </div>
        </div>
      </div>

      <div className="about-navigation">
        {tabs.map(tab => {
          const Icon = tab.icon;
          const isActive = currentTab.startsWith(tab.path);
          
          return (
            <Link
              key={tab.path}
              to={tab.path}
              className={`about-tab ${isActive ? 'about-tab-active' : ''}`}
            >
              <Icon className="about-tab-icon" size={20} />
              <div className="about-tab-content">
                <span className="about-tab-label">{tab.label}</span>
                <span className="about-tab-desc">{tab.description}</span>
              </div>
            </Link>
          );
        })}
      </div>

      <div className="about-content">
        <Routes>
          <Route path="/" element={<Navigate to="/about/how-it-works" replace />} />
          <Route path="/how-it-works" element={<HowItWorks />} />
          <Route path="/threats-protection" element={<ThreatsProtection />} />
        </Routes>
      </div>
    </div>
  );
};

export default AboutPage;