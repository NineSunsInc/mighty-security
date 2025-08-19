import React, { useState } from 'react';
import { Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import { Settings, Shield, Heart, BookOpen, Zap, Github, ExternalLink } from 'lucide-react';
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
          <a 
            href="https://github.com/NineSunsInc/mighty-security" 
            target="_blank" 
            rel="noopener noreferrer"
            className="stat-card hover:scale-105 transition-transform cursor-pointer group"
            title="⭐ Star us on GitHub!"
          >
            <div className="relative">
              <Heart className="stat-icon group-hover:text-red-500 transition-colors" size={24} />
              <ExternalLink className="absolute -top-1 -right-1 w-3 h-3 text-gray-400 group-hover:text-gray-600" />
            </div>
            <div>
              <div className="stat-number flex items-center gap-1">
                OSS <Github className="w-4 h-4 opacity-60" />
              </div>
              <div className="stat-label">Open Source</div>
            </div>
          </a>
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