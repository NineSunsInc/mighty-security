import React from 'react';
import { 
  Search, 
  FileText, 
  Brain, 
  Shield, 
  Zap, 
  CheckCircle,
  ArrowRight,
  Code,
  Network,
  Eye,
  AlertTriangle
} from 'lucide-react';
import './HowItWorks.css';

const HowItWorks = () => {
  const analysisSteps = [
    {
      icon: Search,
      title: 'Discovery & Loading',
      description: 'Scan target (GitHub repo, local files, or config) and identify MCP components',
      details: [
        'Automatic file type detection',
        'MCP server configuration parsing', 
        'Tool signature extraction',
        'Dependency analysis'
      ]
    },
    {
      icon: Code,
      title: 'Static Analysis',
      description: 'Parse code structure using AST and pattern matching',
      details: [
        'Abstract Syntax Tree parsing',
        '50+ threat pattern detection',
        'Code flow analysis',
        'Import and dependency tracking'
      ]
    },
    {
      icon: Network,
      title: 'Taint Analysis',
      description: 'Track data flow and identify potential attack vectors',
      details: [
        'Inter-procedural analysis',
        'Data flow tracking',
        'Source-to-sink analysis',
        'User input validation'
      ]
    },
    {
      icon: Eye,
      title: 'Behavior Analysis',
      description: 'Detect suspicious patterns and anti-patterns',
      details: [
        'Obfuscation detection',
        'Suspicious function calls',
        'Privilege escalation patterns',
        'Network activity analysis'
      ]
    },
    {
      icon: Brain,
      title: 'AI Enhancement',
      description: 'ML models and LLM analysis for sophisticated threats',
      details: [
        'Semantic similarity analysis',
        'Context-aware detection',
        'False positive reduction',
        'Advanced pattern recognition'
      ]
    },
    {
      icon: Shield,
      title: 'Policy Evaluation',
      description: 'Check against security policies and generate report',
      details: [
        'Custom policy enforcement',
        'Compliance checking',
        'Risk scoring (0-100)',
        'Detailed recommendations'
      ]
    }
  ];

  const detectionMethods = [
    {
      method: 'Pattern Matching',
      description: 'Regex and AST-based detection of known attack patterns',
      effectiveness: 'High',
      examples: ['exec()', 'eval()', 'subprocess.call()'],
      color: 'success',
      note: 'Very effective for known patterns'
    },
    {
      method: 'Taint Analysis', 
      description: 'Track untrusted data flow through the application',
      effectiveness: 'Moderate',
      examples: ['user_input → exec()', 'request.data → file_write()'],
      color: 'info',
      note: 'Good for tracking data flows'
    },
    {
      method: 'Machine Learning',
      description: 'Ensemble models for semantic threat detection', 
      effectiveness: 'Experimental',
      examples: ['Obfuscated code', 'Subtle backdoors', 'Social engineering'],
      color: 'warning',
      note: 'When ML models are available'
    },
    {
      method: 'LLM Analysis',
      description: 'Large language model for context-aware detection',
      effectiveness: 'Optional',
      examples: ['Complex attack chains', 'Novel techniques', 'Intent analysis'],
      color: 'info',
      note: 'Requires Cerebras API key'
    }
  ];

  const architecture = [
    {
      layer: 'Input Layer',
      components: ['GitHub URLs', 'Local Files', 'MCP Configs'],
      description: 'Accept various input sources for analysis'
    },
    {
      layer: 'Processing Layer', 
      components: ['AST Parser', 'Pattern Engine', 'Taint Analyzer', 'ML Models'],
      description: 'Core analysis engines for threat detection'
    },
    {
      layer: 'Intelligence Layer',
      components: ['Threat Database', 'Signature Store', 'Policy Engine', 'LLM Interface'], 
      description: 'Knowledge base and advanced analysis capabilities'
    },
    {
      layer: 'Output Layer',
      components: ['Reports', 'Alerts', 'Recommendations', 'API Responses'],
      description: 'Formatted results and actionable insights'
    }
  ];

  return (
    <div className="how-it-works">
      <div className="section">
        <h2 className="section-title">
          <Zap className="section-icon" />
          Analysis Pipeline
        </h2>
        <p className="section-description">
          Our comprehensive security analysis follows a multi-stage pipeline designed to detect 
          both obvious and sophisticated threats in MCP tools.
        </p>
        
        <div className="pipeline">
          {analysisSteps.map((step, index) => {
            const Icon = step.icon;
            return (
              <div key={index} className="pipeline-step">
                <div className="step-header">
                  <div className="step-icon">
                    <Icon size={24} />
                  </div>
                  <div className="step-info">
                    <h3 className="step-title">{step.title}</h3>
                    <p className="step-description">{step.description}</p>
                  </div>
                  <div className="step-number">{index + 1}</div>
                </div>
                
                <div className="step-details">
                  <ul className="detail-list">
                    {step.details.map((detail, idx) => (
                      <li key={idx} className="detail-item">
                        <CheckCircle size={16} className="detail-check" />
                        {detail}
                      </li>
                    ))}
                  </ul>
                </div>
                
                {index < analysisSteps.length - 1 && (
                  <div className="pipeline-arrow">
                    <ArrowRight size={20} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div className="section">
        <h2 className="section-title">
          <Brain className="section-icon" />
          Detection Methods
        </h2>
        <p className="section-description">
          Multiple complementary detection techniques work together to achieve high accuracy 
          while minimizing false positives.
        </p>
        
        <div className="detection-grid">
          {detectionMethods.map((method, index) => (
            <div key={index} className="detection-card">
              <div className="detection-header">
                <h3 className="detection-title">{method.method}</h3>
                <div className={`effectiveness-badge effectiveness-${method.color}`}>
                  {method.effectiveness}
                </div>
              </div>
              
              <p className="detection-description">{method.description}</p>
              
              <div className="detection-examples">
                <h4 className="examples-title">Examples:</h4>
                <ul className="examples-list">
                  {method.examples.map((example, idx) => (
                    <li key={idx} className="example-item">
                      <code className="example-code">{example}</code>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="section">
        <h2 className="section-title">
          <FileText className="section-icon" />
          System Architecture
        </h2>
        <p className="section-description">
          Our modular architecture ensures scalability, maintainability, and extensibility 
          for new threat detection techniques.
        </p>
        
        <div className="architecture-diagram">
          {architecture.map((layer, index) => (
            <div key={index} className="architecture-layer">
              <div className="layer-header">
                <h3 className="layer-title">{layer.layer}</h3>
                <p className="layer-description">{layer.description}</p>
              </div>
              
              <div className="layer-components">
                {layer.components.map((component, idx) => (
                  <div key={idx} className="component-box">
                    {component}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="section">
        <div className="performance-metrics">
          <h2 className="section-title">
            <AlertTriangle className="section-icon" />
            Performance Metrics
          </h2>
          
          <div className="metrics-grid">
            <div className="metric-card">
              <div className="metric-value">100-200</div>
              <div className="metric-label">Files/Second</div>
              <div className="metric-description">Typical Scan Speed</div>
            </div>
            
            <div className="metric-card">
              <div className="metric-value">59</div>
              <div className="metric-label">Threat Patterns</div>
              <div className="metric-description">Active Detection Rules</div>
            </div>
            
            <div className="metric-card">
              <div className="metric-value">Context</div>
              <div className="metric-label">Aware Filtering</div>
              <div className="metric-description">Reduces False Positives</div>
            </div>
            
            <div className="metric-card">
              <div className="metric-value">OSS</div>
              <div className="metric-label">Open Source</div>
              <div className="metric-description">Community Driven</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HowItWorks;