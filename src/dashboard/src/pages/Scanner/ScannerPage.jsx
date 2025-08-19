import React, { useState, useEffect } from 'react';
import { Search, Github, FolderOpen, Zap, Settings, Play, AlertTriangle, CheckCircle, Info, Shield, Lock, Activity, TrendingUp, FileSearch, Code, Eye, Sparkles, Target, ChevronRight } from 'lucide-react';

const ScannerPage = () => {
  const [selectedMode, setSelectedMode] = useState('github');
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [enableLLM, setEnableLLM] = useState(false);
  const [deepScan, setDeepScan] = useState(true);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState(0);
  const [scanAnimation, setScanAnimation] = useState(false);
  const [advancedMode, setAdvancedMode] = useState(false);
  const [scanProfile, setScanProfile] = useState('production');
  const [verbose, setVerbose] = useState(false);
  const [includeTests, setIncludeTests] = useState(false);

  const scanModes = [
    {
      id: 'github',
      name: 'GitHub Repository',
      icon: Github,
      description: 'Scan any GitHub repository for security threats',
      placeholder: 'https://github.com/user/repo',
      color: 'from-purple-500 to-indigo-600'
    },
    {
      id: 'local',
      name: 'Local Directory',
      icon: FolderOpen,
      description: 'Scan files or directories on your computer',
      placeholder: '/path/to/directory',
      color: 'from-blue-500 to-cyan-600'
    },
    {
      id: 'quick',
      name: 'Quick Scan',
      icon: Zap,
      description: 'Fast scan with basic threat detection',
      placeholder: 'GitHub URL or local path',
      color: 'from-amber-500 to-orange-600'
    }
  ];

  const handleScan = async () => {
    setLoading(true);
    setError(null);
    setScanResults(null);
    setProgress(10);
    setScanAnimation(true);

    try {
      let endpoint = '';
      const requestBody = {
        enable_llm: enableLLM,
        deep_scan: deepScan,
        profile: scanProfile,
        verbose: verbose,
        include_tests: includeTests
      };

      // Determine the correct endpoint based on mode and target
      if (selectedMode === 'github' || (selectedMode === 'quick' && target.includes('github.com'))) {
        endpoint = '/api/scan/github';
        requestBody.repo_url = target;
        if (selectedMode === 'quick') {
          requestBody.quick_mode = true;
        }
      } else if (selectedMode === 'local' || selectedMode === 'quick') {
        endpoint = '/api/scan/local';
        requestBody.target_path = target;
        if (selectedMode === 'quick') {
          requestBody.quick_mode = true;
        }
      }

      setProgress(30);

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      setProgress(70);

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Scan failed');
      }

      const result = await response.json();
      setProgress(100);
      setScanResults(result);
      setTimeout(() => setScanAnimation(false), 500);
      
    } catch (err) {
      console.error('Scan error:', err);
      setError(err.message || 'An error occurred during scanning');
      setProgress(0);
    } finally {
      setLoading(false);
      setTimeout(() => setScanAnimation(false), 500);
    }
  };

  const getThreatLevel = (score) => {
    const numScore = parseFloat(score);
    if (numScore >= 80) return { 
      level: 'CRITICAL', 
      color: 'bg-red-100 text-red-700 border-red-300',
      bgGradient: 'from-red-500 to-pink-600',
      textColor: 'text-red-700',
      icon: '🔴',
      pulse: true
    };
    if (numScore >= 60) return { 
      level: 'HIGH', 
      color: 'bg-orange-100 text-orange-700 border-orange-300',
      bgGradient: 'from-orange-500 to-amber-600',
      textColor: 'text-orange-700',
      icon: '🟠',
      pulse: false
    };
    if (numScore >= 40) return { 
      level: 'MEDIUM', 
      color: 'bg-yellow-100 text-yellow-700 border-yellow-300',
      bgGradient: 'from-yellow-500 to-amber-500',
      textColor: 'text-yellow-700',
      icon: '🟡',
      pulse: false
    };
    if (numScore >= 20) return { 
      level: 'LOW', 
      color: 'bg-blue-100 text-blue-700 border-blue-300',
      bgGradient: 'from-blue-500 to-cyan-600',
      textColor: 'text-blue-700',
      icon: '🔵',
      pulse: false
    };
    return { 
      level: 'SAFE', 
      color: 'bg-green-100 text-green-700 border-green-300',
      bgGradient: 'from-green-500 to-emerald-600',
      textColor: 'text-green-700',
      icon: '🟢',
      pulse: false
    };
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-gray-50">
      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Header Section */}
        <div className="mb-10">
          <div className="flex items-center gap-4 mb-2">
            <div className="p-3 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl shadow-lg">
              <Shield className="text-white" size={28} />
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
                Security Scanner
              </h1>
              <p className="text-gray-600 mt-1">
                Analyze MCP tools and repositories for security vulnerabilities
              </p>
            </div>
          </div>
        </div>

        {/* Scan Modes Section */}
        <div className="mb-8">
          <h2 className="text-xl font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <Target className="text-indigo-500" size={20} />
            Select Scan Mode
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {scanModes.map((mode) => {
              const Icon = mode.icon;
              return (
                <button
                  key={mode.id}
                  onClick={() => setSelectedMode(mode.id)}
                  className={`relative p-6 rounded-2xl border-2 transition-all duration-300 ${
                    selectedMode === mode.id
                      ? 'border-indigo-500 bg-gradient-to-br from-indigo-50 to-purple-50 shadow-lg scale-105'
                      : 'border-gray-200 bg-white hover:border-gray-300 hover:shadow-md'
                  }`}
                >
                  {selectedMode === mode.id && (
                    <div className="absolute top-3 right-3">
                      <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    </div>
                  )}
                  <div className="flex flex-col items-center text-center">
                    <div className={`p-3 rounded-xl mb-3 bg-gradient-to-br ${mode.color}`}>
                      <Icon className="text-white" size={24} />
                    </div>
                    <h3 className="font-semibold text-gray-900 mb-1">{mode.name}</h3>
                    <p className="text-sm text-gray-600">{mode.description}</p>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Configuration Section */}
        <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 mb-8">
          <h2 className="text-xl font-semibold text-gray-800 mb-6 flex items-center gap-2">
            <Settings className="text-indigo-500" size={20} />
            Scan Configuration
          </h2>
          
          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Target Location
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder={scanModes.find(m => m.id === selectedMode)?.placeholder}
                  className="w-full px-4 py-3 pl-12 border-2 border-gray-200 rounded-xl focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 transition-all"
                />
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" size={18} />
              </div>
            </div>

            <div className="flex flex-col sm:flex-row gap-4">
              <label className="flex items-center gap-3 p-4 rounded-xl bg-gradient-to-r from-indigo-50 to-purple-50 cursor-pointer hover:from-indigo-100 hover:to-purple-100 transition-all">
                <input
                  type="checkbox"
                  checked={deepScan}
                  onChange={(e) => setDeepScan(e.target.checked)}
                  className="w-5 h-5 text-indigo-600 rounded focus:ring-indigo-500"
                />
                <div className="flex items-center gap-2">
                  <Eye className="text-indigo-500" size={18} />
                  <span className="font-medium text-gray-700">Deep Scan Mode</span>
                </div>
              </label>

              <label className="flex items-center gap-3 p-4 rounded-xl bg-gradient-to-r from-amber-50 to-orange-50 cursor-pointer hover:from-amber-100 hover:to-orange-100 transition-all">
                <input
                  type="checkbox"
                  checked={advancedMode}
                  onChange={(e) => setAdvancedMode(e.target.checked)}
                  className="w-5 h-5 text-amber-600 rounded focus:ring-amber-500"
                />
                <div className="flex items-center gap-2">
                  <Settings className="text-amber-500" size={18} />
                  <span className="font-medium text-gray-700">Advanced Mode</span>
                </div>
              </label>
            </div>

            {/* Advanced Options - only show when advanced mode is enabled */}
            {advancedMode && (
              <div className="mt-6 p-6 bg-gradient-to-r from-gray-50 to-gray-100 rounded-xl border border-gray-200">
                <h3 className="text-sm font-semibold text-gray-700 mb-4 flex items-center gap-2">
                  <Code size={16} />
                  Advanced CLI Options
                </h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-600 mb-2">
                      Scan Profile
                    </label>
                    <select
                      value={scanProfile}
                      onChange={(e) => setScanProfile(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    >
                      <option value="production">Production (Strictest)</option>
                      <option value="development">Development (Balanced)</option>
                      <option value="security-tool">Security Tool (Special)</option>
                    </select>
                    <p className="text-xs text-gray-500 mt-1">
                      Controls false positive filtering based on context
                    </p>
                  </div>

                  <div className="space-y-3">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={enableLLM}
                        onChange={(e) => setEnableLLM(e.target.checked)}
                        className="w-4 h-4 text-purple-600 rounded"
                      />
                      <div className="flex items-center gap-2">
                        <Sparkles className="text-purple-500" size={16} />
                        <span className="text-sm font-medium text-gray-700">Enable LLM Analysis</span>
                      </div>
                    </label>

                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={verbose}
                        onChange={(e) => setVerbose(e.target.checked)}
                        className="w-4 h-4 text-blue-600 rounded"
                      />
                      <span className="text-sm font-medium text-gray-700">Verbose Output</span>
                    </label>

                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={includeTests}
                        onChange={(e) => setIncludeTests(e.target.checked)}
                        className="w-4 h-4 text-green-600 rounded"
                      />
                      <span className="text-sm font-medium text-gray-700">Include Test Files</span>
                    </label>
                  </div>
                </div>

                <div className="mt-4 p-3 bg-blue-50 rounded-lg">
                  <p className="text-xs text-blue-700">
                    <strong>CLI Equivalent:</strong> 
                    <code className="ml-2 bg-white px-2 py-1 rounded">
                      python3 mighty_mcp.py check {target} 
                      {scanProfile !== 'production' && ` --profile ${scanProfile}`}
                      {enableLLM && ' --llm'}
                      {verbose && ' --verbose'}
                      {includeTests && ' --include-tests'}
                      {!deepScan && ' --quick'}
                    </code>
                  </p>
                </div>
              </div>
            )}

            <button
              onClick={handleScan}
              disabled={!target || loading}
              className={`w-full sm:w-auto px-8 py-4 rounded-xl font-semibold text-white transition-all duration-300 flex items-center justify-center gap-3 ${
                loading
                  ? 'bg-gradient-to-r from-indigo-400 to-purple-500 cursor-wait'
                  : 'bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5'
              } disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:transform-none`}
            >
              {loading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Play size={20} />
                  <span>Start Security Scan</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Progress Bar */}
        {loading && (
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 mb-8">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <Shield className="text-indigo-600 animate-pulse" size={24} />
                <div>
                  <div className="font-semibold text-gray-800">Security Analysis in Progress</div>
                  <div className="text-sm text-gray-600">Scanning for vulnerabilities...</div>
                </div>
              </div>
              <div className="text-2xl font-bold text-indigo-600">{progress}%</div>
            </div>
            <div className="h-3 bg-gray-200 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-indigo-500 to-purple-600 rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="bg-red-50 border-2 border-red-200 rounded-2xl p-6 mb-8">
            <div className="flex items-center gap-3">
              <AlertTriangle className="text-red-600" size={24} />
              <div>
                <div className="font-semibold text-red-800">Scan Error</div>
                <p className="text-red-700 mt-1">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Results Section */}
        {scanResults && (
          <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-600">Threat Score</span>
                  <span className="text-3xl">{getThreatLevel(scanResults.threat_score || '0').icon}</span>
                </div>
                <div className={`text-3xl font-bold ${getThreatLevel(scanResults.threat_score || '0').textColor}`}>
                  {scanResults.threat_score || '0'}%
                </div>
              </div>

              <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
                <div className="text-sm font-medium text-gray-600 mb-2">Threat Level</div>
                <div className={`inline-block px-4 py-2 rounded-xl font-semibold ${getThreatLevel(scanResults.threat_score || '0').color}`}>
                  {scanResults.threat_level || getThreatLevel(scanResults.threat_score || '0').level}
                </div>
              </div>

              <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
                <div className="text-sm font-medium text-gray-600 mb-2">Files Analyzed</div>
                <div className="text-3xl font-bold text-gray-800">
                  {scanResults.total_files || 0}
                </div>
              </div>
            </div>

            {/* Threats List */}
            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
              {scanResults.threats && scanResults.threats.length > 0 ? (
                <>
                  <h3 className="text-xl font-semibold text-gray-800 mb-6 flex items-center gap-3">
                    <AlertTriangle className="text-orange-500" size={24} />
                    Security Threats Detected
                    <span className="px-3 py-1 bg-orange-100 text-orange-700 rounded-full text-sm font-medium">
                      {scanResults.threats.length}
                    </span>
                  </h3>
                  <div className="space-y-4">
                    {scanResults.threats.map((threat, index) => (
                      <div key={index} className="border-2 border-gray-200 rounded-xl p-5 hover:border-indigo-300 transition-all">
                        <div className="flex justify-between items-start mb-3">
                          <h4 className="font-semibold text-gray-800">
                            {threat.attack_vector || threat.type || 'Security Issue'}
                          </h4>
                          <span className={`px-3 py-1 rounded-lg text-xs font-semibold ${
                            threat.severity === 'CRITICAL' ? 'bg-red-100 text-red-700' :
                              threat.severity === 'HIGH' ? 'bg-orange-100 text-orange-700' :
                                threat.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-700' :
                                  'bg-blue-100 text-blue-700'
                          }`}>
                            {threat.severity || 'MEDIUM'}
                          </span>
                        </div>
                        <p className="text-gray-600 mb-3">{threat.description}</p>
                        {threat.file_path && (
                          <div className="text-sm text-gray-500 flex items-center gap-2">
                            <Code size={14} />
                            <code className="bg-gray-100 px-2 py-1 rounded">{threat.file_path}</code>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="text-center py-8">
                  <CheckCircle className="text-green-500 mx-auto mb-4" size={48} />
                  <h3 className="text-2xl font-semibold text-green-700 mb-2">All Clear!</h3>
                  <p className="text-gray-600">No security threats detected. Your code is secure!</p>
                </div>
              )}
            </div>

            {/* Fingerprints */}
            {scanResults.fingerprints && (
              <div className="bg-gray-50 rounded-2xl border border-gray-200 p-6">
                <h4 className="font-semibold text-gray-700 mb-4 flex items-center gap-2">
                  <Lock size={18} />
                  Security Fingerprints
                </h4>
                <div className="space-y-2 font-mono text-sm">
                  {scanResults.fingerprints.sha512 && (
                    <div className="flex items-center gap-3">
                      <span className="text-gray-500">SHA-512:</span>
                      <span className="text-gray-700 truncate">{scanResults.fingerprints.sha512}</span>
                    </div>
                  )}
                  {scanResults.fingerprints.merkle_root && (
                    <div className="flex items-center gap-3">
                      <span className="text-gray-500">Merkle:</span>
                      <span className="text-gray-700 truncate">{scanResults.fingerprints.merkle_root}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ScannerPage;