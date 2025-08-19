import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Clock, Search, Filter, RefreshCw, Shield, Info, CheckCircle, ExternalLink, Calendar, User, Settings, FileText } from 'lucide-react';

const HistoryPage = () => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState('all');

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      // Fetch real stats which includes recent scans
      const response = await fetch('/api/stats');
      const data = await response.json();
      
      // Transform recent scans into history format
      const historyItems = [];
      
      if (data.recent_scans && data.recent_scans.length > 0) {
        data.recent_scans.forEach((scan, index) => {
          // Clean up the target display
          let targetDisplay = scan.repo_name || scan.repo_url || 'Local Scan';
          
          // If it's a temp path, extract just the repo name if available
          if (targetDisplay.includes('/tmp/') || targetDisplay.includes('/var/folders/')) {
            // Try to extract the GitHub repo from the scan
            if (scan.repo_name && scan.repo_name !== targetDisplay) {
              targetDisplay = scan.repo_name;
            } else {
              targetDisplay = 'Local Repository Scan';
            }
          }
          
          // Add scan completed event
          historyItems.push({
            id: `scan-${scan.run_id || index}`,
            timestamp: scan.timestamp || new Date().toISOString(),
            action: 'scan_completed',
            user: 'system',
            target: targetDisplay,
            scanType: scan.scan_type || 'static',
            result: scan.threat_level === 'CRITICAL' || scan.threat_level === 'HIGH' ? 'warning' : 'success',
            details: `Found ${scan.total_threats || 0} threats, risk score: ${scan.threat_score || 0}`,
            threatScore: scan.threat_score || 0,
            threatLevel: scan.threat_level || 'MINIMAL',
            totalThreats: scan.total_threats || 0
          });
        });
      }
      
      // Add some default entries if no scans yet
      if (historyItems.length === 0) {
        historyItems.push({
          id: 'welcome',
          timestamp: new Date().toISOString(),
          action: 'system_started',
          user: 'system',
          target: 'Dashboard',
          result: 'success',
          details: 'Security dashboard initialized'
        });
      }
      
      setHistory(historyItems);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch history:', error);
      setLoading(false);
    }
  };

  const getActionIcon = (action) => {
    switch (action) {
    case 'scan_started':
    case 'scan_completed':
      return <Shield className="w-5 h-5" />;
    case 'config_updated':
      return <Settings className="w-5 h-5" />;
    case 'policy_updated':
      return <FileText className="w-5 h-5" />;
    case 'system_started':
      return <CheckCircle className="w-5 h-5" />;
    default:
      return <Info className="w-5 h-5" />;
    }
  };

  const getResultColor = (result, threatLevel) => {
    if (threatLevel) {
      switch (threatLevel) {
      case 'CRITICAL': return 'text-red-600 bg-red-50 border-red-200';
      case 'HIGH': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'LOW': return 'text-blue-600 bg-blue-50 border-blue-200';
      case 'MINIMAL': return 'text-green-600 bg-green-50 border-green-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
      }
    }
    switch (result) {
    case 'success': return 'text-green-600 bg-green-50 border-green-200';
    case 'warning': return 'text-orange-600 bg-orange-50 border-orange-200';
    case 'failure': return 'text-red-600 bg-red-50 border-red-200';
    default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const formatAction = (action) => {
    return action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  const filteredHistory = history
    .filter(item => 
      (actionFilter === 'all' || item.action.includes(actionFilter)) &&
      (searchTerm === '' || 
       item.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
       item.details.toLowerCase().includes(searchTerm.toLowerCase())
      )
    );

  return (
    <div className="history-page">
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <div className="p-4 bg-darkBlue rounded-xl">
            <Clock className="text-white" size={32} />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Audit History</h1>
            <p className="text-gray-600 mt-1">
              Complete audit trail of all security scanner activities and changes
            </p>
          </div>
        </div>
        
        <button 
          onClick={fetchHistory}
          className="px-4 py-2 bg-goldenYellow hover:bg-lightBurntOrange text-mighty-dark-gray rounded-lg transition-colors flex items-center gap-2 font-medium"
        >
          <RefreshCw size={18} />
          Refresh
        </button>
      </div>

      <div className="flex flex-col md:flex-row gap-4 mb-6">
        <div className="flex-1">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={20} />
            <input
              type="text"
              className="w-full pl-10 pr-4 py-2 border-2 border-gray-200 rounded-lg focus:border-vividSkyBlue focus:outline-none"
              placeholder="Search history..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Filter className="text-gray-500" size={20} />
          <select
            className="px-4 py-2 border-2 border-gray-200 rounded-lg focus:border-vividSkyBlue focus:outline-none"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
          >
            <option value="all">All Actions</option>
            <option value="scan">Scans</option>
            <option value="config">Configuration</option>
            <option value="policy">Policy Changes</option>
            <option value="system">System Events</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-12">
          <div className="w-12 h-12 border-4 border-vividSkyBlue border-t-transparent rounded-full animate-spin" />
          <p className="mt-4 text-gray-600">Loading history...</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredHistory.length > 0 ? (
            <div className="relative">
              {/* Timeline line */}
              <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-gradient-to-b from-vividSkyBlue via-darkBlue to-transparent"></div>
              
              {filteredHistory.map((item, index) => (
                <div key={item.id} className="relative flex gap-6 pb-8 last:pb-0">
                  {/* Timeline dot */}
                  <div className="relative z-10">
                    <div className={`w-16 h-16 rounded-full flex items-center justify-center shadow-lg ${
                      item.threatLevel === 'CRITICAL' || item.threatLevel === 'HIGH' 
                        ? 'bg-gradient-to-br from-red-400 to-orange-500' 
                        : item.threatLevel === 'MEDIUM'
                          ? 'bg-gradient-to-br from-yellow-400 to-orange-400'
                          : 'bg-gradient-to-br from-vividSkyBlue to-darkBlue'
                    }`}>
                      {getActionIcon(item.action)}
                    </div>
                  </div>
                  
                  {/* Content card */}
                  <div className={`flex-1 bg-white rounded-xl border-2 p-6 hover:shadow-lg transition-all ${getResultColor(item.result, item.threatLevel).split(' ')[2]}`}>
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h3 className="text-lg font-semibold text-gray-900 mb-1">
                          {formatAction(item.action)}
                        </h3>
                        <div className="flex items-center gap-4 text-sm text-gray-500">
                          <span className="flex items-center gap-1">
                            <Calendar size={14} />
                            {new Date(item.timestamp).toLocaleDateString()}
                          </span>
                          <span className="flex items-center gap-1">
                            <Clock size={14} />
                            {new Date(item.timestamp).toLocaleTimeString()}
                          </span>
                          <span className="flex items-center gap-1">
                            <User size={14} />
                            {item.user}
                          </span>
                        </div>
                      </div>
                      
                      {item.threatLevel && (
                        <span className={`px-3 py-1 rounded-full text-sm font-medium ${getResultColor(item.result, item.threatLevel).split(' ').slice(0, 2).join(' ')}`}>
                          {item.threatLevel}
                        </span>
                      )}
                    </div>
                    
                    <div className="border-t pt-3">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                          <span className="text-sm text-gray-500">Target</span>
                          <p className="font-medium text-gray-900">{item.target}</p>
                        </div>
                        
                        {item.threatScore !== undefined && (
                          <div>
                            <span className="text-sm text-gray-500">Risk Score</span>
                            <div className="flex items-baseline gap-1">
                              <span className="text-2xl font-bold text-vividSkyBlue">{Math.round(item.threatScore)}</span>
                              <span className="text-gray-400">/100</span>
                            </div>
                          </div>
                        )}
                        
                        {item.totalThreats !== undefined && (
                          <div>
                            <span className="text-sm text-gray-500">Threats Found</span>
                            <p className="text-2xl font-bold text-burntOrange">{item.totalThreats}</p>
                          </div>
                        )}
                      </div>
                      
                      {item.details && (
                        <div className="mt-3 pt-3 border-t">
                          <p className="text-sm text-gray-600">{item.details}</p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-naturalLight rounded-xl p-12 text-center">
              <div className="inline-flex items-center justify-center w-20 h-20 bg-white rounded-full mb-4">
                <Clock size={32} className="text-gray-400" />
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">No History Found</h3>
              <p className="text-gray-600 mb-6">No audit history matches your current filters.</p>
              <Link 
                to="/scanner"
                className="inline-flex items-center gap-2 px-6 py-3 bg-vividSkyBlue hover:bg-darkBlue text-white rounded-lg transition-colors"
              >
                <Shield size={20} />
                Start Your First Scan
              </Link>
            </div>
          )}
        </div>
      )}
      
      <div className="mt-8 p-4 bg-naturalLight rounded-lg border border-beige">
        <div className="flex items-center justify-between">
          <p className="text-sm text-mighty-dark-gray">
            <strong>Mighty MCP Security</strong> • A Nine Suns, Inc. OSS Project
          </p>
          <div className="flex items-center gap-4">
            <Link to="/about/threats-protection" className="text-sm text-vividSkyBlue hover:text-darkBlue underline">
              Learn about Risk Scores
            </Link>
            <a href="https://mightynetwork.ai" target="_blank" rel="noopener noreferrer" className="text-sm text-vividSkyBlue hover:text-darkBlue underline inline-flex items-center gap-1">
              mightynetwork.ai <ExternalLink size={12} />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HistoryPage;