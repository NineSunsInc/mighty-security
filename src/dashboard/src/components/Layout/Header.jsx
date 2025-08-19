import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Activity, AlertTriangle, CheckCircle, Zap } from 'lucide-react';
import Logo from '../icons/Logo';

const Header = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState({
    totalScans: 0,
    activeThreats: 0,
    riskScore: 0,
    llmStatus: false
  });

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/stats');
      const data = await response.json();
      setStats({
        totalScans: data.recent_scans?.length || 0,
        activeThreats: data.statistics?.total_threats || 0,
        riskScore: calculateAverageRiskScore(data.recent_scans),
        llmStatus: data.llm_available || false
      });
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  const calculateAverageRiskScore = (scans) => {
    if (!scans || scans.length === 0) return 0;
    const total = scans.reduce((sum, scan) => sum + (scan.threat_score || 0), 0);
    return Math.round(total / scans.length);
  };

  const getRiskLevel = (score) => {
    if (score >= 80) return { level: 'CRITICAL', color: 'critical' };
    if (score >= 60) return { level: 'HIGH', color: 'high' };
    if (score >= 40) return { level: 'MEDIUM', color: 'medium' };
    if (score >= 20) return { level: 'LOW', color: 'low' };
    return { level: 'SAFE', color: 'safe' };
  };

  const risk = getRiskLevel(stats.riskScore);

  return (
    <header className="relative overflow-hidden bg-gradient-to-r from-vividSkyBlue via-darkBlue to-vividSkyBlue shadow-xl">
      {/* Beautiful animated background */}
      <div className="absolute inset-0 bg-gradient-to-r from-vividSkyBlue via-darkBlue to-vividSkyBlue opacity-90"></div>
      <div className="absolute inset-0">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-white rounded-full mix-blend-overlay opacity-10 blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-yellow-300 rounded-full mix-blend-overlay opacity-10 blur-3xl animate-pulse" style={{animationDelay: '2s'}}></div>
      </div>
      
      <div className="relative z-10 px-8 py-8">
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-8">
          {/* Brand Section */}
          <div className="flex items-center gap-6">
            <div className="relative group">
              <div className="absolute inset-0 bg-goldenYellow rounded-2xl blur-xl opacity-30 group-hover:opacity-50 transition-all duration-300"></div>
              <div className="relative bg-white/95 backdrop-blur-md p-4 rounded-2xl shadow-2xl border-2 border-goldenYellow group-hover:scale-110 transition-transform duration-300">
                <img src="/static/mighty-icon.png" alt="Mighty" className="w-20 h-20 object-contain" />
              </div>
            </div>
            <div>
              <h1 className="text-5xl font-bold text-white drop-shadow-2xl mb-2 tracking-tight">
                Mighty MCP Security
              </h1>
              <p className="text-xl text-white/90 drop-shadow-lg font-medium">
                Advanced Model Context Protocol Protection
              </p>
              <p className="text-sm text-white/70 mt-1">
                A Mighty OSS Project by Nine Suns, Inc. • <a href="https://mightynetwork.ai" target="_blank" rel="noopener noreferrer" className="underline hover:text-goldenYellow transition-colors">mightynetwork.ai</a>
              </p>
            </div>
          </div>
          
          {/* Stats Grid */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 w-full lg:w-auto">
            {/* Total Scans */}
            <div className="bg-white/20 backdrop-blur-md rounded-2xl p-6 text-center hover:scale-105 transition-all cursor-pointer group border border-white/30 hover:bg-white/30">
              <div className="bg-gradient-to-br from-blue-400 to-blue-600 w-12 h-12 rounded-xl flex items-center justify-center mx-auto mb-3 shadow-lg">
                <Activity className="w-6 h-6 text-white" />
              </div>
              <div className="text-3xl font-bold text-white mb-1 drop-shadow">{stats.totalScans}</div>
              <div className="text-sm text-white/90 font-medium">Total Scans</div>
              <div className="text-xs mt-1 text-white/70">Files analyzed</div>
            </div>
            
            {/* Active Threats */}
            <div className="bg-white/20 backdrop-blur-md rounded-2xl p-6 text-center hover:scale-105 transition-all cursor-pointer group border border-white/30 hover:bg-white/30">
              <div className="bg-gradient-to-br from-red-400 to-red-600 w-12 h-12 rounded-xl flex items-center justify-center mx-auto mb-3 shadow-lg">
                <AlertTriangle className="w-6 h-6 text-white" />
              </div>
              <div className="text-3xl font-bold text-white mb-1 drop-shadow">{stats.activeThreats}</div>
              <div className="text-sm text-white/90 font-medium">Active Threats</div>
              <div className="text-xs mt-1 text-white/70">Security issues</div>
            </div>
            
            {/* Risk Score */}
            <div className="bg-white/20 backdrop-blur-md rounded-2xl p-6 text-center hover:scale-105 transition-all cursor-pointer group border border-white/30 hover:bg-white/30">
              <div className={`w-12 h-12 mx-auto mb-3 rounded-xl flex items-center justify-center text-lg font-bold text-white shadow-lg ${
                risk.color === 'critical' ? 'bg-gradient-to-br from-red-500 to-red-600' :
                  risk.color === 'high' ? 'bg-gradient-to-br from-orange-500 to-orange-600' :
                    risk.color === 'medium' ? 'bg-gradient-to-br from-yellow-500 to-yellow-600' :
                      risk.color === 'low' ? 'bg-gradient-to-br from-green-500 to-green-600' : 
                        'bg-gradient-to-br from-emerald-500 to-emerald-600'
              }`}>
                {stats.riskScore}
              </div>
              <div className="text-xl font-bold text-white mb-1 drop-shadow">{risk.level}</div>
              <div className="text-xs text-white/70">Risk Level</div>
            </div>
            
            {/* AI Status */}
            <div className="bg-white/20 backdrop-blur-md rounded-2xl p-6 text-center hover:scale-105 transition-all cursor-pointer group border border-white/30 hover:bg-white/30">
              <div className={`w-12 h-12 rounded-xl flex items-center justify-center mx-auto mb-3 shadow-lg ${
                stats.llmStatus ? 
                  'bg-gradient-to-br from-green-400 to-emerald-600' : 
                  'bg-gradient-to-br from-gray-400 to-gray-600'
              }`}>
                {stats.llmStatus ? (
                  <Zap className="w-6 h-6 text-white" />
                ) : (
                  <AlertTriangle className="w-6 h-6 text-white" />
                )}
              </div>
              <div className="text-xl font-bold text-white mb-1 drop-shadow">
                {stats.llmStatus ? 'Online' : 'Offline'}
              </div>
              <div className="text-xs text-white/70">AI Analysis</div>
            </div>
          </div>
        </div>
        
        {/* Quick Actions */}
        <div className="mt-6 flex flex-wrap gap-3">
          <button 
            onClick={() => navigate('/scanner')}
            className="group flex items-center gap-2 px-6 py-3 bg-white text-indigo-600 hover:bg-white/90 rounded-xl transition-all duration-200 shadow-lg hover:shadow-xl hover:scale-105 font-semibold">
            <Zap className="w-4 h-4" />
            <span className="text-sm">Quick Scan</span>
          </button>
          <button 
            onClick={() => navigate('/reports')}
            className="group flex items-center gap-2 px-6 py-3 bg-white/20 hover:bg-white/30 rounded-xl transition-all duration-200 backdrop-blur-sm border border-white/30 hover:border-white/40 hover:scale-105">
            <Activity className="w-4 h-4 text-white" />
            <span className="text-sm font-semibold text-white">View Reports</span>
          </button>
        </div>
      </div>
    </header>
  );
};

export default Header;