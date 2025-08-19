import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { 
  Search, 
  FileText, 
  Clock, 
  Activity, 
  BookOpen,
  Zap
} from 'lucide-react';
import './Navigation.css';

const Navigation = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const navItems = [
    {
      path: '/scanner',
      label: 'Scanner',
      icon: Search,
      description: 'Run security scans'
    },
    {
      path: '/reports',
      label: 'Reports',
      icon: FileText,
      description: 'View scan results'
    },
    {
      path: '/history',
      label: 'History',
      icon: Clock,
      description: 'Audit trail'
    },
    {
      path: '/about',
      label: 'About',
      icon: BookOpen,
      description: 'Learn & protection'
    }
  ];

  return (
    <nav className="navigation">
      <div className="nav-list">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname.startsWith(item.path);
          
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${isActive ? 'nav-item-active' : ''}`}
            >
              <div className="nav-item-content">
                <Icon className="nav-icon" size={20} />
                <div className="nav-text">
                  <span className="nav-label">{item.label}</span>
                  <span className="nav-description">{item.description}</span>
                </div>
              </div>
              {isActive && <div className="nav-item-indicator" />}
            </Link>
          );
        })}
      </div>
      
      <div className="nav-quick-actions">
        <button 
          className="quick-action-btn"
          onClick={() => navigate('/scanner')}
        >
          <Zap size={16} />
          Quick Scan
        </button>
      </div>
    </nav>
  );
};

export default Navigation;