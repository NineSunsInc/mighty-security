import React from 'react';

const Logo = ({ className = 'w-12 h-12', color = 'currentColor' }) => {
  return (
    <svg 
      className={className} 
      viewBox="0 0 100 100" 
      fill="none" 
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* Shield background with gradient */}
      <defs>
        <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#667eea" />
          <stop offset="50%" stopColor="#5e72e4" />
          <stop offset="100%" stopColor="#48bfe3" />
        </linearGradient>
        <linearGradient id="lockGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#ffffff" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#ffffff" stopOpacity="0.7" />
        </linearGradient>
      </defs>
      
      {/* Shield shape */}
      <path 
        d="M50 5 L85 20 L85 55 C85 70 75 85 50 95 C25 85 15 70 15 55 L15 20 Z" 
        fill="url(#shieldGradient)"
        stroke="white"
        strokeWidth="2"
        strokeOpacity="0.3"
      />
      
      {/* Inner shield highlight */}
      <path 
        d="M50 15 L75 25 L75 52 C75 62 68 72 50 80 C32 72 25 62 25 52 L25 25 Z" 
        fill="url(#lockGradient)"
        opacity="0.2"
      />
      
      {/* Lock icon in center */}
      <g transform="translate(35, 35)">
        {/* Lock body */}
        <rect 
          x="5" 
          y="15" 
          width="20" 
          height="18" 
          rx="2" 
          fill="white"
          fillOpacity="0.9"
        />
        {/* Lock shackle */}
        <path 
          d="M9 15 L9 10 C9 6 11 3 15 3 C19 3 21 6 21 10 L21 15" 
          stroke="white"
          strokeWidth="3"
          strokeLinecap="round"
          fill="none"
          strokeOpacity="0.9"
        />
        {/* Keyhole */}
        <circle cx="15" cy="22" r="2" fill="url(#shieldGradient)" />
        <rect x="14" y="23" width="2" height="5" fill="url(#shieldGradient)" />
      </g>
      
      {/* Subtle glow effect */}
      <circle cx="50" cy="50" r="45" fill="white" opacity="0.1" filter="blur(10px)" />
    </svg>
  );
};

export default Logo;