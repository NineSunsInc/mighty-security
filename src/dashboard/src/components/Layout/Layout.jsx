import React from 'react';
import Header from './Header';
import Navigation from './Navigation';

const Layout = ({ children }) => {
  return (
    <div className="min-h-screen p-5">
      <div className="max-w-7xl mx-auto glass-card overflow-hidden">
        <Header />
        <Navigation />
        <main className="p-8 min-h-[calc(100vh-280px)]">
          <div className="animate-fade-in">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};

export default Layout;