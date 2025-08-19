import React, { createContext, useContext, useReducer } from 'react';

const AppContext = createContext();

const initialState = {
  user: null,
  settings: {
    theme: 'light',
    autoRefresh: true,
    notifications: true
  },
  notifications: [],
  loading: false,
  error: null
};

const appReducer = (state, action) => {
  switch (action.type) {
  case 'SET_LOADING':
    return { ...state, loading: action.payload };
    
  case 'SET_ERROR':
    return { ...state, error: action.payload, loading: false };
    
  case 'CLEAR_ERROR':
    return { ...state, error: null };
    
  case 'ADD_NOTIFICATION':
    return {
      ...state,
      notifications: [
        ...state.notifications,
        { id: Date.now(), ...action.payload }
      ]
    };
    
  case 'REMOVE_NOTIFICATION':
    return {
      ...state,
      notifications: state.notifications.filter(n => n.id !== action.payload)
    };
    
  case 'UPDATE_SETTINGS':
    return {
      ...state,
      settings: { ...state.settings, ...action.payload }
    };
    
  default:
    return state;
  }
};

export const AppProvider = ({ children }) => {
  const [state, dispatch] = useReducer(appReducer, initialState);

  const setLoading = (loading) => {
    dispatch({ type: 'SET_LOADING', payload: loading });
  };

  const setError = (error) => {
    dispatch({ type: 'SET_ERROR', payload: error });
  };

  const clearError = () => {
    dispatch({ type: 'CLEAR_ERROR' });
  };

  const addNotification = (notification) => {
    dispatch({ type: 'ADD_NOTIFICATION', payload: notification });
    
    // Auto-remove after 5 seconds for info/success
    if (notification.type !== 'error') {
      setTimeout(() => {
        dispatch({ type: 'REMOVE_NOTIFICATION', payload: notification.id || Date.now() });
      }, 5000);
    }
  };

  const removeNotification = (id) => {
    dispatch({ type: 'REMOVE_NOTIFICATION', payload: id });
  };

  const updateSettings = (settings) => {
    dispatch({ type: 'UPDATE_SETTINGS', payload: settings });
  };

  const value = {
    ...state,
    setLoading,
    setError,
    clearError,
    addNotification,
    removeNotification,
    updateSettings
  };

  return (
    <AppContext.Provider value={value}>
      {children}
    </AppContext.Provider>
  );
};

export const useApp = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};