import React, { createContext, useContext, useReducer, useEffect } from 'react';

const TaskContext = createContext();

const initialState = {
  tasks: [],
  activeTasks: [],
  completedTasks: [],
  taskHistory: []
};

const taskReducer = (state, action) => {
  switch (action.type) {
  case 'ADD_TASK':
    return {
      ...state,
      tasks: [...state.tasks, action.payload],
      activeTasks: [...state.activeTasks, action.payload]
    };
    
  case 'UPDATE_TASK': {
    const updatedTasks = state.tasks.map(task =>
      task.id === action.payload.id ? { ...task, ...action.payload } : task
    );
      
    return {
      ...state,
      tasks: updatedTasks,
      activeTasks: updatedTasks.filter(t => ['running', 'queued'].includes(t.status)),
      completedTasks: updatedTasks.filter(t => ['completed', 'failed', 'cancelled'].includes(t.status))
    };
  }
    
  case 'REMOVE_TASK': {
    const filteredTasks = state.tasks.filter(task => task.id !== action.payload);
    return {
      ...state,
      tasks: filteredTasks,
      activeTasks: filteredTasks.filter(t => ['running', 'queued'].includes(t.status)),
      completedTasks: filteredTasks.filter(t => ['completed', 'failed', 'cancelled'].includes(t.status))
    };
  }
    
  case 'SET_TASKS': {
    const tasksArray = Array.isArray(action.payload) ? action.payload : [];
    return {
      ...state,
      tasks: tasksArray,
      activeTasks: tasksArray.filter(t => ['running', 'queued'].includes(t.status)),
      completedTasks: tasksArray.filter(t => ['completed', 'failed', 'cancelled'].includes(t.status))
    };
  }
    
  case 'ADD_TASK_LOG':
    return {
      ...state,
      tasks: state.tasks.map(task =>
        task.id === action.payload.taskId
          ? { ...task, logs: [...(task.logs || []), action.payload.log] }
          : task
      )
    };
    
  default:
    return state;
  }
};

export const TaskProvider = ({ children }) => {
  const [state, dispatch] = useReducer(taskReducer, initialState);

  const addTask = (task) => {
    const newTask = {
      id: Date.now().toString(),
      status: 'queued',
      progress: 0,
      createdAt: new Date().toISOString(),
      logs: [],
      ...task
    };
    dispatch({ type: 'ADD_TASK', payload: newTask });
    return newTask.id;
  };

  const updateTask = (taskId, updates) => {
    dispatch({ type: 'UPDATE_TASK', payload: { id: taskId, ...updates } });
  };

  const removeTask = (taskId) => {
    dispatch({ type: 'REMOVE_TASK', payload: taskId });
  };

  const setTasks = (tasks) => {
    dispatch({ type: 'SET_TASKS', payload: tasks });
  };

  const addTaskLog = (taskId, log) => {
    dispatch({ 
      type: 'ADD_TASK_LOG', 
      payload: { 
        taskId, 
        log: {
          timestamp: new Date().toISOString(),
          message: log
        }
      }
    });
  };

  const cancelTask = async (taskId) => {
    try {
      const response = await fetch(`/api/tasks/${taskId}/cancel`, {
        method: 'POST'
      });
      
      if (response.ok) {
        updateTask(taskId, { status: 'cancelled' });
        return true;
      }
      return false;
    } catch (error) {
      console.error('Failed to cancel task:', error);
      return false;
    }
  };

  const fetchTasks = async () => {
    try {
      const response = await fetch('/api/tasks');
      const tasks = await response.json();
      // Ensure tasks is always an array
      const taskArray = Array.isArray(tasks) ? tasks : [];
      setTasks(taskArray);
    } catch (error) {
      console.error('Failed to fetch tasks:', error);
    }
  };

  // Poll for real task updates from backend
  useEffect(() => {
    // Only poll if we have active tasks
    if (state.activeTasks.length === 0) return;

    const interval = setInterval(() => {
      fetchTasks();
    }, 5000); // Poll every 5 seconds for real updates

    return () => clearInterval(interval);
  }, [state.activeTasks.length]);

  const value = {
    ...state,
    addTask,
    updateTask,
    removeTask,
    setTasks,
    addTaskLog,
    cancelTask,
    fetchTasks
  };

  return (
    <TaskContext.Provider value={value}>
      {children}
    </TaskContext.Provider>
  );
};

export const useTasks = () => {
  const context = useContext(TaskContext);
  if (!context) {
    throw new Error('useTasks must be used within a TaskProvider');
  }
  return context;
};