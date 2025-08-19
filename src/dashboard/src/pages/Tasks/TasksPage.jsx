import React, { useState, useEffect } from 'react';
import { Activity, Play, Pause, Square, RotateCcw } from 'lucide-react';
import { useTasks } from '../../context/TaskContext';

const TasksPage = () => {
  const { tasks, activeTasks, completedTasks, cancelTask, fetchTasks } = useTasks();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchTasks().finally(() => setLoading(false));
  }, []);

  const getStatusIcon = (status) => {
    switch (status) {
    case 'running': return <Play className="status-icon running" size={16} />;
    case 'queued': return <Pause className="status-icon queued" size={16} />;
    case 'completed': return <Square className="status-icon completed" size={16} />;
    case 'failed': return <Square className="status-icon failed" size={16} />;
    case 'cancelled': return <Square className="status-icon cancelled" size={16} />;
    default: return <Square className="status-icon" size={16} />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
    case 'running': return 'info';
    case 'queued': return 'warning';
    case 'completed': return 'success';
    case 'failed': return 'danger';
    case 'cancelled': return 'secondary';
    default: return 'secondary';
    }
  };

  const handleCancelTask = async (taskId) => {
    if (confirm('Are you sure you want to cancel this task?')) {
      await cancelTask(taskId);
    }
  };

  const TaskCard = ({ task }) => (
    <div className="task-card">
      <div className="task-header">
        <div className="task-info">
          <h3 className="task-title">{task.type || 'Security Scan'}</h3>
          <p className="task-target">{task.target || 'Unknown target'}</p>
        </div>
        <div className="task-status">
          {getStatusIcon(task.status)}
          <span className={`badge badge-${getStatusColor(task.status)}`}>
            {task.status.toUpperCase()}
          </span>
        </div>
      </div>

      <div className="task-progress">
        <div className="progress-info">
          <span>Progress: {task.progress || 0}%</span>
          <span>Started: {new Date(task.createdAt).toLocaleString()}</span>
        </div>
        <div className="progress-bar">
          <div 
            className="progress-fill" 
            style={{ width: `${task.progress || 0}%` }}
          />
        </div>
      </div>

      <div className="task-actions">
        {task.status === 'running' && (
          <button 
            className="btn btn-danger"
            onClick={() => handleCancelTask(task.id)}
          >
            Cancel
          </button>
        )}
        {task.status === 'failed' && (
          <button className="btn btn-secondary">
            <RotateCcw size={16} />
            Retry
          </button>
        )}
      </div>
    </div>
  );

  return (
    <div className="tasks-page">
      <div className="page-header">
        <Activity className="page-icon" size={32} />
        <div>
          <h1 className="page-title">Task Monitor</h1>
          <p className="page-description">
            Monitor running scans and manage task queue
          </p>
        </div>
        <button className="btn btn-primary" onClick={fetchTasks}>
          <RotateCcw size={20} />
          Refresh
        </button>
      </div>

      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner" />
          <p>Loading tasks...</p>
        </div>
      ) : (
        <div className="tasks-content">
          <div className="tasks-section">
            <h2 className="section-title">
              Active Tasks ({activeTasks.length})
            </h2>
            {activeTasks.length > 0 ? (
              <div className="tasks-grid">
                {activeTasks.map(task => (
                  <TaskCard key={task.id} task={task} />
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <Activity size={48} className="empty-icon" />
                <h3>No Active Tasks</h3>
                <p>All tasks are completed. Start a new scan to see tasks here.</p>
              </div>
            )}
          </div>

          <div className="tasks-section">
            <h2 className="section-title">
              Recent Tasks ({completedTasks.slice(0, 5).length})
            </h2>
            {completedTasks.length > 0 ? (
              <div className="tasks-grid">
                {completedTasks.slice(0, 5).map(task => (
                  <TaskCard key={task.id} task={task} />
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <Activity size={48} className="empty-icon" />
                <h3>No Completed Tasks</h3>
                <p>Completed tasks will appear here.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default TasksPage;