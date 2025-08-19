import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout/Layout';
import ScannerPage from './pages/Scanner/ScannerPage';
import ReportsPage from './pages/Reports/ReportsPage';
import ReportDetails from './pages/Reports/ReportDetails';
import HistoryPage from './pages/History/HistoryPage';
// Tasks page removed - not needed
import AboutPage from './pages/About/AboutPage';
import { AppProvider } from './context/AppContext';
import { TaskProvider } from './context/TaskContext';

function App() {
  return (
    <AppProvider>
      <TaskProvider>
        <Layout>
          <Routes>
            <Route path="/" element={<Navigate to="/scanner" replace />} />
            <Route path="/scanner" element={<ScannerPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/reports/:id" element={<ReportDetails />} />
            <Route path="/history" element={<HistoryPage />} />
            {/* Tasks route removed */}
            <Route path="/about/*" element={<AboutPage />} />
          </Routes>
        </Layout>
      </TaskProvider>
    </AppProvider>
  );
}

export default App;