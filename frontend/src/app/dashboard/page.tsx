'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import FileUpload from '@/components/FileUpload';
import LogChart from '@/components/LogChart';
import ThreatDashboard from '@/components/ThreatDashboard';
import AISummary from '@/components/AISummary';
import ClientWrapper from '@/components/ClientWrapper';

interface FileData {
  file_id: string;
  filename: string;
  total_logs: number;
  threats_detected: number;
}

interface Stats {
  total_files: number;
  total_logs: number;
  total_threats: number;
  log_levels: {
    ERROR: number;
    WARN: number;
    INFO: number;
    DEBUG: number;
  };
  average_logs_per_file: number;
}

export default function DashboardPage() {
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const [threats, setThreats] = useState([]);
  const [currentFile, setCurrentFile] = useState<FileData | null>(null);
  const router = useRouter();

  const handleLogout = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/logout', {
        method: 'POST',
      });

      if (response.ok) {
        router.push('/login');
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFileAnalyzed = async (fileData: FileData) => {
    setCurrentFile(fileData);
    
    // Immediately fetch data for this specific file
    try {
      // Fetch stats for this specific file
      const statsResponse = await fetch(`http://localhost:5001/api/stats/${fileData.file_id}`);
      if (statsResponse.ok) {
        const statsData = await statsResponse.json();
        setStats(statsData);
      }

      // Fetch threats for this specific file
      const threatsResponse = await fetch(`http://localhost:5001/api/threats/${fileData.file_id}`);
      if (threatsResponse.ok) {
        const threatsData = await threatsResponse.json();
        setThreats(threatsData.threats || []);
      }
    } catch (error) {
      console.error('Error fetching file data:', error);
    }
  };

  // Listen for file upload events
  useEffect(() => {
    const handleFileUploaded = (event: CustomEvent<FileData>) => {
      const fileData = event.detail;
      setCurrentFile(fileData);
    };

    window.addEventListener('fileUploaded', handleFileUploaded as EventListener);
    
    return () => {
      window.removeEventListener('fileUploaded', handleFileUploaded as EventListener);
    };
  }, []);

  // Clear stats when no file is selected
  useEffect(() => {
    if (!currentFile) {
      setStats(null);
      setThreats([]);
    }
  }, [currentFile]);

  // Refresh dashboard data when currentFile changes
  // useEffect(() => {
  //   handleFileAnalyzed(currentFile);
  // }, [currentFile]);

  return (
    <ClientWrapper>
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
        {/* Header */}
        <header className="bg-white shadow-lg border-b border-gray-200">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center py-6">
              <div className="flex items-center space-x-4">
                <div className="flex items-center">
                  <div className="w-10 h-10 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                  </div>
                  <div className="ml-3">
                    <h1 className="text-2xl font-bold text-gray-900">Log Dashboard</h1>
                    <p className="text-sm text-gray-600">
                      {currentFile ? `Analyzing: ${currentFile.filename}` : 'AI-Powered Threat Detection & Analysis'}
                    </p>
                  </div>
                </div>
              </div>
              <div className="flex items-center space-x-4">
                {currentFile && stats && (
                  <div className="hidden md:flex items-center space-x-4 text-sm text-gray-600">
                    <span>Logs: {stats.total_logs || 0}</span>
                    <span>Threats: {stats.total_threats || 0}</span>
                  </div>
                )}
                <button
                  onClick={handleLogout}
                  disabled={loading}
                  className="bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shadow-md"
                >
                  {loading ? 'Logging out...' : 'Logout'}
                </button>
              </div>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
          {/* Stats Cards - Only show when a file is selected */}
          {currentFile && stats && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
              <div className="bg-white rounded-xl shadow-lg p-6 border border-gray-100">
                <div className="flex items-center">
                  <div className="p-3 bg-green-100 rounded-lg">
                    <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                    </svg>
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">File Logs</p>
                    <p className="text-2xl font-bold text-gray-900">{stats.total_logs.toLocaleString()}</p>
                  </div>
                </div>
              </div>

              <div className="bg-white rounded-xl shadow-lg p-6 border border-gray-100">
                <div className="flex items-center">
                  <div className="p-3 bg-red-100 rounded-lg">
                    <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">File Threats</p>
                    <p className="text-2xl font-bold text-gray-900">{stats.total_threats}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* No file selected message */}
          {!currentFile && (
            <div className="mb-8 p-6 bg-white rounded-xl shadow-lg border border-gray-100">
              <div className="text-center">
                <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <h3 className="mt-2 text-sm font-medium text-gray-900">No file selected</h3>
                <p className="mt-1 text-sm text-gray-500">Upload and analyze a log file to view its statistics.</p>
              </div>
            </div>
          )}

          {/* Main Dashboard Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* File Upload Section */}
            <div className="lg:col-span-1">
              <div className="bg-white rounded-xl shadow-lg border border-gray-100 overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-100">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                    <svg className="w-5 h-5 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                    Upload Log Files
                  </h3>
                </div>
                <div className="p-6">
                  <FileUpload onFileAnalyzed={handleFileAnalyzed} />
                </div>
              </div>
            </div>

            {/* Log Analysis Chart */}
            <div className="lg:col-span-1">
              <div className="bg-white rounded-xl shadow-lg border border-gray-100 overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-100">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                    <svg className="w-5 h-5 mr-2 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                    </svg>
                    Log Level Distribution
                  </h3>
                </div>
                <div className="p-6">
                  <LogChart currentFileId={currentFile?.file_id} />
                </div>
              </div>
            </div>

            {/* Threat Dashboard */}
            <div className="lg:col-span-1">
              <ThreatDashboard threats={threats} />
            </div>
          </div>

          {/* AI Summary Section */}
          <div className="col-span-full">
            <AISummary fileId={currentFile?.file_id} />
          </div>
        </main>
      </div>
    </ClientWrapper>
  );
} 