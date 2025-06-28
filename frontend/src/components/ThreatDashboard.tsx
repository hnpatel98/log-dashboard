"use client";

import { useState, useEffect } from 'react';

interface Threat {
  id?: number;
  type: string;
  severity: string;
  message: string;
  timestamp: string;
  source: string;
  line_number: number;
  confidence: number;
  pattern_matched?: string;
  file_id?: string;
  filename?: string;
  explanation?: string;
  is_anomaly?: boolean;
  anomaly_features?: Record<string, number>;
  anomaly_score?: number;
}

interface ThreatDashboardProps {
  threats: Threat[];
}

// Client-side only date formatter to prevent hydration issues
function formatDate(timestamp: string): string {
  if (typeof window === 'undefined') {
    return 'Loading...';
  }
  
  try {
    return new Date(timestamp).toLocaleString();
  } catch {
    return 'Invalid date';
  }
}

export default function ThreatDashboard({ threats }: ThreatDashboardProps) {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [mounted, setMounted] = useState(false);
  const [showExplanations, setShowExplanations] = useState<{[key: number]: boolean}>({});

  // Ensure component is mounted before rendering date-dependent content
  useEffect(() => {
    setMounted(true);
  }, []);

  const filteredThreats = selectedSeverity === 'all' 
    ? threats 
    : selectedSeverity === 'anomaly'
    ? threats.filter(threat => threat.is_anomaly)
    : threats.filter(threat => threat.severity === selectedSeverity);

  const severityCounts = {
    high: threats.filter(t => t.severity === 'high').length,
    medium: threats.filter(t => t.severity === 'medium').length,
    low: threats.filter(t => t.severity === 'low').length,
  };

  const anomalyCount = threats.filter(t => t.is_anomaly).length;

  const getSeverityColor = (severity: string, isAnomaly: boolean = false) => {
    if (isAnomaly) {
      return 'bg-purple-100 text-purple-800 border-purple-200 border-2 border-dashed';
    }
    
    switch (severity) {
      case 'high': return 'bg-red-100 text-red-800 border-red-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getSeverityIcon = (severity: string, isAnomaly: boolean = false) => {
    if (isAnomaly) {
      return (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      );
    }
    
    switch (severity) {
      case 'high': return (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      );
      case 'medium': return (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      );
      case 'low': return (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      );
      default: return null;
    }
  };

  const toggleExplanation = (threatId: number) => {
    setShowExplanations(prev => ({
      ...prev,
      [threatId]: !prev[threatId]
    }));
  };

  return (
    <div className="bg-white rounded-xl shadow-lg border border-gray-100 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100">
        <h3 className="text-lg font-semibold text-gray-900 flex items-center">
          <svg className="w-5 h-5 mr-2 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
          Threat Detection
        </h3>
      </div>

      <div className="p-6">
        {/* Threat Summary */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          <div className="text-center">
            <div className="text-2xl font-bold text-red-600">{severityCounts.high}</div>
            <div className="text-sm text-gray-600">High Risk</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-600">{severityCounts.medium}</div>
            <div className="text-sm text-gray-600">Medium Risk</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">{severityCounts.low}</div>
            <div className="text-sm text-gray-600">Low Risk</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-600">{anomalyCount}</div>
            <div className="text-sm text-gray-600">Anomalies</div>
          </div>
        </div>

        {/* Filter Buttons */}
        <div className="flex space-x-2 mb-4 flex-wrap">
          <button
            onClick={() => setSelectedSeverity('all')}
            className={`px-3 py-1 text-sm rounded-full border ${
              selectedSeverity === 'all' 
                ? 'bg-gray-900 text-white border-gray-900' 
                : 'bg-gray-100 text-gray-700 border-gray-300 hover:bg-gray-200'
            }`}
          >
            All ({threats.length})
          </button>
          <button
            onClick={() => setSelectedSeverity('high')}
            className={`px-3 py-1 text-sm rounded-full border ${
              selectedSeverity === 'high' 
                ? 'bg-red-600 text-white border-red-600' 
                : 'bg-red-100 text-red-700 border-red-300 hover:bg-red-200'
            }`}
          >
            High ({severityCounts.high})
          </button>
          <button
            onClick={() => setSelectedSeverity('medium')}
            className={`px-3 py-1 text-sm rounded-full border ${
              selectedSeverity === 'medium' 
                ? 'bg-yellow-600 text-white border-yellow-600' 
                : 'bg-yellow-100 text-yellow-700 border-yellow-300 hover:bg-yellow-200'
            }`}
          >
            Medium ({severityCounts.medium})
          </button>
          <button
            onClick={() => setSelectedSeverity('low')}
            className={`px-3 py-1 text-sm rounded-full border ${
              selectedSeverity === 'low' 
                ? 'bg-blue-600 text-white border-blue-600' 
                : 'bg-blue-100 text-blue-700 border-blue-300 hover:bg-blue-200'
            }`}
          >
            Low ({severityCounts.low})
          </button>
          <button
            onClick={() => setSelectedSeverity('anomaly')}
            className={`px-3 py-1 text-sm rounded-full border ${
              selectedSeverity === 'anomaly' 
                ? 'bg-purple-600 text-white border-purple-600' 
                : 'bg-purple-100 text-purple-700 border-purple-300 hover:bg-purple-200'
            }`}
          >
            Anomalies ({anomalyCount})
          </button>
        </div>

        {/* Threats List */}
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {filteredThreats.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <svg className="w-12 h-12 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-lg font-medium">No threats detected</p>
              <p className="text-sm">Upload log files to see threat analysis</p>
            </div>
          ) : (
            filteredThreats.map((threat, index) => {
              const isAnomaly = threat.is_anomaly || false;
              const threatId = threat.id || index;
              
              return (
                <div
                  key={index}
                  className={`p-4 rounded-lg border transition-all duration-200 ${getSeverityColor(threat.severity, isAnomaly)} ${
                    isAnomaly ? 'ring-2 ring-purple-300' : ''
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3">
                      <div className="flex-shrink-0 mt-1">
                        {getSeverityIcon(threat.severity, isAnomaly)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center space-x-2 mb-1">
                          <span className="text-sm font-semibold capitalize">
                            {(threat.type || 'Unknown').replace('_', ' ')}
                          </span>
                          {isAnomaly && (
                            <span className="text-xs px-2 py-1 rounded-full bg-purple-200 text-purple-800 font-medium">
                              ANOMALY
                            </span>
                          )}
                          <span className="text-xs px-2 py-1 rounded-full bg-white bg-opacity-50">
                            {((threat.confidence || 0) * 100).toFixed(0)}% confidence
                          </span>
                        </div>
                        <p className="text-sm mb-2 line-clamp-2">{threat.message}</p>
                        
                        {/* Explanation Section */}
                        {threat.explanation && (
                          <div className="mb-2">
                            <button
                              onClick={() => toggleExplanation(threatId)}
                              className="text-xs text-blue-600 hover:text-blue-800 underline focus:outline-none"
                            >
                              {showExplanations[threatId] ? 'Hide explanation' : 'Show explanation'}
                            </button>
                            {showExplanations[threatId] && (
                              <div className="mt-2 p-3 bg-blue-50 rounded-md border border-blue-200">
                                <p className="text-xs text-blue-800 font-medium mb-1">Why flagged:</p>
                                <p className="text-xs text-blue-700">{threat.explanation}</p>
                                {isAnomaly && threat.anomaly_score && (
                                  <p className="text-xs text-blue-600 mt-1">
                                    Anomaly score: {threat.anomaly_score.toFixed(2)}
                                  </p>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                        
                        <div className="flex items-center space-x-4 text-xs opacity-75">
                          <span>File: {threat.filename || 'Unknown'}</span>
                          <span>Line: {threat.line_number || 'N/A'}</span>
                          <span>{mounted && threat.timestamp ? formatDate(threat.timestamp) : 'Loading...'}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
} 