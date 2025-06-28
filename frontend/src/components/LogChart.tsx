"use client";

import { useState, useEffect, useCallback } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const COLORS = ['#ef4444', '#f59e0b', '#3b82f6', '#6b7280'];

interface LogChartProps {
  currentFileId?: string;
}

export default function LogChart({ currentFileId }: LogChartProps) {
  const [data, setData] = useState([
    { name: 'Errors', value: 0 },
    { name: 'Warnings', value: 0 },
    { name: 'Info', value: 0 },
    { name: 'Debug', value: 0 },
  ]);
  const [hasData, setHasData] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Function to refresh chart data
  const refreshChartData = useCallback(async () => {
    // Only fetch data if we have a currentFileId
    if (!currentFileId) {
      setHasData(false);
      return;
    }

    setIsLoading(true);
    try {
      // Fetch stats for specific file
      const response = await fetch(`http://localhost:5001/api/stats/${currentFileId}`);
      
      if (response.ok) {
        const statsData = await response.json();
        
        // Only show data if there are actual logs
        if (statsData.total_logs > 0) {
          setData([
            { name: 'Errors', value: statsData.log_levels?.ERROR || 0 },
            { name: 'Warnings', value: statsData.log_levels?.WARN || 0 },
            { name: 'Info', value: statsData.log_levels?.INFO || 0 },
            { name: 'Debug', value: statsData.log_levels?.DEBUG || 0 },
          ]);
          setHasData(true);
        } else {
          setHasData(false);
        }
      } else {
        setHasData(false);
      }
    } catch (error) {
      console.error('Error fetching log data:', error);
      setHasData(false);
    } finally {
      setIsLoading(false);
    }
  }, [currentFileId]);

  // Listen for custom event when files are uploaded
  useEffect(() => {
    const handleFileUploaded = () => {
      refreshChartData();
    };

    window.addEventListener('fileUploaded', handleFileUploaded);
    
    return () => {
      window.removeEventListener('fileUploaded', handleFileUploaded);
    };
  }, [refreshChartData]);

  // Refresh data when currentFileId changes
  useEffect(() => {
    refreshChartData();
  }, [refreshChartData]);

  const filteredData = data.filter(item => item.value > 0);

  return (
    <div className="w-full h-96">
      {currentFileId && hasData && filteredData.length > 0 ? (
        <div className="h-full flex flex-col">
          <div className="flex-1 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={filteredData}
                  cx="50%"
                  cy="40%"
                  labelLine={false}
                  label={false}
                  outerRadius="80%"
                  fill="#8884d8"
                  dataKey="value"
                >
                  {filteredData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  formatter={(value: number) => {
                    const total = filteredData.reduce((sum, item) => sum + item.value, 0);
                    const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : '0.0';
                    return [`${percentage}%`];
                  }}
                  labelStyle={{ display: 'none' }}
                  contentStyle={{ 
                    backgroundColor: '#ffffff', 
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                    padding: '8px 12px'
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          
          {/* Custom Legend - Only show items with values > 0 */}
          <div className="flex justify-center items-center space-x-4 py-4 flex-wrap">
            {filteredData.map((entry, index) => {
              // Double-check that we only show items with values > 0
              if (entry.value > 0) {
                return (
                  <div key={entry.name} className="flex items-center space-x-2">
                    <div 
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: COLORS[index % COLORS.length] }}
                    ></div>
                    <span className="text-sm text-gray-700">{entry.name}</span>
                  </div>
                );
              }
              return null;
            })}
          </div>
        </div>
      ) : (
        <div className="flex items-center justify-center h-full text-gray-500">
          <div className="text-center">
            <p className="text-lg font-medium mb-2">
              {!currentFileId ? 'No File Selected' : 'No Log Data Available'}
            </p>
            <p className="text-sm">
              {!currentFileId 
                ? 'Upload and analyze a log file to see the chart' 
                : 'This file has no log data to display'
              }
            </p>
            {isLoading && (
              <p className="text-xs text-blue-500 mt-2">Loading...</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
} 