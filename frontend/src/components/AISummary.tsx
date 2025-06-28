"use client";

import React, { useState, useEffect, useCallback } from 'react';

interface AISummaryData {
  summary: string;
  key_findings: string[];
  recommendations: string[];
}

interface AISummaryProps {
  fileId?: string;
}

function parseSummaryField(summary: string): Partial<AISummaryData> | null {
  // Remove markdown code block if present
  let cleaned = summary.trim();
  if (cleaned.startsWith('```json')) cleaned = cleaned.slice(7);
  if (cleaned.startsWith('```')) cleaned = cleaned.slice(3);
  if (cleaned.endsWith('```')) cleaned = cleaned.slice(0, -3);
  cleaned = cleaned.trim();
  try {
    const parsed = JSON.parse(cleaned);
    if (typeof parsed === 'object' && parsed !== null) {
      return parsed;
    }
  } catch {
    // Not JSON
  }
  return null;
}

const AISummary: React.FC<AISummaryProps> = ({ fileId }) => {
  const [summary, setSummary] = useState<AISummaryData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchSummary = useCallback(async () => {
    if (!fileId) return;

    setLoading(true);
    setError(null);

    try {
      // First, get threats and stats for this file
      const [threatsResponse, statsResponse] = await Promise.all([
        fetch(`http://localhost:5001/api/threats/${fileId}`),
        fetch(`http://localhost:5001/api/stats/${fileId}`)
      ]);

      if (!threatsResponse.ok || !statsResponse.ok) {
        throw new Error(`Failed to fetch data: ${threatsResponse.status} ${statsResponse.status}`);
      }

      const threatsData = await threatsResponse.json();
      const statsData = await statsResponse.json();

      // Now get AI summary with the actual data
      const summaryResponse = await fetch(`http://localhost:5001/api/ai-summary/${fileId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          threats: threatsData.threats || [],
          stats: statsData
        })
      });
      
      if (!summaryResponse.ok) {
        throw new Error(`HTTP error! status: ${summaryResponse.status}`);
      }
      
      const data = await summaryResponse.json();
      setSummary(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch AI summary');
      console.error('Error fetching AI summary:', err);
    } finally {
      setLoading(false);
    }
  }, [fileId]);

  useEffect(() => {
    if (fileId) {
      fetchSummary();
    } else {
      setSummary(null);
      setError(null);
    }
  }, [fileId, fetchSummary]);

  if (!fileId) {
    return (
      <div className="bg-white rounded-lg shadow-md p-6">
        <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
          <svg className="w-5 h-5 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
          </svg>
          AI Summary
        </h3>
        <div className="text-gray-500 text-center py-8">
          <svg className="w-12 h-12 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
          </svg>
          <p>Select a file and analyze it to see AI-generated insights</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
        <svg className="w-5 h-5 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
        </svg>
        AI Summary
        {loading && (
          <div className="ml-2 flex items-center">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500"></div>
            <span className="ml-2 text-sm text-gray-500">Analyzing...</span>
          </div>
        )}
      </h3>

      {loading && (
        <div className="space-y-4">
          <div className="animate-pulse">
            <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
            <div className="h-4 bg-gray-200 rounded w-1/2"></div>
          </div>
          <div className="animate-pulse">
            <div className="h-4 bg-gray-200 rounded w-full mb-2"></div>
            <div className="h-4 bg-gray-200 rounded w-5/6 mb-2"></div>
            <div className="h-4 bg-gray-200 rounded w-4/6"></div>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <svg className="w-5 h-5 text-red-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <h4 className="text-sm font-medium text-red-800">Error loading AI summary</h4>
              <p className="text-sm text-red-700 mt-1">{error}</p>
              {error.includes('OpenAI API key') && (
                <p className="text-sm text-red-600 mt-2">
                  Please configure your OpenAI API key in the backend environment variables.
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {summary && !loading && (() => {
        // Try to parse summary.summary as JSON
        let parsed: Partial<AISummaryData> | null = null;
        if (summary.summary && typeof summary.summary === 'string') {
          parsed = parseSummaryField(summary.summary);
        }
        // Use parsed fields if available, otherwise fallback
        const execSummary = parsed?.summary || summary.summary;
        const keyFindings = parsed?.key_findings || summary.key_findings;
        const recommendations = parsed?.recommendations || summary.recommendations;
        return (
          <div className="space-y-6">
            {/* Executive Summary */}
            <div>
              <h4 className="text-md font-medium text-gray-700 mb-3 flex items-center">
                <svg className="w-4 h-4 mr-2 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Executive Summary
              </h4>
              <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
                <p className="text-gray-700 leading-relaxed">{execSummary}</p>
              </div>
            </div>

            {/* Key Findings */}
            {keyFindings && keyFindings.length > 0 && (
              <div>
                <h4 className="text-md font-medium text-gray-700 mb-3 flex items-center">
                  <svg className="w-4 h-4 mr-2 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Key Findings
                </h4>
                <ul className="space-y-2">
                  {keyFindings.map((finding, index) => (
                    <li key={index} className="flex items-start">
                      <svg className="w-4 h-4 text-orange-500 mr-2 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span className="text-gray-700">{finding}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Recommendations */}
            {recommendations && recommendations.length > 0 && (
              <div>
                <h4 className="text-md font-medium text-gray-700 mb-3 flex items-center">
                  <svg className="w-4 h-4 mr-2 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                  Recommendations
                </h4>
                <ul className="space-y-2">
                  {recommendations.map((recommendation, index) => (
                    <li key={index} className="flex items-start">
                      <svg className="w-4 h-4 text-purple-500 mr-2 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 9l3 3m0 0l-3 3m3-3H8m13 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span className="text-gray-700">{recommendation}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        );
      })()}
    </div>
  );
};

export default AISummary; 