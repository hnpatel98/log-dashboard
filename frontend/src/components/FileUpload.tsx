"use client";

import { useState } from "react";
import { Upload, FileText, Play } from "lucide-react";

interface UploadedFile {
  name: string;
  file_id: string;
  analyzed: boolean;
}

interface FileUploadProps {
  onFileAnalyzed?: (fileData: { file_id: string; filename: string; total_logs: number; threats_detected: number }) => void;
}

export default function FileUpload({ onFileAnalyzed }: FileUploadProps) {
  const [isUploading, setIsUploading] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [message, setMessage] = useState("");

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setIsUploading(true);
    setMessage("");

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5001';
      
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch(`${apiUrl}/api/upload`, {
          method: 'POST',
          body: formData,
        });

        if (response.ok) {
          const responseData = await response.json();
          setUploadedFiles(prev => [...prev, {
            name: file.name,
            file_id: responseData.file_id,
            analyzed: false
          }]);
          setMessage(prev => prev + `Successfully uploaded ${file.name}\n`);
        } else {
          setMessage(prev => prev + `Failed to upload ${file.name}\n`);
        }
      }
    } catch {
      setMessage("Error uploading files. Please try again.");
    } finally {
      setIsUploading(false);
    }
  };

  const handleAnalyzeFile = async (file: UploadedFile) => {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5001';
      const response = await fetch(`${apiUrl}/api/analyze/${file.file_id}`, {
        method: 'POST',
      });

      if (response.ok) {
        const analysisData = await response.json();
        
        // Update file status to analyzed
        setUploadedFiles(prev => prev.map(f => 
          f.file_id === file.file_id ? { ...f, analyzed: true } : f
        ));

        // Trigger dashboard update with file data
        if (onFileAnalyzed) {
          onFileAnalyzed({
            file_id: file.file_id,
            filename: file.name,
            total_logs: analysisData.total_logs,
            threats_detected: analysisData.threats_detected
          });
        }

        // Trigger chart refresh
        window.dispatchEvent(new CustomEvent('fileUploaded', {
          detail: {
            file_id: file.file_id,
            filename: file.name,
            total_logs: analysisData.total_logs,
            threats_detected: analysisData.threats_detected
          }
        }));

        setMessage(prev => prev + `Analysis completed for ${file.name}\n`);
      } else {
        setMessage(prev => prev + `Failed to analyze ${file.name}\n`);
      }
    } catch {
      setMessage(prev => prev + `Error analyzing ${file.name}\n`);
    }
  };

  const handleFileClick = (file: UploadedFile) => {
    if (file.analyzed) {
      // Trigger dashboard update to show this file's data
      if (onFileAnalyzed) {
        onFileAnalyzed({
          file_id: file.file_id,
          filename: file.name,
          total_logs: 0, // Will be fetched from backend
          threats_detected: 0
        });
      }

      // Trigger chart refresh
      window.dispatchEvent(new CustomEvent('fileUploaded', {
        detail: {
          file_id: file.file_id,
          filename: file.name,
          total_logs: 0,
          threats_detected: 0
        }
      }));
    }
  };

  return (
    <div className="border-4 border-dashed border-gray-200 rounded-lg p-6">
      <div className="text-center">
        <Upload className="mx-auto h-12 w-12 text-gray-400" />
        <div className="mt-4">
          <label htmlFor="file-upload" className="cursor-pointer">
            <span className="mt-2 block text-sm font-medium text-gray-900">
              Upload log files
            </span>
            <span className="mt-1 block text-xs text-gray-500">
              TXT, LOG files up to 10MB
            </span>
          </label>
          <input
            id="file-upload"
            name="file-upload"
            type="file"
            className="sr-only"
            multiple
            accept=".txt,.log"
            onChange={handleFileUpload}
          />
        </div>
      </div>
      {isUploading && (
        <div className="mt-4 text-center">
          <div className="inline-flex items-center px-4 py-2 text-sm text-blue-700 bg-blue-100 rounded-md">
            Processing files...
          </div>
        </div>
      )}
      {message && (
        <div className="mt-4 p-3 bg-gray-100 rounded-md">
          <pre className="text-sm text-gray-700 whitespace-pre-wrap">{message}</pre>
        </div>
      )}
      {uploadedFiles.length > 0 && (
        <div className="mt-4">
          <h3 className="text-sm font-medium text-gray-900 mb-2">Uploaded Files:</h3>
          <ul className="space-y-2">
            {uploadedFiles.map((file, index) => (
              <li key={index} className="flex items-center justify-between p-2 bg-gray-50 rounded-md">
                <div className="flex items-center space-x-2">
                  <FileText className="h-4 w-4 text-gray-500" />
                  <button
                    onClick={() => handleFileClick(file)}
                    className={`text-sm font-medium hover:text-blue-600 transition-colors ${
                      file.analyzed ? 'text-blue-600 cursor-pointer' : 'text-gray-700 cursor-default'
                    }`}
                    disabled={!file.analyzed}
                  >
                    {file.name}
                  </button>
                  {file.analyzed && (
                    <span className="text-xs px-2 py-1 bg-green-100 text-green-800 rounded-full">
                      Analyzed
                    </span>
                  )}
                </div>
                <button
                  onClick={() => handleAnalyzeFile(file)}
                  disabled={file.analyzed}
                  className={`flex items-center space-x-1 px-3 py-1 text-xs rounded-md transition-colors ${
                    file.analyzed
                      ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                      : 'bg-blue-500 text-white hover:bg-blue-600'
                  }`}
                >
                  <Play className="h-3 w-3" />
                  <span>{file.analyzed ? 'Analyzed' : 'Analyze'}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
} 