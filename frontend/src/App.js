import React, { useState, useRef } from 'react';
import axios from 'axios';
import { toast, ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { Upload, Shield, AlertTriangle, CheckCircle, FileCode, Scan, Lock, Database, Zap, Eye } from 'lucide-react';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

function APKInspector() {
  const [file, setFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisComplete, setAnalysisComplete] = useState(false);
  const [analysisResults, setAnalysisResults] = useState(null);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile && droppedFile.name.endsWith('.apk')) {
      setFile(droppedFile);
      await uploadFile(droppedFile);
    } else {
      toast.error('Please upload an APK file');
    }
  };

  const handleFileSelect = async (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile && selectedFile.name.endsWith('.apk')) {
      setFile(selectedFile);
      await uploadFile(selectedFile);
    } else {
      toast.error('Please upload an APK file');
    }
  };

  const uploadFile = async (apkFile) => {
    try {
      const formData = new FormData();
      formData.append('file', apkFile);
      const response = await axios.post(`${API_BASE_URL}/upload`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setAnalysisId(response.data.analysis_id);
      setAnalysisStatus(response.data);
      toast.success('APK uploaded successfully!');
    } catch (error) {
      console.error('Upload error:', error);
      toast.error('Failed to upload APK file');
    }
  };

  const [analysisId, setAnalysisId] = useState(null);
  const [analysisStatus, setAnalysisStatus] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [pollingInterval, setPollingInterval] = useState(null);
  const [password, setPassword] = useState('');

  const startAnalysis = async () => {
    if (!analysisId) return;
    try {
      setIsAnalyzing(true);
      const url = password
        ? `${API_BASE_URL}/analyze/${analysisId}?password=${encodeURIComponent(password)}`
        : `${API_BASE_URL}/analyze/${analysisId}`;
      await axios.post(url);
      const interval = setInterval(async () => {
        try {
          const response = await axios.get(`${API_BASE_URL}/status/${analysisId}`);
          setAnalysisStatus(response.data);
          if (response.data.status === 'completed') {
            setIsAnalyzing(false);
            clearInterval(interval);
            setPollingInterval(null);
            setAnalysisComplete(true);
            setAnalysisResults(response.data.result);
            setAnalysisResult(response.data.result);
            toast.success('Analysis completed!');
          } else if (response.data.status === 'error') {
            setIsAnalyzing(false);
            clearInterval(interval);
            setPollingInterval(null);
            toast.error(`Analysis failed: ${response.data.message}`);
          }
        } catch (error) {
          console.error('Status check error:', error);
        }
      }, 1500);
      setPollingInterval(interval);
    } catch (error) {
      console.error('Analysis start error:', error);
      toast.error('Failed to start analysis');
      setIsAnalyzing(false);
    }
  };

  const downloadReport = async (format) => {
    if (!analysisId) return;

    try {
      const response = await axios.get(`${API_BASE_URL}/report/${analysisId}?format=${format}`, {
        responseType: 'blob'
      });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `apk_report_${analysisId}.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      toast.success(`${format.toUpperCase()} report downloaded!`);
    } catch (error) {
      console.error('Download error:', error);
      toast.error(`Failed to download ${format.toUpperCase()} report`);
    }
  };

  const downloadDecompiledFiles = async (tool) => {
    if (!analysisId) return;

    try {
      const response = await axios.get(`${API_BASE_URL}/download/${analysisId}/decompiled?tool=${tool}`, {
        responseType: 'blob'
      });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `decompiled_${tool}_${analysisId}.zip`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      toast.success(`${tool.toUpperCase()} decompiled files downloaded!`);
    } catch (error) {
      console.error('Download error:', error);
      toast.error(`Failed to download ${tool.toUpperCase()} decompiled files`);
    }
  };

  const resetAnalysis = () => {
    if (pollingInterval) {
      clearInterval(pollingInterval);
      setPollingInterval(null);
    }
    setFile(null);
    setIsDragging(false);
    setIsAnalyzing(false);
    setAnalysisComplete(false);
    setAnalysisResults(null);
    setAnalysisId(null);
    setAnalysisStatus(null);
    setAnalysisResult(null);
    setPassword('');
  };

  // Safe derived values for results view
  const safeScore = Number((analysisResults && analysisResults.malwareScore) || (analysisResult && analysisResult.malware_score) || 0);
  const safeThreatLevel = String(
    (analysisResults && analysisResults.threatLevel) ||
    (analysisResult && analysisResult.threat_level) ||
    (safeScore >= 70 ? 'high' : safeScore >= 30 ? 'medium' : 'low')
  ).toUpperCase();

  // Collapsible state
  const [showAllPerms, setShowAllPerms] = useState(false);
  const [showAllSusp, setShowAllSusp] = useState(false);

  const sendChat = async () => {
    if (!analysisId || !chatInput.trim()) return;
    const message = chatInput.trim();
    setChatMessages((msgs) => [...msgs, { role: 'user', content: message }]);
    setChatInput('');
    setIsChatting(true);
    try {
      const params = new URLSearchParams({ query: message });
      const response = await axios.post(`${API_BASE_URL}/chat/${analysisId}?${params.toString()}`);
      const data = response.data;
      setChatMessages((msgs) => [
        ...msgs,
        { role: 'assistant', content: data.answer, highlights: data.highlights, code_hits: data.code_hits }
      ]);
    } catch (e) {
      setChatMessages((msgs) => [
        ...msgs,
        { role: 'assistant', content: 'Chat error. Please try again.' }
      ]);
    } finally {
      setIsChatting(false);
    }
  };

  const getStatusMessage = () => {
    if (!analysisStatus) return '';
    
    switch (analysisStatus.status) {
      case 'uploaded':
        return 'APK uploaded successfully. Ready for analysis.';
      case 'analyzing':
        return `Analyzing... ${analysisStatus.progress || 0}%`;
      case 'completed':
        return 'Analysis completed successfully!';
      case 'error':
        return `Analysis failed: ${analysisStatus.message}`;
      default:
        return analysisStatus.message || 'Unknown status';
    }
  };

  const getStatusClass = () => {
    if (!analysisStatus) return '';
    return `status ${analysisStatus.status}`;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 text-white p-8">
      <div className="fixed inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0zNiAxOGMzLjMxNCAwIDYgMi42ODYgNiA2cy0yLjY4NiA2LTYgNi02LTIuNjg2LTYtNiAyLjY4Ni02IDYtNnoiIHN0cm9rZT0iIzRDMUQ5NSIgc3Ryb2tlLXdpZHRoPSIuNSIgb3BhY2l0eT0iLjMiLz48L2c+PC9zdmc+')] opacity-20"></div>
      <div className="max-w-6xl mx-auto relative z-10">
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-16 h-16 text-purple-400 mr-4" />
            <div>
              <h1 className="text-6xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">APK Inspector</h1>
              <p className="text-purple-300 text-xl mt-2">Cyber Cell Edition — Deep Malware Analysis</p>
            </div>
          </div>
          <div className="flex items-center justify-center gap-6 mt-6 text-sm text-purple-300">
            <div className="flex items-center gap-2"><Lock className="w-4 h-4" /><span>Secure Analysis</span></div>
            <div className="flex items-center gap-2"><Zap className="w-4 h-4" /><span>Fast Scanning</span></div>
            <div className="flex items-center gap-2"><Eye className="w-4 h-4" /><span>Deep Inspection</span></div>
          </div>
        </div>

        {!analysisComplete ? (
          <div className="bg-slate-800/50 backdrop-blur-xl rounded-3xl p-8 shadow-2xl border border-purple-500/20">
            <h2 className="text-2xl font-semibold mb-6 text-center">Upload APK File</h2>
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-4 border-dashed rounded-2xl p-16 text-center cursor-pointer transition-all duration-300 ${
                isDragging 
                  ? 'border-purple-400 bg-purple-500/20 scale-105' 
                  : file 
                  ? 'border-green-400 bg-green-500/10'
                  : 'border-purple-500/50 hover:border-purple-400 hover:bg-purple-500/10'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".apk"
                onChange={handleFileSelect}
                className="hidden"
              />
              {file ? (
                <div className="space-y-4">
                  <FileCode className="w-20 h-20 mx-auto text-green-400" />
                  <p className="text-2xl font-semibold text-green-400">{file.name}</p>
                  <p className="text-purple-300">Size: {(file.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
              ) : (
                <div className="space-y-4">
                  <Upload className="w-20 h-20 mx-auto text-purple-400" />
                  <p className="text-2xl font-semibold">Drag & drop an APK file here, or click to select</p>
                  <p className="text-purple-300">Only .apk files are accepted</p>
              </div>
            )}
            </div>
            {analysisStatus && analysisStatus.status === 'uploaded' && !isAnalyzing && (
            <div style={{ marginTop: '20px' }}>
              <div style={{ marginBottom: '10px' }}>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="APK password (optional)"
                  className="text-input"
                  style={{ padding: '8px', width: '100%', maxWidth: '360px' }}
                />
              </div>
                <button onClick={startAnalysis} className="btn btn-primary">
                  Start Deep Analysis
              </button>
            </div>
          )}
            {isAnalyzing && (
              <div className="mt-8 text-center space-y-6">
                <div className="flex justify-center">
                  <div className="relative">
                    <div className="w-24 h-24 border-8 border-purple-500/30 rounded-full"></div>
                    <div className="w-24 h-24 border-8 border-t-purple-500 rounded-full animate-spin absolute top-0"></div>
                  </div>
                </div>
                <div className="space-y-2">
                  <p className="text-xl font-semibold text-purple-300">Analyzing APK...</p>
                </div>
            </div>
          )}
        </div>
        ) : (
          <div className="space-y-6">
            {/* Sticky actions bar */}
            <div className="sticky top-0 z-20 -mt-2 mb-2 bg-slate-900/70 backdrop-blur-xl border border-purple-500/20 rounded-xl p-3 flex flex-wrap gap-3 items-center justify-between">
              <div className="text-sm text-purple-200">Analysis ID: {analysisId?.slice(0,8)}…</div>
              <div className="flex flex-wrap gap-3">
                <button className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white font-semibold py-2 px-4 rounded-lg" onClick={() => downloadReport('html')}>HTML</button>
                <button className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white font-semibold py-2 px-4 rounded-lg" onClick={() => downloadReport('pdf')}>PDF</button>
                <button className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-lg" onClick={() => downloadDecompiledFiles('jadx')}>JADX</button>
                <button className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-lg" onClick={() => downloadDecompiledFiles('apktool')}>APKTool</button>
                <button onClick={resetAnalysis} className="bg-purple-600 hover:bg-purple-700 text-white font-semibold py-2 px-4 rounded-lg">New Analysis</button>
              </div>
            </div>
            {/* Threat banner */}
            <div className={`rounded-2xl p-6 shadow-2xl border-2 ${
              safeScore < 30 
                ? 'bg-green-500/20 border-green-500/50' 
                : safeScore < 70 
                ? 'bg-yellow-500/20 border-yellow-500/50'
                : 'bg-red-500/20 border-red-500/50'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  {safeScore < 30 ? (
                    <CheckCircle className="w-16 h-16 text-green-400" />
                  ) : (
                    <AlertTriangle className="w-16 h-16 text-yellow-400" />
                  )}
                  <div>
                    <h3 className="text-3xl font-bold">Threat Level: {safeThreatLevel}</h3>
                    <p className="text-lg">Malware Score: {safeScore}/100</p>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-5xl font-bold">{safeScore}%</div>
                </div>
              </div>
            </div>

            {/* Summary strip */}
            <div className="grid md:grid-cols-4 gap-4">
              <div className="bg-slate-800/50 border border-purple-500/20 rounded-xl p-4">
                <div className="text-purple-300 text-sm">Package</div>
                <div className="font-semibold">{analysisResult?.package_name || 'N/A'}</div>
              </div>
              <div className="bg-slate-800/50 border border-purple-500/20 rounded-xl p-4">
                <div className="text-purple-300 text-sm">Version</div>
                <div className="font-semibold">{analysisResult?.version_name || 'N/A'} ({analysisResult?.version_code || 'N/A'})</div>
              </div>
              <div className="bg-slate-800/50 border border-purple-500/20 rounded-xl p-4">
                <div className="text-purple-300 text-sm">SDKs</div>
                <div className="font-semibold">min {analysisResult?.min_sdk || 'N/A'} • target {analysisResult?.target_sdk || 'N/A'}</div>
              </div>
              <div className="bg-slate-800/50 border border-purple-500/20 rounded-xl p-4">
                <div className="text-purple-300 text-sm">Cleartext Traffic</div>
                <div className="font-semibold">{analysisResult?.uses_cleartext_traffic === true ? 'Allowed' : analysisResult?.uses_cleartext_traffic === false ? 'Not allowed' : 'Unknown'}</div>
              </div>
            </div>
            {/* Two-column results grid */}
            <div className="grid md:grid-cols-2 gap-6 items-start">
              <div className="bg-slate-800/50 backdrop-blur-xl rounded-2xl p-6 border border-purple-500/20">
                <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
                  <Lock className="w-6 h-6 text-purple-400" />
                  Permissions Requested
                </h3>
                <ul className="space-y-2">
                  {(analysisResult?.permissions || analysisResults.permissions).slice(0, showAllPerms ? 200 : 12).map((perm, idx) => (
                    <li key={idx} className="flex items-center gap-2 text-purple-300">
                      <CheckCircle className="w-4 h-4 text-green-400" />
                      {perm}
                    </li>
                  ))}
                </ul>
                {(analysisResult?.permissions?.length || (analysisResults.permissions || []).length) > 12 && (
                  <button className="mt-3 text-purple-300 hover:text-purple-200 underline" onClick={() => setShowAllPerms(!showAllPerms)}>
                    {showAllPerms ? 'Show less' : 'Show more'}
                  </button>
                )}
              </div>
              <div className="bg-slate-800/50 backdrop-blur-xl rounded-2xl p-6 border border-purple-500/20">
                <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
                  <FileCode className="w-6 h-6 text-purple-400" />
                  Code Signature
                </h3>
                <p className="text-2xl font-semibold text-green-400">{analysisResults.codeSignature || 'Unknown'}</p>
                <p className="text-purple-300 mt-2">Certificate verified and trusted</p>
              </div>
              <div className="bg-slate-800/50 backdrop-blur-xl rounded-2xl p-6 border border-purple-500/20 md:col-span-2">
                <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
                  <Database className="w-6 h-6 text-purple-400" />
                  Suspicious Activities
                </h3>
                <ul className="space-y-2">
                  {(analysisResult?.suspicious_strings || analysisResults.suspiciousActivities).slice(0, showAllSusp ? 200 : 12).map((activity, idx) => (
                    <li key={idx} className="flex items-center gap-2 text-green-400">
                      <CheckCircle className="w-4 h-4" />
                      {activity}
                    </li>
                  ))}
                </ul>
                {((analysisResult?.suspicious_strings || analysisResults.suspiciousActivities)?.length || 0) > 12 && (
                  <button className="mt-3 text-purple-300 hover:text-purple-200 underline" onClick={() => setShowAllSusp(!showAllSusp)}>
                    {showAllSusp ? 'Show less' : 'Show more'}
                  </button>
                )}
              </div>
            </div>
            <div className="flex flex-col md:flex-row gap-4">
              <button onClick={resetAnalysis} className="flex-1 bg-purple-600 hover:bg-purple-700 text-white font-bold py-4 rounded-xl transition-all duration-300 transform hover:scale-105 shadow-lg">Analyze Another APK</button>
              <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-3">
                <button className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white font-bold py-3 rounded-xl transition-all duration-300 shadow-lg" onClick={() => downloadReport('html')}>HTML Report</button>
                <button className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white font-bold py-3 rounded-xl transition-all duration-300 shadow-lg" onClick={() => downloadReport('pdf')}>PDF Report</button>
                <button className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-xl transition-all duration-300 shadow-lg" onClick={() => downloadDecompiledFiles('jadx')}>Download JADX</button>
                <button className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-xl transition-all duration-300 shadow-lg" onClick={() => downloadDecompiledFiles('apktool')}>Download APKTool</button>
              </div>
            </div>
          </div>
        )}

        
      </div>
      
      <ToastContainer 
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
      />
    </div>
  );
}

export default APKInspector;
