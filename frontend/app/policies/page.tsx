'use client';

import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Lock, 
  AlertTriangle, 
  ToggleLeft, 
  ToggleRight, 
  Loader2,
  FileText,
  Upload,
  Trash2,
  Plus
} from 'lucide-react';

interface Policy {
  id: number;
  name: string;
  description: string;
  enabled: boolean;
  severity_threshold: string;
  block_on_failure: boolean;
}

interface PolicyDoc {
  id: number;
  filename: string;
  uploaded_at: string;
}

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [docs, setDocs] = useState<PolicyDoc[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<number | null>(null);
  const [uploading, setUploading] = useState(false);

  // Fetch Data
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [polRes, docRes] = await Promise.all([
          fetch('https://intelli-scan-api-82554e007164.herokuapp.com/policies'),
          fetch('https://intelli-scan-api-82554e007164.herokuapp.com/policies/documents')
        ]);

        if (polRes.ok && docRes.ok) {
          setPolicies(await polRes.json());
          setDocs(await docRes.json());
        } else {
          throw new Error('Backend error');
        }
      } catch (error) {
        console.warn("Backend unavailable (using mock data):", error);
        setPolicies([
          { id: 1, name: 'No Critical Vulnerabilities', description: 'Fails scan if any Critical issues are found.', enabled: true, severity_threshold: 'CRITICAL', block_on_failure: true },
          { id: 2, name: 'No High Severity Secrets', description: 'Blocks deployment if secrets/keys are detected.', enabled: true, severity_threshold: 'HIGH', block_on_failure: true },
        ]);
        setDocs([
          { id: 1, filename: 'Corp_Security_Standard_v2.pdf', uploaded_at: new Date().toISOString() },
          { id: 2, filename: 'OWASP_Compliance_Guide.txt', uploaded_at: new Date().toISOString() }
        ]);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  // Toggle Policy Logic
  const togglePolicy = async (id: number, currentStatus: boolean) => {
    setSavingId(id);
    setPolicies(policies.map(p => p.id === id ? { ...p, enabled: !currentStatus } : p));
    try {
      await fetch(`https://intelli-scan-api-82554e007164.herokuapp.com/policies/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !currentStatus }),
      });
    } catch (error) {
      console.warn("Backend unavailable. Simulating update.", error);
    } finally {
      setSavingId(null);
    }
  };

  // Handle File Upload
  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    
    setUploading(true);
    const file = e.target.files[0];
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('https://intelli-scan-api-82554e007164.herokuapp.com/policies', {
        method: 'POST',
        body: formData,
      });
      
      if (res.ok) {
        const newDoc = await res.json();
        setDocs([{ id: newDoc.id, filename: newDoc.filename, uploaded_at: new Date().toISOString() }, ...docs]);
      } else {
        console.error("Upload failed", res.status, await res.text());
        // Fallback to mock update for demo if API fails
        setDocs([{ id: Date.now(), filename: file.name, uploaded_at: new Date().toISOString() }, ...docs]);
      }
    } catch (error) {
      console.error("Upload failed (network error)", error);
      // Fallback to mock update for demo
      setDocs([{ id: Date.now(), filename: file.name, uploaded_at: new Date().toISOString() }, ...docs]);
    } finally {
      setUploading(false);
    }
  };

  // Handle Delete Doc
  const handleDeleteDoc = async (id: number) => {
    setDocs(docs.filter(d => d.id !== id));
    try {
      await fetch(`https://intelli-scan-api-82554e007164.herokuapp.com/policies/documents/${id}`, { method: 'DELETE' });
    } catch (e) {
      console.warn("Backend delete failed", e);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-8">
      
      <header className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
          </div>
          <h1 className="text-3xl font-bold text-white">Security Policies</h1>
        </div>
        <p className="text-slate-400">Configure rules and upload organization standards for the AI Agent.</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* --- LEFT COL: RULES --- */}
        <div className="lg:col-span-2 space-y-6">
          <h2 className="text-xl font-semibold text-white flex items-center gap-2">
            <Lock className="h-5 w-5 text-indigo-400" />
            Enforcement Rules
          </h2>
          
          {loading ? (
            <div className="p-12 flex justify-center text-slate-500">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : (
            policies.map((policy) => (
              <div 
                key={policy.id} 
                className={`p-6 rounded-xl border transition-all ${
                  policy.enabled 
                    ? 'bg-slate-900 border-slate-700 shadow-lg' 
                    : 'bg-slate-900/50 border-slate-800 opacity-75'
                }`}
              >
                <div className="flex justify-between items-start">
                  <div className="flex gap-4">
                    <div className={`mt-1 p-2 rounded-lg ${
                      policy.block_on_failure ? 'bg-rose-500/10 text-rose-500' : 'bg-blue-500/10 text-blue-400'
                    }`}>
                      {policy.block_on_failure ? <Lock className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
                    </div>
                    <div>
                      <h3 className="text-xl font-bold text-white mb-1">{policy.name}</h3>
                      <p className="text-slate-400 mb-4">{policy.description}</p>
                      <div className="flex gap-2">
                        <Badge label={`Threshold: ${policy.severity_threshold}`} color="slate" />
                        {policy.block_on_failure && <Badge label="Blocks Build" color="rose" />}
                      </div>
                    </div>
                  </div>

                  <button 
                    onClick={() => togglePolicy(policy.id, policy.enabled)}
                    disabled={savingId === policy.id}
                    className="focus:outline-none"
                  >
                    {savingId === policy.id ? (
                      <Loader2 className="h-8 w-8 text-slate-500 animate-spin" />
                    ) : policy.enabled ? (
                      <ToggleRight className="h-10 w-10 text-emerald-500 hover:text-emerald-400 transition-colors" />
                    ) : (
                      <ToggleLeft className="h-10 w-10 text-slate-600 hover:text-slate-500 transition-colors" />
                    )}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>

        {/* --- RIGHT COL: KNOWLEDGE BASE --- */}
        <div className="space-y-6">
          <h2 className="text-xl font-semibold text-white flex items-center gap-2">
            <FileText className="h-5 w-5 text-indigo-400" />
            Knowledge Base
          </h2>
          
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
            <p className="text-sm text-slate-400 mb-4">
              Upload your organization's security policies (PDF or TXT). The AI Agent will use these to tailor its remediation advice.
            </p>

            <div className="space-y-3 mb-6">
              {docs.map((doc) => (
                <div key={doc.id} className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800 group">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <FileText className="h-4 w-4 text-indigo-400 flex-shrink-0" />
                    <span className="text-sm text-slate-300 truncate">{doc.filename}</span>
                  </div>
                  <button 
                    onClick={() => handleDeleteDoc(doc.id)}
                    className="text-slate-600 hover:text-rose-500 transition-colors p-1"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))}
              
              {docs.length === 0 && (
                <div className="text-center p-4 text-slate-600 text-sm border border-dashed border-slate-800 rounded-lg">
                  No policies uploaded. AI is using default standards.
                </div>
              )}
            </div>

            <label className={`block w-full cursor-pointer ${uploading ? 'opacity-50 pointer-events-none' : ''}`}>
              <div className="w-full bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg py-3 flex items-center justify-center gap-2 font-medium transition-colors shadow-lg shadow-indigo-500/20">
                {uploading ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : (
                  <Upload className="h-5 w-5" />
                )}
                {uploading ? 'Uploading...' : 'Upload Policy Doc'}
              </div>
              <input 
                type="file" 
                accept=".txt,.md,.pdf" 
                onChange={handleUpload}
                className="hidden" 
              />
            </label>
          </div>
        </div>

      </div>
    </div>
  );
}

function Badge({ label, color }: { label: string, color: 'slate' | 'rose' | 'emerald' }) {
  const colors = {
    slate: "bg-slate-800 text-slate-300 border-slate-700",
    rose: "bg-rose-900/30 text-rose-300 border-rose-800",
    emerald: "bg-emerald-900/30 text-emerald-300 border-emerald-800",
  };
  
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium border ${colors[color]}`}>
      {label}
    </span>
  );
}