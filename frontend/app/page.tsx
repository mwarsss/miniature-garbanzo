'use client';
import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import AgentPipelineReceipt, {
  type RemediationFinding,
} from '@/components/AgentPipelineReceipt';
import {
  Shield,
  Search,
  AlertTriangle,
  CheckCircle,
  Server,
  Code,
  Terminal,
  ChevronRight,
  Cpu,
  Lock,
  Activity,
  FileCode,
  X
} from 'lucide-react';

// --- Types for our Data ---
interface ScanResult {
  id: string;
  repo_url: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  timestamp: string;
  findings_count?: number;
  ai_analysis?: AIAnalysis; // Add AI analysis to the ScanResult
}

interface AIAnalysis {
  summary: string;
  top_vulnerabilities: {
    name: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'CRITICAL';
    file: string;
    poc: string;
  }[];
}

interface Remediation {
  issue: string;
  fix_code: string;
  explanation: string;
}

export default function Dashboard() {
  const [repoUrl, setRepoUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [remediationPlan, setRemediationPlan] = useState<Remediation[] | null>(null);
  const [agenticResults, setAgenticResults] = useState<RemediationFinding[] | null>(null);
  const pathname = usePathname();

  // Handles initiating a scan via the backend API
  const handleScan = async () => {
    if (!repoUrl) return;
    setIsScanning(true);
    setCurrentScan(null); // Clear previous scan results
    setAiAnalysis(null);
    setRemediationPlan(null);
    setAgenticResults(null);

    try {
      const response = await fetch('https://intelli-scan-api-82554e007164.herokuapp.com/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ repo_url: repoUrl }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      setCurrentScan({
        id: data.scan_id,
        repo_url: repoUrl,
        status: data.status,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      console.error("Error starting scan:", error);
      setIsScanning(false);
      // Optionally, set an error state to display to the user
    }
  };

  // Fetch agentic remediation pipeline results
  // The endpoint now returns a list of per-finding RemediationFinding objects
  // (old `data.remediations` is undefined for the new format — modal stays hidden)
  const handleViewRemediation = async (scanId: string) => {
    try {
      const response = await fetch(`https://intelli-scan-api-82554e007164.herokuapp.com/scan/${scanId}/remediation`);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      // Legacy modal state — will be null since new format has no `.remediations` key
      setRemediationPlan((data as { remediations?: Remediation[] }).remediations ?? null);
      // Agentic pipeline receipt
      setAgenticResults(Array.isArray(data) ? (data as RemediationFinding[]) : null);
    } catch (error) {
      console.error("Error fetching remediation plan:", error);
    }
  };

  // Polling mechanism to check scan status
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;

    if (currentScan && (currentScan.status === 'queued' || currentScan?.status === 'processing')) {
      interval = setInterval(async () => {
        try {
          const response = await fetch(`https://intelli-scan-api-82554e007164.herokuapp.com/scan/${currentScan.id}`);
          if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
          }
          const data = await response.json();

          const newScanResult: ScanResult = {
            ...currentScan,
            status: data.status,
            findings_count: data.result?.total_findings, // Assuming backend provides total_findings
            ai_analysis: data.result?.ai_analysis // Capture AI analysis
          };

          setCurrentScan(newScanResult);

          if (data.status === 'completed' || data.status === 'failed') {
            if (interval) clearInterval(interval);
            setIsScanning(false);

            if (data.status === 'completed' && data.result?.ai_analysis) {
              setAiAnalysis(data.result.ai_analysis);
            }
          }
        } catch (error) {
          console.error("Error polling scan status:", error);
          if (interval) clearInterval(interval);
          setIsScanning(false);
          setCurrentScan(prev => ({ ...prev!, status: 'failed' }));
        }
      }, 2000); // Poll every 2 seconds
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [currentScan]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-indigo-500 selection:text-white">

      {/* --- SIDEBAR --- */}
      <aside className="fixed left-0 top-0 h-full w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
        <div className="p-6 flex items-center gap-3">
          <div className="h-8 w-8 bg-indigo-600 rounded-lg flex items-center justify-center shadow-lg shadow-indigo-500/20">
            <Shield className="text-white h-5 w-5" />
          </div>
          <span className="font-bold text-xl tracking-tight text-white">IntelliScan</span>
        </div>

        <nav className="flex-1 px-4 space-y-2 mt-4">
          <NavItem icon={<Activity />} label="Dashboard" href="/" />
          <NavItem icon={<Server />} label="Scans" href="/scans" />
          <NavItem icon={<Lock />} label="Policies" href="/policies" />

          <NavItem icon={<FileCode />} label="Reports" href="/reports" />
        </nav>

        <div className="p-4 border-t border-slate-800">
          <div className="bg-slate-800/50 rounded-xl p-4">
            <p className="text-xs text-slate-400 uppercase font-semibold mb-2">System Status</p>
            <div className="flex items-center gap-2 text-sm text-emerald-400">
              <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              API Online
            </div>
            <div className="flex items-center gap-2 text-sm text-emerald-400 mt-1">
              <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              DB Connected
            </div>
          </div>
        </div>
      </aside>

      {/* --- MAIN CONTENT --- */}
      <main className="ml-64 p-8">

        {/* Header */}
        <header className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
            <p className="text-slate-400">Real-time vulnerability assessment & remediation.</p>
          </div>
          <div className="flex gap-4">
            <button className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-sm font-medium transition-colors">
              Documentation
            </button>
            <div className="h-10 w-10 rounded-full bg-gradient-to-tr from-indigo-500 to-purple-500 border-2 border-slate-900 shadow-xl" />
          </div>
        </header>

        {/* Scan Input Section */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 mb-8 backdrop-blur-sm">
          <label className="block text-sm font-medium text-slate-300 mb-2">Target Repository</label>
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-3 h-5 w-5 text-slate-500" />
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/username/repository"
                className="w-full bg-slate-950 border border-slate-700 rounded-xl py-3 pl-10 pr-4 text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-all placeholder:text-slate-600"
              />
            </div>
            <button
              onClick={handleScan}
              disabled={isScanning || !repoUrl}
              className={`px-6 py-3 rounded-xl font-bold flex items-center gap-2 shadow-lg transition-all ${
                isScanning
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-indigo-500/25 hover:shadow-indigo-500/40'
              }`}
            >
              {isScanning ? (
                <>
                  <div className="h-4 w-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Terminal className="h-5 w-5" />
                  Start Scan
                </>
              )}
            </button>
          </div>
        </div>

        {/* Results Area */}
        {currentScan?.status === 'completed' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Left Column: Stats & Raw Data */}
            <div className="space-y-6">
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                <h3 className="text-slate-400 text-sm font-semibold uppercase tracking-wider mb-4">Scan Overview</h3>
                <div className="grid grid-cols-2 gap-4">
                  <StatCard label="Total Findings" value="12" color="text-white" />
                  <StatCard label="Critical" value="1" color="text-rose-500" />
                  <StatCard label="High" value="3" color="text-orange-500" />
                  <StatCard label="Time Taken" value="24s" color="text-emerald-400" />
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                <h3 className="text-slate-400 text-sm font-semibold uppercase tracking-wider mb-4">Scanners Used</h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 bg-slate-950/50 rounded-lg border border-slate-800/50">
                    <div className="flex items-center gap-3">
                      <div className="h-2 w-2 rounded-full bg-emerald-500" />
                      <span className="font-medium">Trivy (SCA)</span>
                    </div>
                    <span className="text-xs text-slate-500">v0.48.0</span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-slate-950/50 rounded-lg border border-slate-800/50">
                    <div className="flex items-center gap-3">
                      <div className="h-2 w-2 rounded-full bg-emerald-500" />
                      <span className="font-medium">Semgrep (SAST)</span>
                    </div>
                    <span className="text-xs text-slate-500">v1.5.0</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Column: AI Analysis */}
            <div className="lg:col-span-2 space-y-6">

              {/* AI Agent Summary */}
              <div className="bg-gradient-to-br from-slate-900 to-slate-900 border border-indigo-500/30 rounded-2xl p-6 relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                  <Cpu className="h-32 w-32 text-indigo-500" />
                </div>

                <div className="flex items-center gap-2 mb-4">
                  <span className="px-2 py-1 rounded-md bg-indigo-500/20 text-indigo-300 text-xs font-bold border border-indigo-500/30">
                    GEMINI 2.0 FLASH
                  </span>
                  <h2 className="text-xl font-bold text-white">AI Security Analyst</h2>
                </div>

                <p className="text-slate-300 leading-relaxed mb-6">
                  {aiAnalysis?.summary}
                </p>

                <div className="space-y-4">
                  {aiAnalysis?.top_vulnerabilities.map((vuln, idx) => (
                    <div key={idx} className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 hover:border-slate-600 transition-colors">
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className={`h-5 w-5 ${
                            vuln.severity === 'CRITICAL' ? 'text-rose-500' :
                            vuln.severity === 'HIGH' ? 'text-orange-500' : 'text-yellow-500'
                          }`} />
                          <h4 className="font-bold text-slate-200">{vuln.name}</h4>
                        </div>
                        <span className={`text-xs font-bold px-2 py-1 rounded border ${
                          vuln.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-500 border-rose-500/20' :
                          vuln.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-500 border-orange-500/20' : 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
                        }`}>
                          {vuln.severity}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 text-xs text-slate-500 font-mono mb-3 bg-slate-900 inline-block px-2 py-1 rounded">
                        <FileCode className="h-3 w-3" />
                        {vuln.file}
                      </div>

                      <div className="bg-slate-900 rounded-lg p-3 border border-slate-800">
                        <p className="text-xs text-slate-400 font-mono">
                          <span className="text-indigo-400 font-bold">PoC: </span>
                          {vuln.poc}
                        </p>
                      </div>

                      <button
                        onClick={() => handleViewRemediation(currentScan.id)}
                        className="mt-3 text-sm text-indigo-400 hover:text-indigo-300 font-medium flex items-center gap-1 group/btn"
                      >
                        View Remediation Plan
                        <ChevronRight className="h-4 w-4 group-hover/btn:translate-x-1 transition-transform" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Agentic Remediation Pipeline ─────────────────────────────── */}
        {agenticResults && currentScan && (
          <div className="mt-10">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 bg-indigo-500/10 rounded-lg border border-indigo-500/20">
                <Cpu className="h-5 w-5 text-indigo-400" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white">
                  Agentic Remediation Pipeline
                </h2>
                <p className="text-slate-400 text-sm">
                  Per-finding triage → context → patch → validate → score
                </p>
              </div>
            </div>
            <AgentPipelineReceipt
              findings={agenticResults}
              scanId={currentScan.id}
              repoUrl={currentScan.repo_url}
              scannedAt={currentScan.timestamp}
            />
          </div>
        )}

        {!currentScan && !isScanning && (
          <div className="h-96 flex flex-col items-center justify-center text-slate-600 border-2 border-dashed border-slate-800 rounded-3xl mt-8">
            <div className="h-16 w-16 bg-slate-900 rounded-full flex items-center justify-center mb-4">
              <Search className="h-8 w-8 text-slate-700" />
            </div>
            <p className="text-lg font-medium">Ready to scan.</p>
            <p className="text-sm">Enter a repository URL above to begin analysis.</p>
          </div>
        )}

        {remediationPlan && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
            <div className="bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col">
              <div className="flex justify-between items-center p-4 border-b border-slate-800">
                <h2 className="text-lg font-bold text-white">Remediation Plan</h2>
                <button onClick={() => setRemediationPlan(null)} className="p-2 rounded-full hover:bg-slate-800">
                  <X className="h-5 w-5" />
                </button>
              </div>
              <div className="p-6 overflow-y-auto">
                <div className="space-y-6">
                  {remediationPlan.map((rem, idx) => (
                    <div key={idx} className="bg-slate-950/50 border border-slate-800 rounded-xl p-4">
                       <h4 className="font-bold text-slate-200 mb-2">{rem.issue}</h4>
                       <p className="text-sm text-slate-400 mb-3">{rem.explanation}</p>
                       <div className="bg-slate-900 rounded-lg p-3 border border-slate-800">
                         <pre><code className="text-xs text-slate-400 font-mono">{rem.fix_code}</code></pre>
                       </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

      </main>
    </div>
  );
}

function NavItem({ icon, label, href }: { icon: React.ReactNode, label: string, href: string }) {
  const pathname = usePathname();
  const active = pathname === href;

  const content = (
    <div className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
      active
        ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20'
        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
    }`}>
      {React.cloneElement(icon as React.ReactElement<{ size?: number }>, { size: 18 })}
      {label}
    </div>
  );

  return ( <Link href={href}>{content}</Link> );
}


function StatCard({ label, value, color }: { label: string, value: string, color: string }) {
  return (
    <div className="bg-slate-950/50 p-4 rounded-xl border border-slate-800/50">
      <p className="text-xs text-slate-500 mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  );
}