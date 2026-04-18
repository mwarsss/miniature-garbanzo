'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';

import { usePathname } from 'next/navigation';
import {
  FileText,
  Download,
  Loader2,
  CheckCircle,
  Shield,
  Activity,
  Server,
  Lock,
  History,
  AlertTriangle, // Import alert icon
} from 'lucide-react';

// --- Types ---
interface ScanOption {
  id: number;
  repo_url: string;
  finished_at: string;
}

interface PastReport {
  id: number;
  scan_id: number;
  filename: string;
  format: string;
  generated_at: string;
}

interface RemediationDetail {
  issue: string;
  fix_code: string;
  explanation: string;
}

interface RemediationResult {
  remediations: RemediationDetail[];
}

export default function ReportsPage() {
  const [scans, setScans] = useState<ScanOption[]>([]);
  const [pastReports, setPastReports] = useState<PastReport[]>([]);
  const [selectedScan, setSelectedScan] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [remediating, setRemediating] = useState(false);
  const [report, setReport] = useState<{ content: string, filename: string } | null>(null);
  const [remediationPlan, setRemediationPlan] = useState<RemediationResult | null>(null);
  const [error, setError] = useState<string | null>(null); // State for error messages

  // --- Data Fetching ---
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const [scansRes, reportsRes] = await Promise.all([
          fetch('https://intelli-scan-api-82554e007164.herokuapp.com/scans?limit=20'),
          fetch('https://intelli-scan-api-82554e007164.herokuapp.com/reports?limit=10')
        ]);

        if (scansRes.ok) {
          const scansData = await scansRes.json();
          const completed = scansData.filter((s: any) => s.status === 'completed');
          setScans(completed);
        } else {
          console.error("Failed to fetch scans");
          setScans([]);
        }

        if (reportsRes.ok) {
          setPastReports(await reportsRes.json());
        } else {
          console.error("Failed to fetch past reports");
          setPastReports([]);
        }

      } catch (error) {
        console.error("Backend unavailable:", error);
        setError("Backend is currently unavailable. Please try again later.");
        setScans([]);
        setPastReports([]);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);


  // --- Event Handlers ---
  const handleGenerate = async () => {
    if (!selectedScan) return;
    setGenerating(true);
    setReport(null);
    setError(null);

    try {
      const res = await fetch('https://intelli-scan-api-82554e007164.herokuapp.com/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: parseInt(selectedScan), format: 'markdown' }),
      });

      if (res.ok) {
        const data = await res.json();
        setReport({ content: data.report_content, filename: data.filename });
        const reportsRes = await fetch('https://intelli-scan-api-82554e007164.herokuapp.com/reports?limit=10');
        if (reportsRes.ok) setPastReports(await reportsRes.json());
      } else {
        const errorData = await res.json();
        const errorMessage = errorData.detail || "An unknown error occurred.";
        console.error("Failed to generate report:", errorMessage);
        setError(`Error generating report: ${errorMessage}`);
      }
    } catch (error) {
      console.error(error);
      setError("An unexpected error occurred while generating the report.");
    } finally {
      setGenerating(false);
    }
  };

  const handleRemediation = async () => {
    if (!selectedScan) {
      setError("Please select a scan before getting a remediation plan.");
      return;
    }
    setRemediating(true);
    setRemediationPlan(null);
    setError(null);
    try {
      console.log("Fetching remediation for scan ID:", selectedScan);
      const res = await fetch(`https://intelli-scan-api-82554e007164.herokuapp.com/scan/${selectedScan}/remediation`);
      if (res.ok) {
        const data = await res.json();
        setRemediationPlan(data);
      } else {
        const errorData = await res.json();
        const errorMessage = errorData.detail || "An unknown error occurred.";
        console.error("Failed to get remediation plan:", errorMessage);
        setError(`Error generating remediation: ${errorMessage}`);
      }
    } catch (error) {
      console.error("Remediation fetch error:", error);
      setError("An unexpected error occurred while fetching the remediation plan.");
    }
    finally {
      setRemediating(false);
    }
  };

  const downloadReport = (content: string, filename: string) => {
    const element = document.createElement("a");
    const file = new Blob([content], { type: 'text/markdown' });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  // Helper function to get custom display name for a report based on scan info
  const getReportDisplayName = (scanId: number): string => {
    const scan = scans.find(s => s.id === scanId);
    if (!scan) {
      return `Report for Scan #${scanId}`;
    }

    // Extract repo name from URL (e.g., "owner/repo" from "https://github.com/owner/repo")
    const repoName = scan.repo_url.replace('https://github.com/', '').replace('.git', '');
    const date = new Date(scan.finished_at).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });

    return `${repoName} - Security Report (${date})`;
  };

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
          <NavItem icon={<FileText />} label="Reports" href="/reports" />
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

        <header className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20">
              <FileText className="h-6 w-6 text-blue-400" />
            </div>
            <h1 className="text-3xl font-bold text-white">Reports Center</h1>
          </div>
          <p className="text-slate-400">Generate compliance reports and get AI-powered remediation advice.</p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">

          {/* --- Generation Section --- */}
          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-xl">
            <h2 className="text-xl font-bold text-white mb-6">Generate New Report</h2>
            <div className="mb-6">
              <label className="block text-sm font-medium text-slate-300 mb-2">1. Select a Completed Scan</label>
              <div className="relative">
                <select
                  value={selectedScan}
                  onChange={(e) => setSelectedScan(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg py-3 pl-4 pr-10 text-slate-200 focus:outline-none focus:border-blue-500 appearance-none cursor-pointer disabled:opacity-50"
                  disabled={loading}
                >
                  <option value="" disabled>-- Choose a scan --</option>
                  {scans.map(scan => (
                    <option key={scan.id} value={scan.id}>
                      #{scan.id} - {scan.repo_url.replace('https://github.com/', '')} ({new Date(scan.finished_at).toLocaleDateString()})
                    </option>
                  ))}
                </select>
                <div className="absolute right-4 top-3.5 pointer-events-none text-slate-500">▼</div>
              </div>
            </div>

            <div className="flex gap-4">
              <button
                onClick={handleGenerate}
                disabled={!selectedScan || generating}
                className={`w-full py-3 rounded-lg font-bold flex items-center justify-center gap-2 transition-all ${!selectedScan || generating
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/20'
                  }`}
              >
                {generating ? <><Loader2 className="h-5 w-5 animate-spin" />Generating...</> : <><FileText className="h-5 w-5" />Generate Report</>}
              </button>
              <button
                onClick={handleRemediation}
                disabled={remediating}
                className={`w-full py-3 rounded-lg font-bold flex items-center justify-center gap-2 transition-all ${remediating
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/20'
                  }`}
              >
                {remediating ? <><Loader2 className="h-5 w-5 animate-spin" />Analyzing...</> : <><Shield className="h-5 w-5" />Get AI Remediation</>}
              </button>
            </div>

            {error && <ErrorDisplay message={error} onClose={() => setError(null)} />}

            {report && (
              <div className="mt-8 p-4 bg-emerald-900/10 border border-emerald-900/30 rounded-lg animate-in fade-in slide-in-from-bottom-4">
                <div className="flex items-center gap-3 mb-4 text-emerald-400">
                  <CheckCircle className="h-5 w-5" />
                  <span className="font-semibold">Report Generated Successfully</span>
                </div>
                <div className="bg-slate-950 p-4 rounded border border-slate-800 text-xs font-mono text-slate-400 h-32 overflow-y-auto mb-4">
                  {report.content}
                </div>
                <button
                  onClick={() => downloadReport(report.content, report.filename)}
                  className="w-full py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white rounded-lg flex items-center justify-center gap-2 transition-colors"
                >
                  <Download className="h-4 w-4" />
                  Download {report.filename}
                </button>
              </div>
            )}

            {remediationPlan && (
              <div className="mt-8 animate-in fade-in slide-in-from-bottom-4">
                <h3 className="text-xl font-bold text-white mb-4">Top 3 AI Remediation Steps</h3>
                <div className="space-y-6">
                  {remediationPlan.remediations.map((item, index) => (
                    <div key={index} className="bg-slate-900 border border-slate-800 rounded-xl p-6">
                      <h4 className="font-bold text-lg text-indigo-400 mb-2">{index + 1}. {item.issue}</h4>
                      <p className="text-sm text-slate-300 mb-4">{item.explanation}</p>
                      <p className="text-xs text-slate-400 uppercase font-semibold mb-2">Suggested Fix:</p>
                      <code className="block w-full bg-slate-950 p-4 rounded-lg text-sm text-slate-200 border border-slate-700 whitespace-pre-wrap font-mono">
                        {item.fix_code}
                      </code>
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>

          {/* --- Past Reports Section --- */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
            <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
              <History className="h-5 w-5 text-slate-400" />
              Recent Reports
            </h3>
            <div className="space-y-3">
              {loading ? (
                <div className="text-center p-4 text-slate-500">Loading...</div>
              ) : pastReports.length > 0 ? (
                pastReports.map(pr => (
                  <div key={pr.id} className="flex items-center justify-between p-3 bg-slate-950/50 rounded-lg border border-slate-800/50">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-slate-200 truncate">{getReportDisplayName(pr.scan_id)}</p>
                      <p className="text-xs text-slate-500">
                        {pr.filename} • {new Date(pr.generated_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                      </p>
                    </div>
                    <button
                      onClick={async () => {
                        setSelectedScan(pr.scan_id.toString());
                        await handleGenerate();
                      }}
                      className="p-2 text-slate-400 hover:text-blue-400 transition-colors flex-shrink-0 ml-2"
                      title="Re-generate this report"
                    >
                      <Download className="h-4 w-4" />
                    </button>
                  </div>
                ))
              ) : (
                <div className="text-center p-4 text-slate-600 text-sm border border-dashed border-slate-800 rounded-lg">
                  No reports generated yet.
                </div>
              )}
            </div>
          </div>

        </div>
      </main>
    </div>
  );
}

// --- Subcomponent: NavItem ---
function NavItem({ icon, label, href }: { icon: React.ReactNode, label: string, href: string }) {
  const pathname = usePathname();
  const active = pathname === href;

  const content = (
    <div className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${active
      ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20'
      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
      }`}>
      {React.cloneElement(icon as React.ReactElement<{ size?: number }>, { size: 18 })}
      {label}
    </div>
  );

  return (<Link href={href}>{content}</Link>);
}

// --- Subcomponent: Error Display ---
function ErrorDisplay({ message, onClose }: { message: string, onClose: () => void }) {
  return (
    <div className="mt-6 p-4 bg-rose-900/20 border border-rose-500/30 rounded-lg flex items-center justify-between animate-in fade-in">
      <div className="flex items-center gap-3">
        <AlertTriangle className="h-5 w-5 text-rose-400" />
        <p className="font-medium text-rose-300">{message}</p>
      </div>
      <button onClick={onClose} className="text-rose-400 hover:text-white">&times;</button>
    </div>
  )
}
