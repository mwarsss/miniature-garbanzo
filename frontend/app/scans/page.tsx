'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Server,
  Search,
  Filter,
  MoreVertical,
  ExternalLink,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  Calendar,
  Github,
  Shield,
  Activity,
  Lock,
  FileCode,
  FileText
} from 'lucide-react';

// --- Types ---
interface Scan {
  id: number;
  repo_url: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  submit_time: string;
  finished_at?: string;
  sca_result?: any;
  sast_result?: any;
  ai_analysis?: any;
}

interface ScanDetail {
  status: string;
  message?: string;
  result?: {
    sca?: any;
    sast?: any;
    ai_analysis?: {
      summary: string;
      top_vulnerabilities: { name: string; severity: string; file: string; poc: string; }[];
    };
  };
}

// Helper for relative time (e.g., "2 hours ago")
function timeAgo(dateString: string) {
  const date = new Date(dateString);
  const now = new Date();
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (seconds < 60) return 'Just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  const [showDetailModal, setShowDetailModal] = useState(false);
  const [selectedScanUuid, setSelectedScanUuid] = useState<string | null>(null);
  const [detailedScanData, setDetailedScanData] = useState<ScanDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  // Fetch scans from Backend
    useEffect(() => {
      const fetchScans = async () => {
        setLoading(true);
        try {
          const res = await fetch('https://intelli-scan-api-82554e007164.herokuapp.com/scans?limit=50');
          if (res.ok) {
            const data = await res.json();
            setScans(data);
          } else {
            console.error("Failed to fetch scans:", res.status, await res.text());
            setScans([]); // Clear scans on error
          }
        } catch (error) {
          console.error("Connection failed:", error);
          setScans([]); // Clear scans on error
        } finally {
          setLoading(false);
        }
      };
  
      fetchScans();
    }, []);

  const fetchScanDetails = async (id: string) => {
    setLoadingDetail(true);
    setShowDetailModal(true);
    setDetailedScanData(null);
    setDetailError(null);
    try {
      const res = await fetch(`https://intelli-scan-api-82554e007164.herokuapp.com/scan/${id}`);
      if (res.ok) {
        const data = await res.json();
        setDetailedScanData(data);
      } else {
        const errorData = await res.json();
        const errorMessage = errorData.detail || "Failed to load scan details.";
        console.error("Failed to fetch scan details:", errorMessage);
        setDetailError(errorMessage);
      }
    } catch (error) {
      const errorMessage = "An error occurred while fetching scan details.";
      console.error("Failed to fetch scan details:", error);
      setDetailError(errorMessage);
    } finally {
      setLoadingDetail(false);
    }
  };

  // Filter Logic
  const filteredScans = scans.filter(scan => {
    const matchesSearch = scan.repo_url.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

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

        {/* --- HEADER --- */}
        <header className="flex justify-between items-end mb-8">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 bg-indigo-500/10 rounded-lg border border-indigo-500/20">
                <Server className="h-6 w-6 text-indigo-400" />
              </div>
              <h1 className="text-3xl font-bold text-white">Scan History</h1>
            </div>
            <p className="text-slate-400">View and manage your security assessment logs.</p>
          </div>

          <button className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg font-medium transition-colors shadow-lg shadow-indigo-500/20">
            + New Scan
          </button>
        </header>

        {/* --- FILTERS --- */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 mb-6 flex gap-4 items-center">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-5 w-5 text-slate-500" />
            <input
              type="text"
              placeholder="Search repositories..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg py-2 pl-10 pr-4 text-slate-200 focus:outline-none focus:border-indigo-500 transition-colors"
            />
          </div>

          <div className="relative">
            <Filter className="absolute left-3 top-2.5 h-5 w-5 text-slate-500" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg py-2 pl-10 pr-8 text-slate-200 focus:outline-none focus:border-indigo-500 appearance-none cursor-pointer"
            >
              <option value="all">All Status</option>
              <option value="completed">Completed</option>
              <option value="processing">Processing</option>
              <option value="failed">Failed</option>
            </select>
          </div>
        </div>

        {/* --- TABLE --- */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-950/50 border-b border-slate-800 text-slate-400 text-sm uppercase tracking-wider">
                <th className="p-4 font-semibold">ID</th>
                <th className="p-4 font-semibold">Repository</th>
                <th className="p-4 font-semibold">Status</th>
                <th className="p-4 font-semibold">Date</th>
                <th className="p-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {loading ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500">
                    <div className="flex justify-center items-center gap-2">
                      <Loader2 className="h-5 w-5 animate-spin" />
                      Loading scans...
                    </div>
                  </td>
                </tr>
              ) : filteredScans.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500">
                    No scans found matching your filters.
                  </td>
                </tr>
              ) : (
                filteredScans.map((scan) => (
                  <tr 
                    key={scan.id} 
                    className="hover:bg-slate-800/50 transition-colors group cursor-pointer"
                    onClick={() => fetchScanDetails(scan.id.toString())} // Make row clickable
                  >
                    <td className="p-4 text-slate-500 font-mono text-sm">#{scan.id}</td>
                    <td className="p-4">
                      <div className="flex items-center gap-2 text-indigo-300 font-medium">
                        <Github className="h-4 w-4 text-slate-500" />
                        {scan.repo_url.replace('https://github.com/', '')}
                      </div>
                    </td>
                    <td className="p-4">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="p-4 text-slate-400 text-sm">
                      <div className="flex items-center gap-2">
                        <Clock className="h-3 w-3" />
                        {timeAgo(scan.submit_time)}
                      </div>
                    </td>
                    <td className="p-4 text-right">
                      <button className="p-2 hover:bg-slate-700 rounded-lg text-slate-400 hover:text-white transition-colors">
                        <MoreVertical className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>

          {/* Pagination Footer */}
          <div className="p-4 border-t border-slate-800 bg-slate-950/30 flex justify-between items-center text-sm text-slate-500">
            <span>Showing {filteredScans.length} results</span>
            <div className="flex gap-2">
              <button className="px-3 py-1 border border-slate-700 rounded hover:bg-slate-800 disabled:opacity-50" disabled>Previous</button>
              <button className="px-3 py-1 border border-slate-700 rounded hover:bg-slate-800">Next</button>
            </div>
          </div>
        </div>
      </main>

      {/* Scan Detail Modal */}
      {showDetailModal && (
        <div className="fixed inset-0 bg-slate-900 bg-opacity-75 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-slate-700 flex justify-between items-center">
              <h3 className="text-xl font-bold text-white">Scan Details</h3>
              <button 
                onClick={() => setShowDetailModal(false)}
                className="text-slate-400 hover:text-white"
              >
                &times;
              </button>
            </div>
            <div className="p-6">
              {loadingDetail ? (
                <div className="flex flex-col items-center justify-center p-10">
                  <Loader2 className="h-8 w-8 text-indigo-400 animate-spin mb-4" />
                  <p className="text-indigo-300">Loading scan details...</p>
                </div>
              ) : detailError ? (
                <div className="p-10 text-center text-rose-400">
                  <p>Error: {detailError}</p>
                </div>
              ) : detailedScanData && detailedScanData.result ? (
                <>
                  <div className="mb-6">
                    <p className="text-lg font-semibold text-white mb-2">AI Analysis Summary:</p>
                    <p className="text-slate-300 text-sm">
                      {detailedScanData.result.ai_analysis?.summary || "No AI summary available."}
                    </p>
                  </div>

                  {detailedScanData.result.ai_analysis?.top_vulnerabilities && detailedScanData.result.ai_analysis.top_vulnerabilities.length > 0 && (
                    <div className="mb-6">
                      <p className="text-lg font-semibold text-white mb-2">Top Vulnerabilities (AI):</p>
                      <div className="space-y-2">
                        {detailedScanData.result.ai_analysis.top_vulnerabilities.map((v, i) => (
                          <div key={i} className="bg-slate-900 p-3 rounded border border-slate-700">
                            <p className="font-medium text-red-300">{v.name} - <span className="text-slate-400">Severity: {v.severity}</span></p>
                            <p className="text-xs text-slate-500">File: {v.file}</p>
                            <p className="text-xs text-slate-500">PoC: {v.poc}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {detailedScanData.result.sast?.results && detailedScanData.result.sast.results.length > 0 && (
                    <div className="mb-6">
                      <p className="text-lg font-semibold text-white mb-2">SAST Findings:</p>
                      <p className="text-slate-300 text-sm">
                        Found {detailedScanData.result.sast.results.length} SAST issues.
                      </p>
                    </div>
                  )}

                  {detailedScanData.result.sca?.Results && detailedScanData.result.sca.Results.length > 0 && (
                    <div className="mb-6">
                      <p className="text-lg font-semibold text-white mb-2">SCA Findings:</p>
                      <p className="text-slate-300 text-sm">
                        Found {detailedScanData.result.sca.Results.reduce((acc: number, res: any) => acc + (res.Vulnerabilities?.length || 0), 0)} SCA vulnerabilities.
                      </p>
                    </div>
                  )}

                  {!detailedScanData.result.ai_analysis && !detailedScanData.result.sast?.results && !detailedScanData.result.sca?.Results && (
                    <p className="text-slate-500">No detailed findings available for this scan.</p>
                  )}
                </>
              ) : (
                <div className="p-10 text-center text-slate-500">
                  No data available for this scan. This may be because the scan is still in progress or failed.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// --- Subcomponent: NavItem ---
function NavItem({ icon, label, href }: { icon: React.ReactNode, label: string, href: string }) {
  const pathname = usePathname();
  const active = pathname === href;

  const content = (
    <div className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
      active
        ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20'
        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
    }`}>
      {React.cloneElement(icon as React.ReactElement, { size: 18 })}
      {label}
    </div>
  );

  return ( <Link href={href}>{content}</Link> );
}

// --- Subcomponent: Status Badge ---
function StatusBadge({ status }: { status: string }) {
  const styles = {
    completed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    processing: "bg-blue-500/10 text-blue-400 border-blue-500/20 animate-pulse",
    failed: "bg-rose-500/10 text-rose-500 border-rose-500/20",
    queued: "bg-slate-500/10 text-slate-400 border-slate-500/20"
  };

  const icons = {
    completed: <CheckCircle2 className="h-3 w-3" />,
    processing: <Loader2 className="h-3 w-3 animate-spin" />,
    failed: <XCircle className="h-3 w-3" />,
    queued: <Clock className="h-3 w-3" />
  };

  const key = status as keyof typeof styles;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold border ${styles[key] || styles.queued}`}>
      {icons[key]}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}