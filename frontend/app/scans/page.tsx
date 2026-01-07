'use client';
import React, { useState, useEffect, useMemo, useCallback } from 'react';
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
  FileText,
  AlertCircle
} from 'lucide-react';
import Modal from '@/components/Modal';

// --- Configuration ---
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'https://intelli-scan-api-82554e007164.herokuapp.com';
const SCANS_PER_PAGE = 50;

// --- Types ---
interface Scan {
  id: number;
  uuid: string;
  repo_url: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  submit_time: string;
  finished_at?: string;
  sca_result?: { Results?: Array<{ Vulnerabilities?: Array<unknown> }> };
  sast_result?: { results?: Array<unknown> };
  ai_analysis?: {
    summary: string;
    top_vulnerabilities: { name: string; severity: string; file: string; poc: string; }[];
  };
}

interface ScanDetail {
  status: string;
  result?: {
    sca?: any;
    sast?: any;
    ai_analysis?: {
      summary: string;
      top_vulnerabilities: { name: string; severity: string; file: string; poc: string; }[];
    };
  };
}

// --- Helper Functions ---
function timeAgo(dateString: string): string {
  try {
    const date = new Date(dateString);
    const now = new Date();
    const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);
    
    if (seconds < 60) return 'Just now';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `${days}d ago`;
    const months = Math.floor(days / 30);
    if (months < 12) return `${months}mo ago`;
    const years = Math.floor(months / 12);
    return `${years}y ago`;
  } catch {
    return 'Unknown';
  }
}

// --- Main Component ---
export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [detailedScanData, setDetailedScanData] = useState<ScanDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  // Fetch scans from Backend
  useEffect(() => {
    let isMounted = true;

    const fetchScans = async () => {
      setLoading(true);
      setError(null);
      
      try {
        const res = await fetch(`${API_BASE_URL}/scans?limit=${SCANS_PER_PAGE}`);
        
        if (!res.ok) {
          throw new Error(`Failed to fetch scans: ${res.status}`);
        }
        
        const data = await res.json();
        
        if (isMounted) {
          setScans(Array.isArray(data) ? data : []);
        }
      } catch (err) {
        console.error("Failed to fetch scans:", err);
        if (isMounted) {
          setError(err instanceof Error ? err.message : 'Failed to connect to the server');
          setScans([]);
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchScans();

    return () => {
      isMounted = false;
    };
  }, []);

  // Fetch scan details
  const fetchScanDetails = useCallback(async (scan: Scan) => {
    if (!scan?.uuid) {
      console.error("Invalid scan object:", scan);
      return;
    }
    
    setSelectedScan(scan);
    setLoadingDetail(true);
    setShowDetailModal(true);
    setDetailedScanData(null);
    setDetailError(null);
    
    try {
      const res = await fetch(`${API_BASE_URL}/scan/${scan.uuid}`);
      
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Failed to fetch scan details: ${res.status}`);
      }
      
      const data = await res.json();
      setDetailedScanData(data);
    } catch (err) {
      console.error("Failed to fetch scan details:", err);
      setDetailError(err instanceof Error ? err.message : 'An error occurred while fetching scan details');
    } finally {
      setLoadingDetail(false);
    }
  }, []);

  // Memoized filtered scans
  const filteredScans = useMemo(() => {
    return scans.filter(scan => {
      const matchesSearch = scan.repo_url.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [scans, searchTerm, statusFilter]);

  // Handle row click
  const handleRowClick = useCallback((scan: Scan) => {
    fetchScanDetails(scan);
  }, [fetchScanDetails]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-indigo-500 selection:text-white">
      {/* --- SIDEBAR --- */}
      <aside className="fixed left-0 top-0 h-full w-64 bg-slate-900 border-r border-slate-800 flex flex-col z-10">
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
          <Link href="/new-scan">
            <button className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg font-medium transition-colors shadow-lg shadow-indigo-500/20">
              + New Scan
            </button>
          </Link>
        </header>

        {/* --- ERROR ALERT --- */}
        {error && (
          <div className="bg-rose-500/10 border border-rose-500/20 rounded-xl p-4 mb-6 flex items-center gap-3">
            <AlertCircle className="h-5 w-5 text-rose-400 flex-shrink-0" />
            <div className="flex-1">
              <p className="text-rose-400 font-medium">Failed to load scans</p>
              <p className="text-rose-300 text-sm">{error}</p>
            </div>
            <button 
              onClick={() => window.location.reload()}
              className="px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 rounded-lg text-sm transition-colors"
            >
              Retry
            </button>
          </div>
        )}

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
              aria-label="Search repositories"
            />
          </div>
          <div className="relative">
            <Filter className="absolute left-3 top-2.5 h-5 w-5 text-slate-500 pointer-events-none" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg py-2 pl-10 pr-8 text-slate-200 focus:outline-none focus:border-indigo-500 appearance-none cursor-pointer"
              aria-label="Filter by status"
            >
              <option value="all">All Status</option>
              <option value="completed">Completed</option>
              <option value="processing">Processing</option>
              <option value="queued">Queued</option>
              <option value="failed">Failed</option>
            </select>
          </div>
        </div>

        {/* --- TABLE --- */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
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
                      <div className="flex flex-col items-center gap-2">
                        <Server className="h-12 w-12 text-slate-700" />
                        <p className="font-medium">No scans found</p>
                        <p className="text-sm">
                          {searchTerm || statusFilter !== 'all' 
                            ? 'Try adjusting your filters' 
                            : 'Start a new scan to see results here'}
                        </p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  filteredScans.map((scan, index) => (
                    <tr 
                      key={scan.id || index}
                      onClick={(e) => {
                        e.stopPropagation(); // Prevents weird bubbling issues
                        console.log("👇 CLICKED SCAN DATA:", scan); // This will prove if scan exists
                        handleRowClick(scan);
                      }}
                      className="hover:bg-slate-800 cursor-pointer transition-colors"
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleRowClick(scan);
                        }
                      }}
                    >
                      <td className="p-4 text-slate-500 font-mono text-sm">#{scan.id}</td>
                      <td className="p-4">
                        <div className="flex items-center gap-2 text-indigo-300 font-medium">
                          <Github className="h-4 w-4 text-slate-500 flex-shrink-0" />
                          <span className="truncate max-w-md">
                            {scan.repo_url.replace('https://github.com/', '')}
                          </span>
                        </div>
                      </td>
                      <td className="p-4">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="p-4 text-slate-400 text-sm">
                        <div className="flex items-center gap-2">
                          <Clock className="h-3 w-3 flex-shrink-0" />
                          <time dateTime={scan.submit_time}>{timeAgo(scan.submit_time)}</time>
                        </div>
                      </td>
                      <td className="p-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation(); // Stop the row from stealing the click
                            // Direct link to the new PDF endpoint
                            window.location.href = `https://intelli-scan-api-82554e007164.herokuapp.com/scan/${scan.uuid}/remediation-pdf`;
                          }}
                          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded-md text-xs font-medium transition-colors shadow-lg shadow-indigo-500/20"
                        >
                          {/* Icon for visual flair */}
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                          Get Plan
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          
          {/* Pagination Footer */}
          <div className="p-4 border-t border-slate-800 bg-slate-950/30 flex justify-between items-center text-sm text-slate-500">
            <span>Showing {filteredScans.length} of {scans.length} results</span>
            <div className="flex gap-2">
              <button 
                className="px-3 py-1 border border-slate-700 rounded hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed transition-colors" 
                disabled
              >
                Previous
              </button>
              <button 
                className="px-3 py-1 border border-slate-700 rounded hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                disabled
              >
                Next
              </button>
            </div>
          </div>
        </div>
      </main>

      {/* Scan Detail Modal */}
      <Modal 
        isOpen={showDetailModal} 
        onClose={() => setShowDetailModal(false)} 
        title={`Scan Details: ${selectedScan?.uuid || 'Loading...'}`}
      >
        {loadingDetail ? (
          <div className="flex flex-col items-center justify-center p-10">
            <Loader2 className="h-8 w-8 text-indigo-400 animate-spin mb-4" />
            <p className="text-indigo-300">Loading scan details...</p>
          </div>
        ) : detailError ? (
          <div className="p-10 text-center">
            <AlertCircle className="h-12 w-12 text-rose-400 mx-auto mb-4" />
            <p className="text-rose-400 font-medium mb-2">Error Loading Details</p>
            <p className="text-slate-400 text-sm">{detailError}</p>
            <button
              onClick={() => selectedScan && fetchScanDetails(selectedScan)}
              className="mt-4 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors"
            >
              Retry
            </button>
          </div>
        ) : detailedScanData && selectedScan ? (
          <div className="max-h-[70vh] overflow-y-auto">
            {/* Scan Metadata */}
            <div className="mb-6 p-4 bg-slate-800/50 rounded-lg border border-slate-700">
              <div className="flex items-center gap-2 mb-3">
                <Github className="h-5 w-5 text-slate-400" />
                <p className="text-lg font-semibold text-white truncate">
                  {selectedScan.repo_url.replace('https://github.com/', '')}
                </p>
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="text-slate-500">Status:</span>
                  <div className="mt-1">
                    <StatusBadge status={selectedScan.status} />
                  </div>
                </div>
                <div>
                  <span className="text-slate-500">Submitted:</span>
                  <p className="text-slate-300 mt-1">{timeAgo(selectedScan.submit_time)}</p>
                </div>
                {selectedScan.finished_at && (
                  <div>
                    <span className="text-slate-500">Finished:</span>
                    <p className="text-slate-300 mt-1">{timeAgo(selectedScan.finished_at)}</p>
                  </div>
                )}
              </div>
            </div>

            {/* AI Analysis Summary */}
            {detailedScanData.result?.ai_analysis?.summary && (
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
                  <Activity className="h-5 w-5 text-indigo-400" />
                  AI Analysis Summary
                </h3>
                <p className="text-slate-300 text-sm leading-relaxed bg-slate-800/30 p-4 rounded-lg border border-slate-700">
                  {detailedScanData.result.ai_analysis.summary}
                </p>
              </div>
            )}

            {/* Top Vulnerabilities */}
            {detailedScanData.result?.ai_analysis?.top_vulnerabilities && 
             detailedScanData.result.ai_analysis.top_vulnerabilities.length > 0 && (
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
                  <AlertCircle className="h-5 w-5 text-rose-400" />
                  Top Vulnerabilities
                </h3>
                <div className="space-y-3">
                  {detailedScanData.result.ai_analysis.top_vulnerabilities.map((v, i) => (
                    <div key={i} className="bg-slate-800/50 p-4 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors">
                      <div className="flex items-start justify-between mb-2">
                        <p className="font-medium text-rose-300 flex-1">{v.name}</p>
                        <SeverityBadge severity={v.severity} />
                      </div>
                      <p className="text-xs text-slate-500 mb-1">
                        <FileCode className="inline h-3 w-3 mr-1" />
                        {v.file}
                      </p>
                      {v.poc && (
                        <p className="text-xs text-slate-400 mt-2 p-2 bg-slate-900/50 rounded border border-slate-700">
                          <strong>PoC:</strong> {v.poc}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* SAST Findings */}
            {detailedScanData.result?.sast?.results && detailedScanData.result.sast.results.length > 0 && (
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
                  <FileCode className="h-5 w-5 text-blue-400" />
                  SAST Findings
                </h3>
                <div className="bg-slate-800/30 p-4 rounded-lg border border-slate-700">
                  <p className="text-slate-300 text-sm">
                    Found <span className="font-bold text-white">{detailedScanData.result.sast.results.length}</span> SAST issues.
                  </p>
                </div>
              </div>
            )}

            {/* SCA Findings */}
            {detailedScanData.result?.sca?.Results && detailedScanData.result.sca.Results.length > 0 && (
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
                  <Shield className="h-5 w-5 text-emerald-400" />
                  SCA Findings
                </h3>
                <div className="bg-slate-800/30 p-4 rounded-lg border border-slate-700">
                  <p className="text-slate-300 text-sm">
                    Found <span className="font-bold text-white">
                      {detailedScanData.result.sca.Results.reduce((acc: number, res: any) => 
                        acc + (res.Vulnerabilities?.length || 0), 0
                      )}
                    </span> SCA vulnerabilities.
                  </p>
                </div>
              </div>
            )}

            {/* No Data Message */}
            {!detailedScanData.result?.ai_analysis?.summary &&
             (!detailedScanData.result?.sast?.results || detailedScanData.result.sast.results.length === 0) &&
             (!detailedScanData.result?.sca?.Results || detailedScanData.result.sca.Results.length === 0) && (
              <div className="p-10 text-center">
                <FileText className="h-12 w-12 text-slate-700 mx-auto mb-4" />
                <p className="text-slate-500 font-medium mb-2">No Findings Available</p>
                <p className="text-slate-600 text-sm">
                  This scan may still be in progress or no vulnerabilities were detected.
                </p>
              </div>
            )}
          </div>
        ) : (
          <div className="p-10 text-center">
            <FileText className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <p className="text-slate-500">No data available for this scan.</p>
          </div>
        )}
      </Modal>
    </div>
  );
}

// --- Subcomponents ---

function NavItem({ icon, label, href }: { icon: React.ReactNode; label: string; href: string }) {
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
  
  return <Link href={href}>{content}</Link>;
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    processing: "bg-blue-500/10 text-blue-400 border-blue-500/20 animate-pulse",
    failed: "bg-rose-500/10 text-rose-500 border-rose-500/20",
    queued: "bg-slate-500/10 text-slate-400 border-slate-500/20"
  };
  
  const icons: Record<string, React.ReactNode> = {
    completed: <CheckCircle2 className="h-3 w-3" />,
    processing: <Loader2 className="h-3 w-3 animate-spin" />,
    failed: <XCircle className="h-3 w-3" />,
    queued: <Clock className="h-3 w-3" />
  };
  
  const key = status as keyof typeof styles;
  
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold border ${styles[key] || styles.queued}`}>
      {icons[key] || icons.queued}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    critical: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    info: "bg-slate-500/10 text-slate-400 border-slate-500/30"
  };
  
  const key = severity.toLowerCase() as keyof typeof styles;
  
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${styles[key] || styles.info}`}>
      {severity.toUpperCase()}
    </span>
  );
}


