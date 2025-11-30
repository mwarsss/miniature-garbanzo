'use client';

import React, { useState, useEffect } from 'react';
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
  Github
} from 'lucide-react';

// --- Types ---
interface Scan {
  id: number;
  repo_url: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  submit_time: string;
  finished_at?: string;
  scan_data?: any; // We don't need full data for the list view
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

  // Fetch scans from Backend
  useEffect(() => {
    const fetchScans = async () => {
      try {
        // In prod, use process.env.NEXT_PUBLIC_API_URL
        const res = await fetch('http://localhost:8000/scans?limit=50');
        if (res.ok) {
          const data = await res.json();
          setScans(data);
        } else {
          // Fallback Mock Data for demo if API fails
          console.warn("API unavailable, using mock data");
          setScans([
            { id: 105, repo_url: 'https://github.com/juice-shop/juice-shop', status: 'completed', submit_time: new Date(Date.now() - 1000 * 60 * 5).toISOString() },
            { id: 104, repo_url: 'https://github.com/fastapi/fastapi', status: 'processing', submit_time: new Date(Date.now() - 1000 * 60 * 2).toISOString() },
            { id: 103, repo_url: 'https://github.com/facebook/react', status: 'failed', submit_time: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString() },
            { id: 102, repo_url: 'https://github.com/vercel/next.js', status: 'completed', submit_time: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString() },
          ]);
        }
      } catch (error) {
        console.error("Connection failed", error);
      } finally {
        setLoading(false);
      }
    };

    fetchScans();
  }, []);

  // Filter Logic
  const filteredScans = scans.filter(scan => {
    const matchesSearch = scan.repo_url.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-8">

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
                <tr key={scan.id} className="hover:bg-slate-800/50 transition-colors group">
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
    </div>
  );
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