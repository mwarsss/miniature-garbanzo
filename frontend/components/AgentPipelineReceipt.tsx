/*
 * AgentPipelineReceipt.tsx
 *
 * ASSUMPTIONS
 * -----------
 * 1. This component is rendered inside the existing Dashboard page (app/page.tsx)
 *    under the ml-64 main content container. It does not own its scroll context —
 *    the sticky summary bar uses window scroll.
 *
 * 2. Optional fields on RemediationFinding (raw_code_snippet, function_name,
 *    imports, confidence, syntax_valid, vuln_eliminated) may be absent because
 *    the backend /scan/{id}/remediation endpoint only exposes the final result
 *    dict. All step tracker rows degrade gracefully when these fields are missing.
 *    For validation step display, `validation_passed` is used as a fallback proxy
 *    for both syntax_valid and vuln_eliminated when individual flags are absent.
 *
 * 3. react-syntax-highlighter is installed as a project dependency. The Prism
 *    variant is used with the vscDarkPlus theme — it closely matches the existing
 *    slate-950/900 dark palette without additional configuration.
 *
 * 4. Print styles are injected dynamically via a <style> tag on the "Export as PDF"
 *    button click using visibility:hidden / visibility:visible so that layout is
 *    preserved in print mode. The tag is cleaned up after window.print() resolves.
 *
 * 5. The RIS gauge is an SVG full-circle arc. The animation is driven by a CSS
 *    transition on strokeDashoffset, triggered once on mount via requestAnimationFrame
 *    to ensure the browser commits the initial (zero) state before animating to the
 *    final value.
 *
 * 6. Verdict "SKIPPED" is treated as a valid non-spec value that the backend may
 *    return for skipped findings. It is rendered with muted styles.
 *
 * 7. Language detection for syntax highlighting is based on the file_path extension.
 *    Unknown extensions default to 'python' since the codebase is Python-primary.
 */

'use client';

import React, { useState, useEffect, useCallback } from 'react';
import SyntaxHighlighter from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import {
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  XCircle,
  SkipForward,
  FileCode,
  Cpu,
  Code2,
  ShieldCheck,
  BarChart3,
  AlertTriangle,
  Printer,
  Minus,
} from 'lucide-react';
import RISGauge from '@/components/ui/RISGauge';
import PatchDiffScoringPanel, {
  type PatchDiffScoringPanelProps,
} from '@/components/PatchDiffScoringPanel';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface RemediationFinding {
  finding_id: string;
  file_path: string;
  vuln_type: string;
  priority_score: number;
  skipped: boolean;
  patched_code: string | null;
  explanation: string | null;
  ris_score: number | null;
  verdict:
    | 'AUTO_APPLY'
    | 'REVIEW_RECOMMENDED'
    | 'MANUAL_REMEDIATION_REQUIRED'
    | 'SKIPPED';
  new_findings_introduced: unknown[];
  validation_passed: boolean | null;
  // Optional pass-through fields from combined scan+remediation response
  raw_code_snippet?: string;
  function_name?: string;
  imports?: string[];
  confidence?: number;
  syntax_valid?: boolean;
  vuln_eliminated?: boolean;
  // Agentic pipeline v2 — patch integrity fields
  basic_ris?: number | null;
  rigorous_ris?: boolean;
  diff_summary?: PatchDiffScoringPanelProps['finding']['diff_summary'];
  dual_scan_result?: PatchDiffScoringPanelProps['finding']['dual_scan_result'];
  ris_breakdown?: PatchDiffScoringPanelProps['finding']['ris_breakdown'];
}

export interface AgentPipelineReceiptProps {
  findings: RemediationFinding[];
  scanId: string;
  repoUrl: string;
  scannedAt: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const VERDICT_STYLE: Record<
  RemediationFinding['verdict'],
  { badge: string; label: string; row: string }
> = {
  AUTO_APPLY: {
    badge:
      'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    label: 'Auto Apply',
    row: 'border-emerald-500/20',
  },
  REVIEW_RECOMMENDED: {
    badge: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    label: 'Review Recommended',
    row: 'border-amber-500/20',
  },
  MANUAL_REMEDIATION_REQUIRED: {
    badge: 'bg-rose-500/10 text-rose-500 border-rose-500/20',
    label: 'Manual Required',
    row: 'border-rose-500/20',
  },
  SKIPPED: {
    badge: 'bg-slate-700/50 text-slate-400 border-slate-700',
    label: 'Skipped',
    row: 'border-slate-700',
  },
};

const PRIORITY_STYLE = (score: number) => {
  if (score >= 75) return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
  if (score >= 50) return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
  if (score >= 25) return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
  return 'bg-slate-700/50 text-slate-400 border-slate-700';
};

function getLanguage(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = {
    py: 'python',
    js: 'javascript',
    ts: 'typescript',
    jsx: 'jsx',
    tsx: 'tsx',
    go: 'go',
    java: 'java',
    rb: 'ruby',
    rs: 'rust',
    cpp: 'cpp',
    c: 'c',
    sh: 'bash',
    yaml: 'yaml',
    yml: 'yaml',
    json: 'json',
    sql: 'sql',
  };
  return map[ext] ?? 'python';
}

// ─────────────────────────────────────────────────────────────────────────────
// Mini RIS bar — horizontal gauge for collapsed card header
// ─────────────────────────────────────────────────────────────────────────────

function MiniRisBar({ score }: { score: number }) {
  const pct = Math.round((score ?? 0) * 100);
  const barColor =
    pct >= 80
      ? 'bg-emerald-500'
      : pct >= 50
      ? 'bg-amber-500'
      : 'bg-rose-500';

  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs font-mono text-slate-400 w-8 text-right">
        {pct}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfidenceBar — step 3
// ─────────────────────────────────────────────────────────────────────────────

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const barColor =
    pct >= 70
      ? 'bg-emerald-500'
      : pct >= 40
      ? 'bg-amber-500'
      : 'bg-rose-500';

  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden max-w-[200px]">
        <div
          className={`h-full rounded-full transition-all duration-700 ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-sm font-semibold text-slate-300">{pct}%</span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// StepRow — single step in the tracker
// ─────────────────────────────────────────────────────────────────────────────

function StepRow({
  step,
  icon,
  title,
  isLast = false,
  children,
}: {
  step: number;
  icon: React.ReactNode;
  title: string;
  isLast?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="relative flex gap-4">
      {/* Connector line */}
      {!isLast && (
        <div className="absolute left-4 top-9 bottom-0 w-px bg-slate-800" />
      )}

      {/* Step circle */}
      <div className="flex-shrink-0 h-8 w-8 rounded-full bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center mt-1">
        <span className="text-xs font-bold text-indigo-400">{step}</span>
      </div>

      {/* Step content */}
      <div className={`flex-1 ${isLast ? '' : 'pb-6'}`}>
        <div className="flex items-center gap-2 mb-2">
          <span className="text-slate-500">{icon}</span>
          <span className="text-sm font-semibold text-slate-300 uppercase tracking-wide">
            {title}
          </span>
        </div>
        {children}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// CheckChip — ✓ / ✗ inline chip
// ─────────────────────────────────────────────────────────────────────────────

function CheckChip({
  value,
  trueLabel,
  falseLabel,
}: {
  value: boolean | null | undefined;
  trueLabel: string;
  falseLabel: string;
}) {
  if (value === null || value === undefined) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs border bg-slate-800 text-slate-500 border-slate-700">
        <Minus className="h-3 w-3" />
        N/A
      </span>
    );
  }
  return value ? (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs border bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
      <CheckCircle2 className="h-3 w-3" />
      {trueLabel}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs border bg-rose-500/10 text-rose-400 border-rose-500/20">
      <XCircle className="h-3 w-3" />
      {falseLabel}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffView — side-by-side code panels
// ─────────────────────────────────────────────────────────────────────────────

function DiffView({
  original,
  patched,
  language,
}: {
  original: string;
  patched: string;
  language: string;
}) {
  const codeStyle: React.CSSProperties = {
    background: 'transparent',
    padding: 0,
    margin: 0,
    fontSize: '0.7rem',
    fontFamily: 'var(--font-geist-mono, monospace)',
    lineHeight: '1.6',
  };

  return (
    <div className="grid grid-cols-2 gap-3 mt-4">
      {/* Original */}
      <div className="rounded-xl border border-rose-500/20 overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-2 bg-rose-500/10 border-b border-rose-500/20">
          <div className="h-2 w-2 rounded-full bg-rose-500" />
          <span className="text-xs font-semibold text-rose-400 uppercase tracking-wide">
            Original — Vulnerable
          </span>
        </div>
        <div className="p-3 bg-slate-950/80 overflow-x-auto max-h-72">
          {original ? (
            <SyntaxHighlighter
              language={language}
              style={vscDarkPlus}
              customStyle={codeStyle}
              wrapLines
              wrapLongLines
            >
              {original}
            </SyntaxHighlighter>
          ) : (
            <span className="text-slate-600 text-xs italic">
              Snippet not available
            </span>
          )}
        </div>
      </div>

      {/* Patched */}
      <div className="rounded-xl border border-emerald-500/20 overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-2 bg-emerald-500/10 border-b border-emerald-500/20">
          <div className="h-2 w-2 rounded-full bg-emerald-500" />
          <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wide">
            Patched — Remediated
          </span>
        </div>
        <div className="p-3 bg-slate-950/80 overflow-x-auto max-h-72">
          <SyntaxHighlighter
            language={language}
            style={vscDarkPlus}
            customStyle={codeStyle}
            wrapLines
            wrapLongLines
          >
            {patched}
          </SyntaxHighlighter>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingCard — collapsible accordion card per finding
// ─────────────────────────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: RemediationFinding }) {
  const [expanded, setExpanded] = useState(false);

  const verdictConfig = VERDICT_STYLE[finding.verdict] ?? VERDICT_STYLE.SKIPPED;
  const risScore = finding.ris_score ?? 0;
  const lang = getLanguage(finding.file_path);

  // Derive validation details — prefer explicit flags, fall back to validation_passed
  const syntaxValid =
    finding.syntax_valid !== undefined
      ? finding.syntax_valid
      : finding.validation_passed;
  const vulnEliminated =
    finding.vuln_eliminated !== undefined
      ? finding.vuln_eliminated
      : finding.validation_passed;

  const toggle = useCallback(() => setExpanded((v) => !v), []);

  return (
    <div
      className={`bg-slate-900 rounded-2xl border transition-colors ${
        finding.skipped
          ? 'border-slate-800 opacity-60'
          : verdictConfig.row
      }`}
    >
      {/* ── Collapsed header (always visible) ─────────────────────── */}
      <button
        onClick={toggle}
        className="w-full text-left p-5 flex items-center gap-4 group"
        aria-expanded={expanded}
      >
        {/* File + vuln type */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            <FileCode className="h-4 w-4 text-slate-500 flex-shrink-0" />
            <code className="text-xs font-mono text-indigo-300 truncate max-w-xs">
              {finding.file_path || 'unknown file'}
            </code>
            <span
              className={`text-xs font-bold px-2 py-0.5 rounded border ${PRIORITY_STYLE(
                finding.priority_score
              )}`}
            >
              {finding.vuln_type.replace(/_/g, '-') || 'unknown'}
            </span>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-xs text-slate-500">
              Priority&nbsp;
              <span className="text-slate-300 font-semibold">
                {finding.priority_score}
              </span>
              /100
            </span>
            <span className="text-slate-700">·</span>
            {/* Mini RIS bar */}
            <MiniRisBar score={risScore} />
          </div>
        </div>

        {/* Verdict badge */}
        <span
          className={`text-xs font-bold px-3 py-1.5 rounded-full border flex-shrink-0 ${verdictConfig.badge}`}
        >
          {verdictConfig.label}
        </span>

        {/* Chevron */}
        <span className="text-slate-600 group-hover:text-slate-400 transition-colors flex-shrink-0">
          {expanded ? (
            <ChevronDown className="h-5 w-5" />
          ) : (
            <ChevronRight className="h-5 w-5" />
          )}
        </span>
      </button>

      {/* ── Expanded content ───────────────────────────────────────── */}
      {expanded && (
        <div className="px-5 pb-6 border-t border-slate-800">
          <div className="pt-5">
            {/* ── SKIPPED BANNER ───────────────────────────────────── */}
            {finding.skipped ? (
              <div className="flex items-center gap-3 p-4 rounded-xl bg-slate-800/50 border border-slate-700">
                <SkipForward className="h-5 w-5 text-slate-400" />
                <div>
                  <p className="text-sm font-semibold text-slate-300">
                    Skipped — Low Priority
                  </p>
                  <p className="text-xs text-slate-500 mt-0.5">
                    This finding was classified as LOW severity and matched the
                    pipeline skip list. No patch was generated.
                  </p>
                </div>
              </div>
            ) : (
              <>
                {/* ── 5-STEP TRACKER ──────────────────────────────── */}
                <div className="bg-slate-950/50 rounded-xl border border-slate-800 p-5 mb-5">
                  <p className="text-xs text-slate-500 uppercase font-semibold tracking-wider mb-5">
                    Agent Pipeline Steps
                  </p>

                  {/* Step 1 — Triage */}
                  <StepRow
                    step={1}
                    icon={<AlertTriangle className="h-4 w-4" />}
                    title="Triage"
                  >
                    <div className="flex flex-wrap gap-2">
                      <span
                        className={`text-xs font-bold px-2.5 py-1 rounded-full border ${PRIORITY_STYLE(
                          finding.priority_score
                        )}`}
                      >
                        Priority Score: {finding.priority_score}/100
                      </span>
                      <span
                        className={`text-xs font-bold px-2.5 py-1 rounded-full border ${
                          finding.skipped
                            ? 'bg-slate-700/50 text-slate-400 border-slate-700'
                            : 'bg-indigo-500/10 text-indigo-300 border-indigo-500/20'
                        }`}
                      >
                        {finding.skipped ? 'Skip: Yes' : 'Skip: No'}
                      </span>
                      <span className="text-xs text-slate-500 self-center">
                        Vuln type:{' '}
                        <span className="text-slate-300 font-mono">
                          {finding.vuln_type || '—'}
                        </span>
                      </span>
                    </div>
                  </StepRow>

                  {/* Step 2 — Context */}
                  <StepRow
                    step={2}
                    icon={<Code2 className="h-4 w-4" />}
                    title="Context"
                  >
                    <div className="flex flex-wrap gap-4 text-sm">
                      <div>
                        <span className="text-slate-500 text-xs uppercase tracking-wide">
                          Enclosing scope
                        </span>
                        <p className="font-mono text-indigo-300 text-xs mt-0.5">
                          {finding.function_name ?? (
                            <span className="text-slate-600 italic">
                              Not detected
                            </span>
                          )}
                        </p>
                      </div>
                      <div>
                        <span className="text-slate-500 text-xs uppercase tracking-wide">
                          Imports detected
                        </span>
                        <p className="font-semibold text-slate-200 text-sm mt-0.5">
                          {finding.imports !== undefined
                            ? finding.imports.length
                            : '—'}
                        </p>
                      </div>
                      <div>
                        <span className="text-slate-500 text-xs uppercase tracking-wide">
                          File
                        </span>
                        <p className="font-mono text-slate-300 text-xs mt-0.5 truncate max-w-xs">
                          {finding.file_path || '—'}
                        </p>
                      </div>
                    </div>
                  </StepRow>

                  {/* Step 3 — Patch */}
                  <StepRow
                    step={3}
                    icon={<Cpu className="h-4 w-4" />}
                    title="Patch — Gemini"
                  >
                    <div className="space-y-2">
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-slate-500 w-28 flex-shrink-0">
                          Model confidence
                        </span>
                        <ConfidenceBar value={finding.confidence ?? 0} />
                        {finding.confidence === undefined && (
                          <span className="text-xs text-slate-600 italic">
                            Not reported
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-500 w-28 flex-shrink-0">
                          Patch generated
                        </span>
                        <CheckChip
                          value={finding.patched_code !== null}
                          trueLabel="Yes"
                          falseLabel="No"
                        />
                      </div>
                    </div>
                  </StepRow>

                  {/* Step 4 — Validation */}
                  <StepRow
                    step={4}
                    icon={<ShieldCheck className="h-4 w-4" />}
                    title="Validation"
                  >
                    <div className="flex flex-wrap gap-2">
                      <CheckChip
                        value={syntaxValid}
                        trueLabel="Syntax Valid"
                        falseLabel="Syntax Error"
                      />
                      <CheckChip
                        value={vulnEliminated}
                        trueLabel="Vuln Eliminated"
                        falseLabel="Vuln Remains"
                      />
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs border ${
                          finding.new_findings_introduced.length === 0
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                            : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                        }`}
                      >
                        {finding.new_findings_introduced.length === 0 ? (
                          <CheckCircle2 className="h-3 w-3" />
                        ) : (
                          <AlertTriangle className="h-3 w-3" />
                        )}
                        {finding.new_findings_introduced.length === 0
                          ? 'No new issues'
                          : `${finding.new_findings_introduced.length} new finding${
                              finding.new_findings_introduced.length > 1
                                ? 's'
                                : ''
                            } introduced`}
                      </span>
                      <CheckChip
                        value={finding.validation_passed}
                        trueLabel="Passed"
                        falseLabel="Failed"
                      />
                    </div>
                  </StepRow>

                  {/* Step 5 — RIS Score */}
                  <StepRow
                    step={5}
                    icon={<BarChart3 className="h-4 w-4" />}
                    title="RIS Score"
                    isLast
                  >
                    <div className="flex items-center gap-6">
                      <RISGauge score={risScore} size={88} />
                      <div className="space-y-3">
                        <div>
                          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">
                            Verdict
                          </p>
                          <span
                            className={`text-sm font-bold px-3 py-1.5 rounded-full border ${verdictConfig.badge}`}
                          >
                            {verdictConfig.label}
                          </span>
                        </div>
                        <div>
                          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">
                            Score formula
                          </p>
                          <p className="text-xs font-mono text-slate-500 leading-relaxed">
                            0.5·elim + 0.3·conf + 0.2·syntax − 0.1·new
                          </p>
                        </div>
                      </div>
                    </div>
                  </StepRow>
                </div>

                {/* ── DIFF VIEW ───────────────────────────────────── */}
                {finding.patched_code && (
                  <div className="mb-5">
                    <p className="text-xs text-slate-500 uppercase font-semibold tracking-wider mb-3">
                      Diff — Original vs Patched
                    </p>
                    <DiffView
                      original={finding.raw_code_snippet ?? ''}
                      patched={finding.patched_code}
                      language={lang}
                    />
                  </div>
                )}

                {/* ── EXPLANATION BLOCKQUOTE ───────────────────────── */}
                {finding.explanation && (
                  <blockquote className="border-l-4 border-indigo-500/50 bg-indigo-500/5 rounded-r-xl pl-4 pr-4 py-3 mb-5">
                    <p className="text-xs text-slate-400 uppercase font-semibold tracking-wide mb-1.5">
                      Gemini Explanation
                    </p>
                    <p className="text-sm text-slate-300 leading-relaxed">
                      {finding.explanation}
                    </p>
                  </blockquote>
                )}

                {/* ── PATCH INTEGRITY ANALYSIS ─────────────────────── */}
                <div className="border-t border-slate-800 pt-5">
                  <p className="text-xs text-slate-500 uppercase font-semibold tracking-wider mb-4">
                    Patch Integrity Analysis
                  </p>
                  <PatchDiffScoringPanel
                    finding={{
                      finding_id: finding.finding_id,
                      vuln_type: finding.vuln_type,
                      ris_score: finding.ris_score,
                      verdict: (finding.verdict === 'SKIPPED'
                        ? 'MANUAL_REMEDIATION_REQUIRED'
                        : finding.verdict) as PatchDiffScoringPanelProps['finding']['verdict'],
                      rigorous_ris: finding.rigorous_ris ?? false,
                      diff_summary: finding.diff_summary ?? null,
                      dual_scan_result: finding.dual_scan_result ?? null,
                      ris_breakdown: finding.ris_breakdown ?? null,
                    }}
                  />
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SummaryBar — sticky top bar showing aggregate stats
// ─────────────────────────────────────────────────────────────────────────────

function SummaryBar({ findings }: { findings: RemediationFinding[] }) {
  const total = findings.length;
  const autoApply = findings.filter((f) => f.verdict === 'AUTO_APPLY').length;
  const reviewRec = findings.filter(
    (f) => f.verdict === 'REVIEW_RECOMMENDED'
  ).length;
  const manual = findings.filter(
    (f) => f.verdict === 'MANUAL_REMEDIATION_REQUIRED'
  ).length;
  const skipped = findings.filter((f) => f.skipped).length;

  const scored = findings.filter((f) => f.ris_score !== null);
  const avgRis =
    scored.length > 0
      ? scored.reduce((acc, f) => acc + (f.ris_score ?? 0), 0) / scored.length
      : 0;

  const statItems = [
    { label: 'Total Processed', value: total, color: 'text-white' },
    { label: 'Auto Apply', value: autoApply, color: 'text-emerald-400' },
    { label: 'Needs Review', value: reviewRec, color: 'text-amber-400' },
    { label: 'Manual Required', value: manual, color: 'text-rose-400' },
    { label: 'Skipped', value: skipped, color: 'text-slate-400' },
  ];

  return (
    <div className="sticky top-0 z-30 bg-slate-950/95 backdrop-blur-sm border border-slate-800 rounded-2xl p-4 mb-6">
      <div className="flex items-center gap-6 flex-wrap">
        {/* Stat chips */}
        {statItems.map((s) => (
          <div key={s.label} className="flex flex-col min-w-[72px]">
            <span className="text-xs text-slate-500 uppercase tracking-wide whitespace-nowrap">
              {s.label}
            </span>
            <span className={`text-2xl font-bold ${s.color}`}>{s.value}</span>
          </div>
        ))}

        {/* Divider */}
        <div className="h-10 w-px bg-slate-800 mx-2 hidden lg:block" />

        {/* Avg RIS */}
        <div className="flex flex-col min-w-[140px]">
          <span className="text-xs text-slate-500 uppercase tracking-wide mb-1">
            Avg RIS Score
          </span>
          <div className="flex items-center gap-2">
            <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden max-w-[100px]">
              <div
                className={`h-full rounded-full transition-all duration-700 ${
                  avgRis >= 0.8
                    ? 'bg-emerald-500'
                    : avgRis >= 0.5
                    ? 'bg-amber-500'
                    : 'bg-rose-500'
                }`}
                style={{ width: `${Math.round(avgRis * 100)}%` }}
              />
            </div>
            <span
              className={`text-lg font-bold ${
                avgRis >= 0.8
                  ? 'text-emerald-400'
                  : avgRis >= 0.5
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}
            >
              {Math.round(avgRis * 100)}%
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentPipelineReceipt — main export
// ─────────────────────────────────────────────────────────────────────────────

export default function AgentPipelineReceipt({
  findings,
  scanId,
  repoUrl,
  scannedAt,
}: AgentPipelineReceiptProps) {
  const handlePrint = useCallback(() => {
    const STYLE_ID = '__apt_print__';
    const existing = document.getElementById(STYLE_ID);
    if (existing) existing.remove();

    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = `
      @media print {
        body > * { visibility: hidden !important; }
        .apt-root, .apt-root * { visibility: visible !important; }
        .apt-root { position: absolute; top: 0; left: 0; width: 100%; }
        .apt-no-print { display: none !important; }
        aside, header { display: none !important; }
      }
    `;
    document.head.appendChild(style);
    window.print();
    // Cleanup after print dialog closes
    setTimeout(() => style.remove(), 500);
  }, []);

  return (
    <div className="apt-root">
      {/* ── Summary Bar ─────────────────────────────────────────────── */}
      {findings.length > 0 && <SummaryBar findings={findings} />}

      {/* ── Scan metadata strip ─────────────────────────────────────── */}
      <div className="flex items-center gap-4 mb-5 flex-wrap">
        <span className="text-xs text-slate-500 font-mono">
          scan&nbsp;
          <span className="text-slate-400">#{scanId}</span>
        </span>
        <span className="text-slate-800">·</span>
        <span className="text-xs text-slate-500 font-mono truncate max-w-xs">
          {repoUrl}
        </span>
        <span className="text-slate-800">·</span>
        <span className="text-xs text-slate-500">
          {new Date(scannedAt).toLocaleString()}
        </span>
      </div>

      {/* ── Empty state ─────────────────────────────────────────────── */}
      {findings.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-48 border-2 border-dashed border-slate-800 rounded-2xl text-slate-600">
          <ShieldCheck className="h-10 w-10 text-slate-700 mb-3" />
          <p className="font-medium text-slate-500">
            No findings were processed by the remediation pipeline.
          </p>
          <p className="text-sm mt-1">
            Either no SAST issues were detected or all findings were filtered.
          </p>
        </div>
      ) : (
        /* ── Finding cards ─────────────────────────────────────────── */
        <div className="space-y-4">
          {findings.map((finding) => (
            <FindingCard key={finding.finding_id} finding={finding} />
          ))}
        </div>
      )}

      {/* ── Export button ───────────────────────────────────────────── */}
      {findings.length > 0 && (
        <div className="mt-8 flex justify-end apt-no-print">
          <button
            onClick={handlePrint}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-sm font-medium text-slate-300 hover:text-white transition-all"
          >
            <Printer className="h-4 w-4" />
            Export Receipt as PDF
          </button>
        </div>
      )}
    </div>
  );
}
