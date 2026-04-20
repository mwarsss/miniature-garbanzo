/*
 * PatchDiffScoringPanel.tsx
 *
 * ASSUMPTIONS
 * -----------
 * 1. Rendered inside each expanded FindingCard in AgentPipelineReceipt.tsx, below
 *    the step tracker and diff view. It inherits the same dark slate palette and
 *    is never rendered standalone — no independent scroll context needed.
 *
 * 2. All sub-objects (ris_breakdown, dual_scan_result, diff_summary) may be null.
 *    Every section degrades to a muted placeholder rather than crashing.
 *
 * 3. Bandit findings in new_bandit_findings follow the bandit JSON schema:
 *    { test_id, test_name, issue_severity, issue_confidence, line_number }.
 *    Semgrep findings follow: { check_id, extra: { message } }.
 *    Both are typed `any[]` in the backend interface — accessed with optional
 *    chaining so unknown shapes render gracefully.
 *
 * 4. Bar animations use the same requestAnimationFrame + CSS-transition pattern
 *    as AgentPipelineReceipt. No extra animation libraries needed.
 *
 * 5. The breakdown bar scale treats 0.40 as 100% width (the largest single
 *    positive contribution). Penalty bars use the same scale in red.
 *
 * 6. Verdict explanations are derived dynamically from live data values —
 *    no hardcoded strings that don't reflect actual scores.
 *
 * 7. Functions-modified tooltip is implemented with the native <title> SVG/HTML
 *    approach (hover title attribute) to avoid adding any new dependency.
 *    A visible pill list is also rendered below the stats grid.
 *
 * 8. The print stylesheet in AgentPipelineReceipt targets `.apt-root *` with
 *    visibility:visible, which includes this component since it is a descendant.
 *    No additional print CSS needed here.
 */

'use client';

import React, { useState, useEffect } from 'react';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Minus,
  ShieldCheck,
  ShieldX,
  Activity,
  GitCompare,
  Zap,
} from 'lucide-react';
import RISGauge from '@/components/ui/RISGauge';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface DiffSummary {
  lines_added: number;
  lines_removed: number;
  lines_changed_total: number;
  functions_modified: string[];
  imports_added: string[];
  imports_removed: string[];
  ast_parse_success: boolean;
}

interface DualScanResult {
  semgrep_findings: unknown[];
  bandit_findings: unknown[];
  original_vuln_eliminated: boolean;
  new_semgrep_findings: unknown[];
  new_bandit_findings: unknown[];
  total_new_issues: number;
  bandit_skipped: boolean;
  semgrep_tool_error: boolean;
  bandit_tool_error: boolean;
}

interface RISBreakdown {
  vuln_eliminated_contribution: number;
  confidence_contribution: number;
  tool_reliability_contribution: number;
  clean_patch_contribution: number;
  new_findings_penalty: number;
  imports_penalty: number;
  diff_size_penalty: number;
}

export interface PatchDiffScoringPanelProps {
  finding: {
    finding_id: string;
    vuln_type: string;
    ris_score: number | null;
    verdict: 'AUTO_APPLY' | 'REVIEW_RECOMMENDED' | 'MANUAL_REMEDIATION_REQUIRED';
    rigorous_ris: boolean;
    diff_summary: DiffSummary | null;
    dual_scan_result: DualScanResult | null;
    ris_breakdown: RISBreakdown | null;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

// BAR_SCALE: the max value mapped to 100% bar width (largest single contribution)
const BAR_SCALE = 0.40;

const BREAKDOWN_FACTORS: {
  key: keyof RISBreakdown;
  label: string;
  isPositive: boolean;
}[] = [
  { key: 'vuln_eliminated_contribution', label: 'Vulnerability Eliminated', isPositive: true },
  { key: 'confidence_contribution', label: 'Model Confidence', isPositive: true },
  { key: 'tool_reliability_contribution', label: 'Tool Reliability', isPositive: true },
  { key: 'clean_patch_contribution', label: 'Clean Patch (No New Issues)', isPositive: true },
  { key: 'new_findings_penalty', label: 'New Findings Penalty', isPositive: false },
  { key: 'imports_penalty', label: 'Imports Added Penalty', isPositive: false },
  { key: 'diff_size_penalty', label: 'Diff Size Penalty', isPositive: false },
];

const SEVERITY_CHIP: Record<string, string> = {
  HIGH: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
  MEDIUM: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  LOW: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  UNDEFINED: 'bg-slate-700/50 text-slate-400 border-slate-700',
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function fmt(n: number, positive: boolean): string {
  const sign = positive ? '+' : '-';
  return `${sign}${Math.abs(n).toFixed(2)}`;
}

function buildReviewReasons(
  breakdown: RISBreakdown | null,
  dual: DualScanResult | null,
  diff: DiffSummary | null,
): string[] {
  const reasons: string[] = [];

  if (breakdown) {
    const confPct = Math.round((breakdown.confidence_contribution / 0.25) * 100);
    if (confPct < 70) {
      reasons.push(`Model confidence was ${confPct}% (below recommended 70%)`);
    }
    if (breakdown.diff_size_penalty > 0) {
      const lines = diff?.lines_changed_total ?? 0;
      reasons.push(`Patch is large — ${lines} lines changed (diff size penalty applied)`);
    }
    if (breakdown.imports_penalty > 0) {
      const n = diff?.imports_added.length ?? Math.round(breakdown.imports_penalty / 0.05);
      reasons.push(`${n} new import${n !== 1 ? 's' : ''} added to the patched file`);
    }
  }

  if (dual) {
    if (dual.new_bandit_findings.length > 0) {
      const n = dual.new_bandit_findings.length;
      reasons.push(`Bandit detected ${n} new issue${n !== 1 ? 's' : ''} in the patch`);
    }
    if (dual.new_semgrep_findings.length > 0) {
      const n = dual.new_semgrep_findings.length;
      reasons.push(`Semgrep flagged ${n} new finding${n !== 1 ? 's' : ''}`);
    }
    if (!dual.original_vuln_eliminated) {
      reasons.push('Original vulnerability was not confirmed eliminated by dual-tool scan');
    }
  }

  return reasons.slice(0, 3);
}

function buildManualReasons(
  breakdown: RISBreakdown | null,
  dual: DualScanResult | null,
): string[] {
  const reasons: string[] = [];

  if (dual) {
    if (!dual.original_vuln_eliminated) {
      reasons.push('the original vulnerability was not confirmed eliminated');
    }
    if (dual.new_semgrep_findings.length > 2) {
      reasons.push(`Semgrep detected ${dual.new_semgrep_findings.length} new findings introduced by the patch`);
    }
    if (dual.semgrep_tool_error) {
      reasons.push('Semgrep validation could not run — results are unreliable');
    }
  }

  if (breakdown) {
    const confPct = Math.round((breakdown.confidence_contribution / 0.25) * 100);
    if (confPct < 40) {
      reasons.push(`model confidence was very low (${confPct}%)`);
    }
    if (breakdown.new_findings_penalty >= 0.20) {
      reasons.push('multiple new security findings were introduced');
    }
  }

  return reasons.slice(0, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 1 sub-components
// ─────────────────────────────────────────────────────────────────────────────

function BreakdownBar({
  label,
  value,
  isPositive,
  index,
  animated,
}: {
  label: string;
  value: number;
  isPositive: boolean;
  index: number;
  animated: boolean;
}) {
  const pct = Math.min((value / BAR_SCALE) * 100, 100);
  const isEmpty = value === 0;

  const barColor = isEmpty
    ? 'bg-slate-700'
    : isPositive
    ? pct >= 75
      ? 'bg-emerald-400'
      : pct >= 40
      ? 'bg-emerald-500'
      : 'bg-emerald-600'
    : 'bg-rose-500';

  return (
    <div className="flex items-center gap-3">
      {/* Label */}
      <span
        className="text-xs text-slate-400 w-52 flex-shrink-0 text-right leading-tight"
        title={label}
      >
        {label}
      </span>

      {/* Bar track */}
      <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${barColor}`}
          style={{
            width: animated ? `${Math.max(pct, isEmpty ? 0.5 : 1)}%` : '0%',
            transitionDelay: `${index * 60}ms`,
          }}
        />
      </div>

      {/* Value */}
      <span
        className={`text-xs font-mono w-12 text-right flex-shrink-0 ${
          isEmpty
            ? 'text-slate-600'
            : isPositive
            ? 'text-emerald-400'
            : 'text-rose-400'
        }`}
      >
        {fmt(value, isPositive)}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 2 sub-components
// ─────────────────────────────────────────────────────────────────────────────

function SemgrepPanel({ dual }: { dual: DualScanResult }) {
  if (dual.semgrep_tool_error) {
    return (
      <div className="flex items-start gap-2 p-3 rounded-lg bg-rose-500/5 border border-rose-500/20">
        <AlertTriangle className="h-4 w-4 text-rose-400 flex-shrink-0 mt-0.5" />
        <span className="text-xs text-rose-400">
          Semgrep did not run — results unavailable
        </span>
      </div>
    );
  }

  const pass =
    dual.original_vuln_eliminated && dual.new_semgrep_findings.length === 0;

  return (
    <div className="space-y-2">
      {/* Status chip */}
      <div
        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${
          dual.original_vuln_eliminated
            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
            : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
        }`}
      >
        {dual.original_vuln_eliminated ? (
          <CheckCircle2 className="h-3 w-3" />
        ) : (
          <XCircle className="h-3 w-3" />
        )}
        {dual.original_vuln_eliminated
          ? 'Original vuln eliminated ✓'
          : 'Still detected ✗'}
      </div>

      {/* New findings */}
      {dual.new_semgrep_findings.length > 0 && (
        <div className="space-y-1.5">
          {(dual.new_semgrep_findings as Record<string, unknown>[]).map(
            (f, i) => (
              <div
                key={i}
                className="text-xs px-2.5 py-1.5 rounded-lg bg-amber-500/5 border border-amber-500/20"
              >
                <span className="font-mono text-amber-400 block truncate">
                  {String(f?.check_id ?? f?.rule_id ?? 'unknown-rule')}
                </span>
                <span className="text-slate-500 leading-snug">
                  {String(
                    (f?.extra as Record<string, unknown>)?.message ??
                      f?.message ??
                      'No message'
                  ).slice(0, 120)}
                </span>
              </div>
            )
          )}
        </div>
      )}

      {dual.new_semgrep_findings.length === 0 && !dual.semgrep_tool_error && (
        <p className="text-xs text-slate-500 italic">
          {pass ? 'No new findings introduced.' : 'No new findings, but vuln persists.'}
        </p>
      )}
    </div>
  );
}

function BanditPanel({ dual }: { dual: DualScanResult }) {
  if (dual.bandit_skipped) {
    return (
      <p className="text-xs text-slate-500 italic">
        Skipped — non-Python file
      </p>
    );
  }

  if (dual.bandit_tool_error) {
    return (
      <div className="flex items-start gap-2 p-3 rounded-lg bg-rose-500/5 border border-rose-500/20">
        <AlertTriangle className="h-4 w-4 text-rose-400 flex-shrink-0 mt-0.5" />
        <span className="text-xs text-rose-400">
          Bandit did not run — results unavailable
        </span>
      </div>
    );
  }

  if (dual.new_bandit_findings.length === 0) {
    return (
      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
        <CheckCircle2 className="h-3 w-3" />
        No issues detected ✓
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      {(dual.new_bandit_findings as Record<string, unknown>[]).map((f, i) => {
        const sev = String(f?.issue_severity ?? 'UNDEFINED').toUpperCase();
        return (
          <div
            key={i}
            className="flex items-start gap-2 text-xs px-2.5 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700"
          >
            <span
              className={`px-1.5 py-0.5 rounded border text-xs font-bold flex-shrink-0 ${
                SEVERITY_CHIP[sev] ?? SEVERITY_CHIP.UNDEFINED
              }`}
            >
              {sev}
            </span>
            <span className="text-slate-300 leading-snug">
              {String(f?.test_name ?? f?.issue_text ?? 'Unknown issue')}
            </span>
            {f?.line_number !== undefined && (
              <span className="ml-auto text-slate-600 font-mono flex-shrink-0">
                L{String(f.line_number)}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 3 — Diff Stats Grid
// ─────────────────────────────────────────────────────────────────────────────

function DiffStatsGrid({ diff }: { diff: DiffSummary }) {
  const stats = [
    {
      label: 'Lines Added',
      value: `+${diff.lines_added}`,
      color: 'text-emerald-400',
    },
    {
      label: 'Lines Removed',
      value: `-${diff.lines_removed}`,
      color: 'text-rose-400',
    },
    {
      label: 'Total Changed',
      value: String(diff.lines_changed_total),
      color: 'text-slate-200',
    },
    {
      label: 'Functions Touched',
      value: String(diff.functions_modified.length),
      color: diff.functions_modified.length > 0 ? 'text-amber-400' : 'text-slate-400',
      tooltip:
        diff.functions_modified.length > 0
          ? diff.functions_modified.join(', ')
          : undefined,
    },
    {
      label: 'Imports Added',
      value: String(diff.imports_added.length),
      color:
        diff.imports_added.length > 0 ? 'text-amber-400' : 'text-slate-400',
    },
    {
      label: 'AST Parsed',
      value: diff.ast_parse_success ? '✓' : '⚠',
      color: diff.ast_parse_success ? 'text-emerald-400' : 'text-amber-400',
    },
  ];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-3">
        {stats.map((s) => (
          <div
            key={s.label}
            title={s.tooltip}
            className={`bg-slate-950/60 rounded-xl border border-slate-800 p-3 ${
              s.tooltip ? 'cursor-help' : ''
            }`}
          >
            <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">
              {s.label}
            </p>
            <p className={`text-xl font-bold font-mono ${s.color}`}>
              {s.value}
            </p>
          </div>
        ))}
      </div>

      {/* Function pill list */}
      {diff.functions_modified.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {diff.functions_modified.map((fn) => (
            <code
              key={fn}
              className="text-xs px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono"
            >
              {fn}()
            </code>
          ))}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 4 — Verdict Explainer
// ─────────────────────────────────────────────────────────────────────────────

function VerdictExplainer({
  verdict,
  ris_score,
  breakdown,
  dual,
  diff,
}: {
  verdict: PatchDiffScoringPanelProps['finding']['verdict'];
  ris_score: number | null;
  breakdown: RISBreakdown | null;
  dual: DualScanResult | null;
  diff: DiffSummary | null;
}) {
  const scorePct = Math.round((ris_score ?? 0) * 100);

  if (verdict === 'AUTO_APPLY') {
    const confPct = breakdown
      ? Math.round((breakdown.confidence_contribution / 0.25) * 100)
      : null;
    const eliminated = dual?.original_vuln_eliminated ?? true;
    const noNewIssues = (dual?.total_new_issues ?? 0) === 0;

    return (
      <div className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20">
        <div className="flex items-center gap-2 mb-2">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          <span className="text-xs font-bold text-emerald-400 uppercase tracking-wide">
            Auto Apply — Safe to Merge
          </span>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">
          The patch scored{' '}
          <span className="font-bold text-emerald-400">{scorePct}%</span>.{' '}
          {eliminated && 'The original vulnerability was confirmed eliminated. '}
          {noNewIssues && 'No new issues were introduced. '}
          {confPct !== null &&
            confPct >= 70 &&
            `The model reported ${confPct}% confidence. `}
          This patch is safe to apply automatically.
        </p>
      </div>
    );
  }

  if (verdict === 'REVIEW_RECOMMENDED') {
    const reasons = buildReviewReasons(breakdown, dual, diff);
    return (
      <div className="p-4 rounded-xl bg-amber-500/5 border border-amber-500/20">
        <div className="flex items-center gap-2 mb-2">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <span className="text-xs font-bold text-amber-400 uppercase tracking-wide">
            Review Recommended — Manual Inspection Required
          </span>
        </div>
        <p className="text-sm text-slate-300 mb-2">
          The patch scored{' '}
          <span className="font-bold text-amber-400">{scorePct}%</span>. Human
          review is needed before applying. Specific concerns:
        </p>
        {reasons.length > 0 ? (
          <ul className="space-y-1">
            {reasons.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-400">
                <span className="text-amber-500 mt-0.5 flex-shrink-0">•</span>
                {r}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-slate-500 italic">
            Score fell between auto-apply and manual-required thresholds.
          </p>
        )}
      </div>
    );
  }

  // MANUAL_REMEDIATION_REQUIRED
  const reasons = buildManualReasons(breakdown, dual);
  return (
    <div className="p-4 rounded-xl bg-rose-500/5 border border-rose-500/20">
      <div className="flex items-center gap-2 mb-2">
        <ShieldX className="h-4 w-4 text-rose-400" />
        <span className="text-xs font-bold text-rose-400 uppercase tracking-wide">
          Manual Remediation Required — Do Not Auto-Apply
        </span>
      </div>
      <p className="text-sm text-slate-300 leading-relaxed">
        Automated remediation is not recommended. The patch scored{' '}
        <span className="font-bold text-rose-400">{scorePct}%</span>
        {reasons.length > 0 ? (
          <>
            {' '}
            — primary concern
            {reasons.length > 1 ? 's' : ''}:{' '}
            {reasons.join('; ')}.
          </>
        ) : (
          '. The overall integrity score fell below the minimum safe threshold.'
        )}
      </p>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main export
// ─────────────────────────────────────────────────────────────────────────────

export default function PatchDiffScoringPanel({
  finding,
}: PatchDiffScoringPanelProps) {
  const { ris_score, verdict, rigorous_ris, ris_breakdown, dual_scan_result, diff_summary } =
    finding;

  // Trigger bar animations on mount
  const [animated, setAnimated] = useState(false);
  useEffect(() => {
    const raf = requestAnimationFrame(() => setAnimated(true));
    return () => cancelAnimationFrame(raf);
  }, []);

  const score = ris_score ?? 0;
  const totalNewIssues = dual_scan_result?.total_new_issues ?? 0;
  const newIssuesColor =
    totalNewIssues === 0
      ? 'text-emerald-400'
      : totalNewIssues <= 2
      ? 'text-amber-400'
      : 'text-rose-400';

  return (
    <div className="space-y-5">
      {/* ── Not-rigorous banner ──────────────────────────────────────────── */}
      {!rigorous_ris && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800/60 border border-slate-700">
          <Minus className="h-3.5 w-3.5 text-slate-500 flex-shrink-0" />
          <p className="text-xs text-slate-500">
            Basic scoring only — dual-tool validation did not run for this
            finding.
          </p>
        </div>
      )}

      {/* ══ SECTION 1 — RIS Score Breakdown ═══════════════════════════════ */}
      <div className="bg-slate-950/50 rounded-xl border border-slate-800 p-5">
        <p className="text-xs text-slate-500 uppercase font-semibold tracking-wider mb-4">
          RIS Score Breakdown
        </p>

        {/* Large gauge + score */}
        <div className="flex items-center gap-5 mb-6">
          <RISGauge score={score} size={112} strokeWidth={9} />
          <div>
            <p className="text-3xl font-bold text-white">
              {Math.round(score * 100)}
              <span className="text-lg text-slate-500 font-normal">%</span>
            </p>
            <p className="text-xs text-slate-500 mt-0.5">
              Remediation Integrity Score
            </p>
            {ris_breakdown && (
              <p className="text-xs font-mono text-slate-600 mt-2 leading-relaxed">
                base&nbsp;
                <span className="text-slate-400">
                  {(
                    ris_breakdown.vuln_eliminated_contribution +
                    ris_breakdown.confidence_contribution +
                    ris_breakdown.tool_reliability_contribution +
                    ris_breakdown.clean_patch_contribution
                  ).toFixed(2)}
                </span>
                &nbsp;−&nbsp;penalty&nbsp;
                <span className="text-slate-400">
                  {(
                    ris_breakdown.new_findings_penalty +
                    ris_breakdown.imports_penalty +
                    ris_breakdown.diff_size_penalty
                  ).toFixed(2)}
                </span>
              </p>
            )}
          </div>
        </div>

        {/* Factor bars */}
        {ris_breakdown ? (
          <div className="space-y-2.5">
            {BREAKDOWN_FACTORS.map((factor, i) => (
              <BreakdownBar
                key={factor.key}
                label={factor.label}
                value={ris_breakdown[factor.key]}
                isPositive={factor.isPositive}
                index={i}
                animated={animated}
              />
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-600 italic">
            Score breakdown unavailable for this finding.
          </p>
        )}
      </div>

      {/* ══ SECTION 2 — Dual Tool Validation ══════════════════════════════ */}
      <div className="bg-slate-950/50 rounded-xl border border-slate-800 p-5">
        <p className="text-xs text-slate-500 uppercase font-semibold tracking-wider mb-4">
          Dual Tool Validation Report
        </p>

        {dual_scan_result ? (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              {/* Semgrep column */}
              <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-4">
                <div className="flex items-center gap-2 mb-3">
                  {dual_scan_result.semgrep_tool_error ? (
                    <AlertTriangle className="h-4 w-4 text-rose-400" />
                  ) : dual_scan_result.original_vuln_eliminated &&
                    dual_scan_result.new_semgrep_findings.length === 0 ? (
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <ShieldX className="h-4 w-4 text-amber-400" />
                  )}
                  <span className="text-sm font-semibold text-slate-200">
                    Semgrep
                  </span>
                </div>
                <SemgrepPanel dual={dual_scan_result} />
              </div>

              {/* Bandit column */}
              <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-4">
                <div className="flex items-center gap-2 mb-3">
                  {dual_scan_result.bandit_tool_error ? (
                    <AlertTriangle className="h-4 w-4 text-rose-400" />
                  ) : dual_scan_result.bandit_skipped ? (
                    <Minus className="h-4 w-4 text-slate-500" />
                  ) : dual_scan_result.new_bandit_findings.length === 0 ? (
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <ShieldX className="h-4 w-4 text-amber-400" />
                  )}
                  <span className="text-sm font-semibold text-slate-200">
                    Bandit
                  </span>
                </div>
                <BanditPanel dual={dual_scan_result} />
              </div>
            </div>

            {/* Summary line */}
            <div className="flex items-center gap-2">
              <Activity className="h-3.5 w-3.5 text-slate-500" />
              <span className={`text-sm font-semibold ${newIssuesColor}`}>
                {totalNewIssues} new issue{totalNewIssues !== 1 ? 's' : ''}{' '}
                introduced across both tools
              </span>
            </div>
          </>
        ) : (
          <p className="text-xs text-slate-600 italic">
            Dual-tool validation results unavailable for this finding.
          </p>
        )}
      </div>

      {/* ══ SECTION 3 — Semantic Diff Summary ═════════════════════════════ */}
      <div className="bg-slate-950/50 rounded-xl border border-slate-800 p-5">
        <div className="flex items-center gap-2 mb-4">
          <GitCompare className="h-4 w-4 text-slate-500" />
          <p className="text-xs text-slate-500 uppercase font-semibold tracking-wider">
            Semantic Diff Summary
          </p>
        </div>

        {diff_summary ? (
          <DiffStatsGrid diff={diff_summary} />
        ) : (
          <p className="text-xs text-slate-600 italic">
            Semantic diff unavailable for this finding.
          </p>
        )}
      </div>

      {/* ══ SECTION 4 — Verdict Explainer ═════════════════════════════════ */}
      <div className="bg-slate-950/50 rounded-xl border border-slate-800 p-5">
        <div className="flex items-center gap-2 mb-4">
          <Zap className="h-4 w-4 text-slate-500" />
          <p className="text-xs text-slate-500 uppercase font-semibold tracking-wider">
            Verdict Explainer
          </p>
        </div>
        <VerdictExplainer
          verdict={verdict}
          ris_score={ris_score}
          breakdown={ris_breakdown}
          dual={dual_scan_result}
          diff={diff_summary}
        />
      </div>
    </div>
  );
}
