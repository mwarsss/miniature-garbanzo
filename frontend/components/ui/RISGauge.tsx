'use client';

import React, { useState, useEffect } from 'react';

export interface RISGaugeProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  animate?: boolean;
}

export default function RISGauge({
  score,
  size = 80,
  strokeWidth = 8,
  animate = true,
}: RISGaugeProps) {
  const [displayed, setDisplayed] = useState(animate ? 0 : score);

  useEffect(() => {
    if (!animate) {
      setDisplayed(score);
      return;
    }
    const raf = requestAnimationFrame(() => setDisplayed(score));
    return () => cancelAnimationFrame(raf);
  }, [score, animate]);

  // Keep arc inside the 100×100 viewBox regardless of strokeWidth
  const R = 50 - strokeWidth - 2;
  const CIRCUMFERENCE = 2 * Math.PI * R;
  const offset = CIRCUMFERENCE * (1 - displayed);
  const strokeColor =
    score >= 0.8 ? '#10b981' : score >= 0.5 ? '#f59e0b' : '#f43f5e';

  return (
    <svg
      viewBox="0 0 100 100"
      width={size}
      height={size}
      aria-label={`RIS score ${Math.round(score * 100)}`}
    >
      {/* Track */}
      <circle
        cx="50"
        cy="50"
        r={R}
        fill="none"
        stroke="#1e293b"
        strokeWidth={strokeWidth}
      />
      {/* Arc */}
      <circle
        cx="50"
        cy="50"
        r={R}
        fill="none"
        stroke={strokeColor}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeDasharray={CIRCUMFERENCE}
        strokeDashoffset={offset}
        transform="rotate(-90 50 50)"
        style={animate ? { transition: 'stroke-dashoffset 1.1s ease-out' } : undefined}
      />
      {/* Score */}
      <text
        x="50"
        y="46"
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize="22"
        fontWeight="bold"
        fill="white"
      >
        {Math.round(score * 100)}
      </text>
      <text
        x="50"
        y="65"
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize="11"
        fill="#94a3b8"
      >
        RIS
      </text>
    </svg>
  );
}
