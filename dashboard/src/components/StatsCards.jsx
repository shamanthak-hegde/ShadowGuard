import React from 'react';
import { useAnimatedCounter } from '../hooks/useAnimatedCounter';

function StatCard({ icon, label, value, isFloat, trend, colorClass }) {
  const animated = useAnimatedCounter(value);

  return (
    <div className="glass-panel p-4 flex items-center gap-4 hover:border-sg-cyan/30 transition-all">
      <div className="text-2xl">{icon}</div>
      <div className="flex-1">
        <div className={`text-2xl font-mono font-bold ${colorClass || 'text-white'}`}>
          {isFloat ? animated.toFixed(1) : animated}
        </div>
        <div className="text-xs text-gray-400 mt-0.5">{label}</div>
      </div>
      {trend && (
        <div className={`text-xs font-mono ${trend.startsWith('↑') ? 'text-sg-green' : 'text-sg-red'}`}>
          {trend}
        </div>
      )}
    </div>
  );
}

export default function StatsCards({ stats }) {
  const avgRiskColor =
    stats.avg_risk_score < 30
      ? 'text-sg-green'
      : stats.avg_risk_score < 60
        ? 'text-sg-amber'
        : 'text-sg-red';

  return (
    <div className="grid grid-cols-4 gap-4 mb-4">
      <StatCard
        icon="🛡️"
        label="Total Intercepted"
        value={stats.total_requests}
        trend="↑12%"
      />
      <StatCard
        icon="🚨"
        label="PHI Detected"
        value={stats.phi_detected}
        trend="↑8%"
        colorClass="text-sg-red"
      />
      <StatCard
        icon="✂️"
        label="Requests Redacted"
        value={stats.requests_redacted}
        colorClass="text-sg-amber"
      />
      <StatCard
        icon="⚡"
        label="Avg Risk Score"
        value={stats.avg_risk_score}
        isFloat
        colorClass={avgRiskColor}
      />
    </div>
  );
}
