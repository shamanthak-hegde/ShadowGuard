import React from 'react';

const severityConfig = {
  critical: { class: 'badge-critical', label: 'CRITICAL' },
  high: { class: 'badge-high', label: 'HIGH' },
  medium: { class: 'badge-medium', label: 'MEDIUM' },
  low: { class: 'badge-low', label: 'LOW' },
  clean: { class: 'badge-clean', label: 'CLEAN' },
};

export default function StatusBadge({ severity }) {
  const config = severityConfig[severity] || severityConfig.clean;
  return (
    <span className={`badge ${config.class}`}>
      {config.label}
    </span>
  );
}
