import React from 'react';
import StatusBadge from './StatusBadge';

function highlightPHI(text, findings) {
  if (!text || !findings || !Array.isArray(findings) || findings.length === 0) {
    return <span>{text || ''}</span>;
  }

  // Find PHI text in the original and wrap in highlights
  let result = text;
  const parts = [];
  let lastIdx = 0;

  // Sort findings by position in text (find each occurrence)
  const positions = [];
  findings.forEach((f) => {
    if (!f.text) return;
    const idx = text.indexOf(f.text, 0);
    if (idx >= 0) {
      positions.push({ start: idx, end: idx + f.text.length, type: f.entity_type, text: f.text });
    }
  });

  positions.sort((a, b) => a.start - b.start);

  // Remove overlaps
  const cleaned = [];
  positions.forEach((p) => {
    if (cleaned.length === 0 || p.start >= cleaned[cleaned.length - 1].end) {
      cleaned.push(p);
    }
  });

  cleaned.forEach((p, i) => {
    if (p.start > lastIdx) {
      parts.push(<span key={`t-${i}`}>{text.slice(lastIdx, p.start)}</span>);
    }
    parts.push(
      <span
        key={`h-${i}`}
        className="bg-red-500/20 text-sg-red border border-red-500/30 rounded px-1 py-0.5 font-mono text-xs"
        title={p.type}
      >
        {p.text}
      </span>
    );
    lastIdx = p.end;
  });

  if (lastIdx < text.length) {
    parts.push(<span key="rest">{text.slice(lastIdx)}</span>);
  }

  return <>{parts.length > 0 ? parts : <span>{text}</span>}</>;
}

function highlightRedacted(text) {
  if (!text) return <span>N/A</span>;

  const regex = /\[REDACTED_\w+\]/g;
  const parts = [];
  let lastIdx = 0;
  let match;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIdx) {
      parts.push(<span key={`t-${lastIdx}`}>{text.slice(lastIdx, match.index)}</span>);
    }
    parts.push(
      <span
        key={`r-${match.index}`}
        className="bg-sg-green/15 text-sg-green border border-sg-green/30 rounded px-1 py-0.5 font-mono text-xs"
      >
        {match[0]}
      </span>
    );
    lastIdx = match.index + match[0].length;
  }

  if (lastIdx < text.length) {
    parts.push(<span key="rest">{text.slice(lastIdx)}</span>);
  }

  return <>{parts.length > 0 ? parts : <span>{text}</span>}</>;
}

export default function RedactionViewer({ event, onClose }) {
  if (!event) return null;

  const findings = Array.isArray(event.phi_findings)
    ? event.phi_findings
    : [];

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="glass-panel w-[90vw] max-w-5xl max-h-[85vh] overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-white/5">
          <div className="flex items-center gap-4">
            <h2 className="text-sm font-semibold text-white">Redaction Details</h2>
            <StatusBadge severity={event.severity} />
            <span className="text-xs font-mono text-gray-400">
              {event.ai_service}
            </span>
            <span className="text-xs font-mono text-gray-500">
              Risk: {event.risk_score}
            </span>
            <span className="text-xs font-mono text-gray-500">
              {new Date(event.timestamp).toLocaleString()}
            </span>
            {event.voice_call && (
              <span className="flex items-center gap-1 text-xs font-mono text-sg-amber">
                📞 Voice Alert: {event.voice_call.status}
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-white/10 transition-colors text-gray-400 hover:text-white"
          >
            ✕
          </button>
        </div>

        {/* PHI Findings Summary */}
        {findings.length > 0 && (
          <div className="px-4 py-2 border-b border-white/5 flex items-center gap-2 flex-wrap">
            <span className="text-xs text-gray-400 mr-1">PHI Found:</span>
            {findings.map((f, i) => (
              <span key={i} className="phi-tag">
                {f.entity_type}: &quot;{f.text}&quot;
              </span>
            ))}
          </div>
        )}

        {/* Split panels */}
        <div className="flex-1 grid grid-cols-2 gap-0 overflow-hidden">
          {/* Original */}
          <div className="border-r border-white/5 flex flex-col">
            <div className="px-4 py-2 border-b border-white/5 bg-red-500/5">
              <span className="text-xs font-semibold text-sg-red tracking-wider uppercase">
                Original
              </span>
            </div>
            <div className="flex-1 p-4 overflow-y-auto text-sm leading-relaxed text-gray-300 whitespace-pre-wrap">
              {highlightPHI(event.original_text, findings)}
            </div>
          </div>

          {/* Redacted */}
          <div className="flex flex-col">
            <div className="px-4 py-2 border-b border-white/5 bg-sg-green/5">
              <span className="text-xs font-semibold text-sg-green tracking-wider uppercase">
                Redacted
              </span>
            </div>
            <div className="flex-1 p-4 overflow-y-auto text-sm leading-relaxed text-gray-300 whitespace-pre-wrap">
              {highlightRedacted(event.redacted_text)}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
