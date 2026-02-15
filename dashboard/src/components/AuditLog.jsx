import React, { useState, useMemo } from 'react';
import StatusBadge from './StatusBadge';
import { updateEventStatus } from '../lib/api';

function formatTime(ts) {
  if (!ts) return '--';
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

function RiskPill({ score }) {
  const color =
    score >= 70
      ? 'bg-sg-red/20 text-sg-red border-sg-red/30'
      : score >= 40
        ? 'bg-sg-amber/20 text-sg-amber border-sg-amber/30'
        : 'bg-sg-green/20 text-sg-green border-sg-green/30';

  return (
    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-mono font-semibold border ${color}`}>
      {score}
    </span>
  );
}

export default function AuditLog({ events, onSelectEvent }) {
  const [sortField, setSortField] = useState('timestamp');
  const [sortDir, setSortDir] = useState('desc');
  const [showAll, setShowAll] = useState(false);
  const [page, setPage] = useState(0);
  const pageSize = 20;

  const sorted = useMemo(() => {
    const base = showAll ? events : events.filter((e) => e.phi_detected);
    const copy = [...base];
    copy.sort((a, b) => {
      let va = a[sortField];
      let vb = b[sortField];
      if (sortField === 'timestamp') {
        va = new Date(va).getTime();
        vb = new Date(vb).getTime();
      }
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return copy;
  }, [events, sortField, sortDir, showAll]);

  const paged = sorted.slice(page * pageSize, (page + 1) * pageSize);
  const totalPages = Math.ceil(sorted.length / pageSize);

  const toggleSort = (field) => {
    if (sortField === field) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const SortHeader = ({ field, children }) => (
    <th
      onClick={() => toggleSort(field)}
      className="px-3 py-2 text-left text-xs font-semibold text-gray-400 tracking-wider uppercase cursor-pointer hover:text-sg-cyan transition-colors select-none"
    >
      {children}
      {sortField === field && (
        <span className="ml-1 text-sg-cyan">{sortDir === 'asc' ? '↑' : '↓'}</span>
      )}
    </th>
  );

  const handleStatusChange = async (eventId, newStatus) => {
    try {
      await updateEventStatus(eventId, newStatus);
    } catch (err) {
      // silent
    }
  };

  return (
    <div className="glass-panel p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-semibold text-gray-400 tracking-widest uppercase">
          Audit Log
        </h3>
        <button
          onClick={() => { setShowAll(!showAll); setPage(0); }}
          className={`text-[0.6rem] font-mono px-2 py-0.5 rounded border transition-colors ${showAll ? 'border-sg-cyan/30 text-sg-cyan' : 'border-white/10 text-gray-500 hover:text-gray-300'}`}
        >
          {showAll ? 'ALL' : 'PHI ONLY'}
        </button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/5">
              <SortHeader field="timestamp">Time</SortHeader>
              <SortHeader field="source_ip">Source IP</SortHeader>
              <SortHeader field="ai_service">Service</SortHeader>
              <SortHeader field="risk_score">Risk</SortHeader>
              <th className="px-3 py-2 text-left text-xs font-semibold text-gray-400 tracking-wider uppercase">
                PHI Types
              </th>
              <SortHeader field="action">Action</SortHeader>
              <th className="px-3 py-2 text-left text-xs font-semibold text-gray-400 tracking-wider uppercase">
                Status
              </th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-gray-400 tracking-wider uppercase">
                Call
              </th>
            </tr>
          </thead>
          <tbody>
            {paged.map((e) => {
              const phiTypes = Array.isArray(e.phi_types) ? e.phi_types : [];
              return (
                <tr
                  key={e.event_id}
                  onClick={() => onSelectEvent(e)}
                  className="border-b border-white/[0.03] hover:bg-white/[0.03] cursor-pointer transition-colors"
                >
                  <td className="px-3 py-2 text-xs font-mono text-gray-300">
                    {formatTime(e.timestamp)}
                  </td>
                  <td className="px-3 py-2 text-xs font-mono text-gray-300">
                    {e.source_ip}
                  </td>
                  <td className="px-3 py-2 text-xs text-white">
                    {e.ai_service}
                  </td>
                  <td className="px-3 py-2">
                    <RiskPill score={e.risk_score || 0} />
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {phiTypes.slice(0, 3).map((t, i) => (
                        <span key={i} className="phi-tag">{t}</span>
                      ))}
                      {phiTypes.length > 3 && (
                        <span className="phi-tag">+{phiTypes.length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <StatusBadge severity={e.action === 'redacted' ? 'high' : e.action === 'blocked' ? 'critical' : 'clean'} />
                  </td>
                  <td className="px-3 py-2" onClick={(ev) => ev.stopPropagation()}>
                    <select
                      value={e.status || 'active'}
                      onChange={(ev) => handleStatusChange(e.event_id, ev.target.value)}
                      className="status-select"
                    >
                      <option value="active">Active</option>
                      <option value="mitigated">Mitigated</option>
                      <option value="resolved">Resolved</option>
                    </select>
                  </td>
                  <td className="px-3 py-2 text-center">
                    {e.voice_call ? (
                      <span className="inline-flex items-center gap-1 text-[0.65rem] font-mono text-sg-amber">
                        📞 {e.voice_call.status}
                      </span>
                    ) : (
                      <span className="text-gray-600 text-[0.6rem]">--</span>
                    )}
                  </td>
                </tr>
              );
            })}
            {paged.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-8 text-center text-gray-500 text-xs font-mono">
                  No events to display
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-3 pt-3 border-t border-white/5">
          <span className="text-xs text-gray-500 font-mono">
            {sorted.length} events
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
              className="px-2 py-1 text-xs font-mono text-gray-400 hover:text-sg-cyan disabled:opacity-30 transition-colors"
            >
              Prev
            </button>
            <span className="text-xs font-mono text-gray-500">
              {page + 1} / {totalPages}
            </span>
            <button
              onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
              disabled={page >= totalPages - 1}
              className="px-2 py-1 text-xs font-mono text-gray-400 hover:text-sg-cyan disabled:opacity-30 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
