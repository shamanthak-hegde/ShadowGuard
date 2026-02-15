import React from 'react';
import StatusBadge from './StatusBadge';
import { updateEventStatus } from '../lib/api';

function timeAgo(timestamp) {
  const now = Date.now();
  const then = new Date(timestamp).getTime();
  const seconds = Math.floor((now - then) / 1000);

  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

const serviceIcons = {
  ChatGPT: '🤖',
  Claude: '🟣',
  Gemini: '💎',
};

const borderColors = {
  critical: 'border-l-sg-red',
  high: 'border-l-sg-amber',
  medium: 'border-l-yellow-500',
  low: 'border-l-sg-cyan',
  clean: 'border-l-sg-green',
};

function ThreatCard({ event, isNew, onClick }) {
  const phiTypes = Array.isArray(event.phi_types)
    ? event.phi_types
    : [];

  const handleStatusChange = async (e) => {
    e.stopPropagation();
    try {
      await updateEventStatus(event.event_id, e.target.value);
    } catch (err) {
      // silent fail
    }
  };

  return (
    <div
      onClick={() => onClick(event)}
      className={`glass-panel p-3 border-l-4 ${borderColors[event.severity] || 'border-l-sg-cyan'} cursor-pointer hover:bg-white/5 transition-all ${isNew ? 'slide-in' : ''} ${event.severity === 'critical' ? 'critical-glow' : ''}`}
    >
      <div className="flex items-start justify-between mb-1.5">
        <span className="text-[0.65rem] text-gray-500 font-mono">
          {timeAgo(event.timestamp)}
        </span>
        <StatusBadge severity={event.severity} />
      </div>

      <div className="flex items-center gap-2 mb-1">
        <span className="text-sm">
          {serviceIcons[event.ai_service] || '🔗'}
        </span>
        <span className="text-xs font-semibold text-white">
          {event.ai_service}
        </span>
      </div>

      <div className="text-[0.65rem] font-mono text-gray-400 mb-1.5">
        {event.source_ip}
      </div>

      {phiTypes.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {phiTypes.slice(0, 4).map((t, i) => (
            <span key={i} className="phi-tag">{t}</span>
          ))}
          {phiTypes.length > 4 && (
            <span className="phi-tag">+{phiTypes.length - 4}</span>
          )}
        </div>
      )}

      {event.voice_call && (
        <div className="flex items-center gap-1.5 mb-2">
          <span className="text-xs">📞</span>
          <span className="text-[0.6rem] font-mono text-sg-amber">
            Voice alert {event.voice_call.status}
          </span>
        </div>
      )}

      <select
        value={event.status || 'active'}
        onChange={handleStatusChange}
        onClick={(e) => e.stopPropagation()}
        className="status-select w-full"
      >
        <option value="active">Active</option>
        <option value="mitigated">Mitigated</option>
        <option value="resolved">Resolved</option>
      </select>
    </div>
  );
}

export default function ThreatFeed({ events, newEventIds, onSelectEvent }) {
  const [showAll, setShowAll] = React.useState(false);
  const filtered = showAll ? events : events.filter((e) => e.phi_detected);

  return (
    <div className="glass-panel p-3 flex flex-col h-full">
      <div className="flex items-center justify-between mb-3 px-1">
        <h3 className="text-xs font-semibold text-gray-400 tracking-widest uppercase">
          Live Threat Feed
        </h3>
        <button
          onClick={() => setShowAll(!showAll)}
          className={`text-[0.6rem] font-mono px-2 py-0.5 rounded border transition-colors ${showAll ? 'border-sg-cyan/30 text-sg-cyan' : 'border-white/10 text-gray-500 hover:text-gray-300'}`}
        >
          {showAll ? 'ALL' : 'PHI ONLY'}
        </button>
      </div>
      <div className="flex-1 overflow-y-auto space-y-2 pr-1" style={{ maxHeight: 'calc(100vh - 280px)' }}>
        {filtered.map((event) => (
          <ThreatCard
            key={event.event_id}
            event={event}
            isNew={newEventIds.has(event.event_id)}
            onClick={onSelectEvent}
          />
        ))}
        {filtered.length === 0 && (
          <div className="text-center text-gray-500 text-xs py-8 font-mono">
            No events yet
          </div>
        )}
      </div>
    </div>
  );
}
