import React from 'react';

export default function Header({ connected, totalEvents }) {
  return (
    <header className="glass-panel px-6 py-3 flex items-center justify-between mb-4">
      {/* Left: Logo */}
      <div className="flex items-center gap-3">
        <div className="text-2xl">🛡️</div>
        <div>
          <span className="text-lg font-bold tracking-wider text-white">
            SHADOWGUARD
          </span>
          <span className="text-xs text-gray-500 ml-2 font-mono">v1.0</span>
        </div>
      </div>

      {/* Center: Live indicator */}
      <div className="flex items-center gap-2">
        <div
          className={`w-2.5 h-2.5 rounded-full ${
            connected
              ? 'bg-sg-green live-dot-connected'
              : 'bg-sg-red live-dot-disconnected'
          }`}
        />
        <span
          className={`text-xs font-mono font-semibold tracking-widest ${
            connected ? 'text-sg-green' : 'text-sg-red'
          }`}
        >
          {connected ? 'LIVE' : 'DISCONNECTED'}
        </span>
      </div>

      {/* Right: Status */}
      <div className="flex items-center gap-4 text-xs text-gray-400 font-mono">
        <span>
          {connected ? 'WebSocket Connected' : 'Reconnecting...'}
        </span>
        <span className="text-sg-cyan">
          {totalEvents} events
        </span>
      </div>
    </header>
  );
}
