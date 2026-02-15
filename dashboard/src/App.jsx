import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import Header from './components/Header';
import StatsCards from './components/StatsCards';
import ThreatFeed from './components/ThreatFeed';
import TrafficTimeline from './components/TrafficTimeline';
import RiskHeatmap from './components/RiskHeatmap';
import NetworkGraph from './components/NetworkGraph';
import AuditLog from './components/AuditLog';
import RedactionViewer from './components/RedactionViewer';
import { useWebSocket } from './hooks/useWebSocket';
import { fetchStats, fetchEvents, fetchCalls, fetchCallStats } from './lib/api';

const defaultStats = {
  total_requests: 0,
  phi_detected: 0,
  requests_redacted: 0,
  requests_clean: 0,
  avg_risk_score: 0,
  by_service: {},
  by_severity: {},
  by_hour: [],
  recent_phi_types: {},
  timeline: [],
};

export default function App() {
  const [stats, setStats] = useState(defaultStats);
  const [events, setEvents] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [newEventIds, setNewEventIds] = useState(new Set());
  const [callStats, setCallStats] = useState({ total_calls: 0, completed_calls: 0, failed_calls: 0 });
  const newEventTimeouts = useRef(new Map());

  // Load initial data
  useEffect(() => {
    async function loadData() {
      try {
        const [statsData, eventsData, callData, callsList] = await Promise.all([
          fetchStats(),
          fetchEvents({ limit: 200 }),
          fetchCallStats().catch(() => ({ total_calls: 0, completed_calls: 0, failed_calls: 0 })),
          fetchCalls({ limit: 200 }).catch(() => []),
        ]);
        setStats(statsData);
        setCallStats(callData);

        // Merge call data into events
        const callMap = {};
        callsList.forEach((c) => {
          callMap[c.event_id] = { call_id: c.call_id, status: c.status, phone_number: c.phone_number };
        });
        const enrichedEvents = eventsData.map((e) => ({
          ...e,
          voice_call: callMap[e.event_id] || null,
        }));
        setEvents(enrichedEvents);
      } catch (err) {
        console.error('Failed to load initial data:', err);
      }
    }
    loadData();
  }, []);

  // Handle WebSocket messages
  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'new_event') {
      const event = msg.data;

      // Add to events list
      setEvents((prev) => [event, ...prev]);

      // Update stats incrementally
      setStats((prev) => ({
        ...prev,
        total_requests: prev.total_requests + 1,
        phi_detected: prev.phi_detected + (event.phi_detected ? 1 : 0),
        requests_redacted: prev.requests_redacted + (event.action === 'redacted' ? 1 : 0),
        requests_clean: prev.requests_clean + (event.action === 'clean' ? 1 : 0),
        avg_risk_score:
          prev.total_requests > 0
            ? parseFloat(
                (
                  (prev.avg_risk_score * prev.total_requests + (event.risk_score || 0)) /
                  (prev.total_requests + 1)
                ).toFixed(1)
              )
            : event.risk_score || 0,
        by_service: {
          ...prev.by_service,
          [event.ai_service]: (prev.by_service[event.ai_service] || 0) + 1,
        },
        by_severity: {
          ...prev.by_severity,
          [event.severity]: (prev.by_severity[event.severity] || 0) + 1,
        },
      }));

      // Mark as new for animation
      setNewEventIds((prev) => {
        const next = new Set(prev);
        next.add(event.event_id);
        return next;
      });

      // Remove "new" marker after animation completes
      const timeout = setTimeout(() => {
        setNewEventIds((prev) => {
          const next = new Set(prev);
          next.delete(event.event_id);
          return next;
        });
      }, 2000);

      newEventTimeouts.current.set(event.event_id, timeout);
    }

    if (msg.type === 'status_update') {
      const { event_id, status } = msg.data;
      setEvents((prev) =>
        prev.map((e) =>
          e.event_id === event_id ? { ...e, status } : e
        )
      );
    }

    if (msg.type === 'voice_call') {
      const { event_id, call_id, status, phone_number } = msg.data;
      setEvents((prev) =>
        prev.map((e) =>
          e.event_id === event_id
            ? { ...e, voice_call: { call_id, status, phone_number } }
            : e
        )
      );
      setCallStats((prev) => ({ ...prev, total_calls: prev.total_calls + 1 }));
    }
  }, []);

  const { connected } = useWebSocket(handleWsMessage);

  // Cleanup timeouts on unmount
  useEffect(() => {
    return () => {
      newEventTimeouts.current.forEach((t) => clearTimeout(t));
    };
  }, []);

  // Derive stats from PHI-detected events only
  const phiStats = useMemo(() => {
    const phiEvents = events.filter((e) => e.phi_detected);
    const total = phiEvents.length;
    const avgRisk = total > 0
      ? parseFloat((phiEvents.reduce((s, e) => s + (e.risk_score || 0), 0) / total).toFixed(1))
      : 0;
    return {
      total_requests: events.length,
      phi_detected: total,
      requests_redacted: phiEvents.filter((e) => e.action === 'redacted').length,
      requests_clean: phiEvents.filter((e) => e.action === 'clean').length,
      avg_risk_score: avgRisk,
    };
  }, [events]);

  return (
    <div className="min-h-screen p-4">
      <Header connected={connected} totalEvents={events.length} />

      <StatsCards stats={phiStats} callStats={callStats} />

      {/* Main grid: ThreatFeed | Charts | NetworkGraph */}
      <div className="grid grid-cols-12 gap-4 mb-4">
        {/* Left: Threat Feed */}
        <div className="col-span-3">
          <ThreatFeed
            events={events}
            newEventIds={newEventIds}
            onSelectEvent={setSelectedEvent}
          />
        </div>

        {/* Center: Charts */}
        <div className="col-span-6 space-y-4">
          <TrafficTimeline events={events} />
          <RiskHeatmap events={events} />
        </div>

        {/* Right: Network Graph */}
        <div className="col-span-3">
          <NetworkGraph events={events} />
        </div>
      </div>

      {/* Bottom: Audit Log */}
      <AuditLog events={events} onSelectEvent={setSelectedEvent} />

      {/* Modal: Redaction Viewer */}
      {selectedEvent && (
        <RedactionViewer
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  );
}
