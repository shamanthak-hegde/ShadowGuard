const API_BASE = 'http://localhost:8000/api';

export async function fetchStats() {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function fetchEvents(params = {}) {
  const query = new URLSearchParams();
  if (params.limit) query.set('limit', params.limit);
  if (params.offset) query.set('offset', params.offset);
  if (params.severity) query.set('severity', params.severity);
  if (params.service) query.set('service', params.service);
  if (params.status) query.set('status', params.status);

  const res = await fetch(`${API_BASE}/events?${query}`);
  if (!res.ok) throw new Error('Failed to fetch events');
  return res.json();
}

export async function fetchEvent(eventId) {
  const res = await fetch(`${API_BASE}/events/${eventId}`);
  if (!res.ok) throw new Error('Failed to fetch event');
  return res.json();
}

export async function updateEventStatus(eventId, status) {
  const res = await fetch(`${API_BASE}/events/${eventId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error('Failed to update status');
  return res.json();
}

export async function seedDatabase() {
  const res = await fetch(`${API_BASE}/seed`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to seed database');
  return res.json();
}

export async function fetchCalls(params = {}) {
  const query = new URLSearchParams();
  if (params.limit) query.set('limit', params.limit);
  if (params.event_id) query.set('event_id', params.event_id);

  const res = await fetch(`${API_BASE}/calls?${query}`);
  if (!res.ok) throw new Error('Failed to fetch calls');
  return res.json();
}

export async function fetchCallStats() {
  const res = await fetch(`${API_BASE}/calls/stats`);
  if (!res.ok) throw new Error('Failed to fetch call stats');
  return res.json();
}

export async function triggerTestCall() {
  const res = await fetch(`${API_BASE}/calls/test`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to trigger test call');
  return res.json();
}
