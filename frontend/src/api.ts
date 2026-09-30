export const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8000/api';

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export function displayTime(value?: string) {
  return value ? new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—';
}

export type Incident = {
  incident_id: number;
  title: string;
  severity: string;
  risk_score: number;
  confidence: number;
  summary: string;
  first_seen: string;
  last_seen: string;
  affected_hosts: string[];
  affected_users: string[];
  source_ips: string[];
  destination_ips: string[];
  alert_count?: number;
  event_count?: number;
  kill_chain: { stages: string[]; progress: string };
};

export type EventRecord = {
  id: number;
  timestamp: string;
  event_type: string;
  source_ip?: string;
  destination_ip?: string;
  user?: string;
  hostname?: string;
  description: string;
  severity: string;
  confidence: number;
  false_positive_likelihood: number;
  kill_chain_stage: string;
  mitre_id?: string;
  explanation: string;
  incident_id?: number;
};

export type DashboardStats = {
  total_incidents: number;
  critical_incidents: number;
  high_risk_events: number;
  hosts_affected: number;
  users_affected: number;
  techniques_detected: number;
  stages_detected: number;
  severity_distribution: Record<string, number>;
  events_over_time: { time: string; count: number }[];
  top_ips: { name: string; count: number }[];
  top_hosts: { name: string; count: number }[];
  technique_distribution: { id: string; name: string; count: number }[];
  kill_chain: { stage: string; detected: boolean }[];
};

export type GraphPayload = {
  nodes: { id: string; event_id: number; label: string; entity: string; timestamp: string; severity: string; technique?: string; stage: string; evidence: string }[];
  edges: { source: string; target: string; label: string }[];
};