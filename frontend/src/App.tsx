import { useEffect, useState } from 'react';
import { Link, NavLink, Route, Routes, useNavigate, useParams } from 'react-router-dom';
import { Background, Controls, ReactFlow, type Edge, type Node } from '@xyflow/react';
import {
  Activity, AlertTriangle, ArrowDownToLine, ArrowUpRight, BarChart3, BookOpen,
  Bug, Check, ChevronRight, CircleDot, Clock3, CloudUpload, FileText, Fingerprint,
  Gauge, GitBranch, HardDrive, LayoutDashboard, ListFilter, LockKeyhole, Network,
  Plus, RefreshCw, Search, Server, Settings, Shield, ShieldAlert, Upload, Users,
  X,
} from 'lucide-react';
import { API_BASE, api, displayTime, type DashboardStats, type EventRecord, type GraphPayload, type Incident } from './api';

const navItems = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { to: '/events', label: 'Event intake', icon: Activity },
  { to: '/attack-graph', label: 'Attack graph', icon: GitBranch },
  { to: '/mitre', label: 'ATT&CK library', icon: BookOpen },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/settings', label: 'Configuration', icon: Settings },
];

function App() {
  const [online, setOnline] = useState(false);
  useEffect(() => {
    api<{ status: string }>('/health').then(() => setOnline(true)).catch(() => setOnline(false));
  }, []);
  return <div className="shell">
    <aside className="sidebar">
      <Link className="brand" to="/">
        <span className="brand-mark"><Shield size={19} /></span>
        <span><strong>CHAIN / WATCH</strong><small>INCIDENT ANALYSIS</small></span>
      </Link>
      <div className="workspace-label">WORKSPACE <span>LOCAL SOC</span></div>
      <nav className="nav-list" aria-label="Main navigation">
        {navItems.map(({ to, label, icon: Icon, end }) => <NavLink key={to} to={to} end={end} className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
          <Icon size={17} strokeWidth={1.8} /><span>{label}</span>{label === 'Incidents' && <i className="nav-pulse" />}
        </NavLink>)}
      </nav>
      <div className="sidebar-bottom">
        <div className="connection"><span className={online ? 'status-light' : 'status-light offline'} />
          <span><b>{online ? 'API CONNECTED' : 'API OFFLINE'}</b><small>{online ? 'SQLite · live data' : 'Waiting for backend'}</small></span>
        </div>
        <div className="operator"><span className="operator-avatar">SA</span><span><b>Security Analyst</b><small>Local workspace</small></span><Settings size={15} /></div>
      </div>
    </aside>
    <main className="main-area">
      <header className="topbar">
        <div className="crumb"><span>SECURITY OPERATIONS</span><ChevronRight size={14} /><b>INCIDENT ANALYZER</b></div>
        <div className="topbar-actions"><div className="search-mini"><Search size={15} /><span>Search incidents</span><kbd>/</kbd></div><span className="live-indicator"><i /> LIVE</span></div>
      </header>
      <div className="page-wrap"><Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/incidents/:id" element={<IncidentPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/attack-graph" element={<AttackGraphPage />} />
        <Route path="/mitre" element={<MitrePage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFound />} />
      </Routes></div>
    </main>
  </div>;
}

function PageHeading({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail?: string; action?: React.ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{detail && <p>{detail}</p>}</div>{action && <div className="heading-action">{action}</div>}</div>;
}

function LoadingError({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return <div className="error-state"><AlertTriangle size={18} /><div><b>Could not load this view</b><p>{error}</p></div>{onRetry && <button className="icon-button" onClick={onRetry} title="Retry"><RefreshCw size={15} /></button>}</div>;
}

function Severity({ value }: { value: string }) { return <span className={`severity severity-${value.toLowerCase()}`}><i />{value}</span>; }
function formatDuration(seconds: number) { const minutes = Math.floor(seconds / 60); return minutes < 60 ? `${minutes}m` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`; }

function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [error, setError] = useState('');
  const load = () => Promise.all([api<DashboardStats>('/statistics'), api<Incident[]>('/incidents')]).then(([s, i]) => { setStats(s); setIncidents(i); setError(''); }).catch((e: Error) => setError(e.message));
  useEffect(() => { void load(); }, []);
  if (error) return <><PageHeading eyebrow="LIVE OPERATIONS" title="Threat overview" detail="Correlated activity from the local event store." /><LoadingError error={error} onRetry={() => void load()} /></>;
  if (!stats) return <div className="loading-line"><span /> Loading telemetry</div>;
  const statCards = [
    { label: 'Open incidents', value: stats.total_incidents, icon: ShieldAlert, tint: 'mint' },
    { label: 'Critical incidents', value: stats.critical_incidents, icon: AlertTriangle, tint: 'red' },
    { label: 'High-risk events', value: stats.high_risk_events, icon: Activity, tint: 'amber' },
    { label: 'Affected hosts', value: stats.hosts_affected, icon: Server, tint: 'blue' },
    { label: 'Affected users', value: stats.users_affected, icon: Users, tint: 'violet' },
    { label: 'ATT&CK techniques', value: stats.techniques_detected, icon: Fingerprint, tint: 'blue' },
    { label: 'Stages observed', value: stats.stages_detected, icon: GitBranch, tint: 'mint' },
  ];
  return <>
    <PageHeading eyebrow="LIVE OPERATIONS / 30 SEP 2026" title="Threat overview" detail="Correlated activity from the local event store." action={<button className="button button-quiet" onClick={() => void load()}><RefreshCw size={15} /> Refresh</button>} />
    <section className="stats-grid">{statCards.map(({ label, value, icon: Icon, tint }) => <div className="stat-tile" key={label}><div className={`stat-icon ${tint}`}><Icon size={17} /></div><div className="stat-value">{value}</div><div className="stat-label">{label}</div></div>)}</section>
    <div className="overview-grid dashboard-top-grid">
      <section className="panel progression-panel"><div className="panel-heading"><div><span className="panel-kicker">ATTACK PROGRESSION</span><h2>Cyber Kill Chain</h2></div><span className="micro-count">{stats.stages_detected} / 7 STAGES</span></div>
        <div className="chain-track">{stats.kill_chain.map((item, index) => <div className={`chain-stage ${item.detected ? 'detected' : ''}`} key={item.stage}><div className="chain-node">{item.detected ? <Check size={14} /> : String(index + 1).padStart(2, '0')}</div><span>{item.stage}</span></div>)}</div>
        <div className="chain-foot"><span><i className="dot dot-green" /> Stage observed in event evidence</span><Link to="/incidents">Review incidents <ArrowUpRight size={14} /></Link></div>
      </section>
      <section className="panel severity-panel"><div className="panel-heading"><div><span className="panel-kicker">INCIDENT LOAD</span><h2>Severity distribution</h2></div><BarChart3 size={17} className="muted-icon" /></div>
        <div className="severity-bars">{Object.entries(stats.severity_distribution).map(([name, value]) => <div className="severity-row" key={name}><span>{name}</span><div className="bar-track"><i className={`bar-${name.toLowerCase()}`} style={{ width: `${Math.max(4, (value / Math.max(1, stats.total_incidents)) * 100)}%` }} /></div><b>{value}</b></div>)}</div>
        <div className="severity-footer"><span>{stats.techniques_detected} ATT&CK techniques mapped</span><span>{stats.stages_detected} stages represented</span></div>
      </section>
    </div>
    <section className="panel recent-panel"><div className="panel-heading"><div><span className="panel-kicker">TRIAGE QUEUE</span><h2>Recent incidents</h2></div><Link className="text-link" to="/incidents">View all <ArrowUpRight size={14} /></Link></div>
      <IncidentTable incidents={incidents.slice(0, 6)} compact />
    </section>
    <div className="overview-grid chart-grid">
      <section className="panel trend-panel"><div className="panel-heading"><div><span className="panel-kicker">EVENT VOLUME / HOURLY</span><h2>Events over time</h2></div><Clock3 size={17} className="muted-icon" /></div>
        {stats.events_over_time.length ? <div className="hour-chart">{stats.events_over_time.slice(-12).map(item => <div className="hour-column" key={item.time} title={`${item.time} · ${item.count} events`}><b>{item.count}</b><i style={{ height: `${Math.max(5, item.count / Math.max(...stats.events_over_time.map(point => point.count)) * 100)}%` }} /><small>{item.time.slice(11, 16)}</small></div>)}</div> : <p className="muted-copy">No event timestamps available.</p>}
      </section>
      <section className="panel list-panel"><div className="panel-heading"><div><span className="panel-kicker">TECHNIQUE FREQUENCY</span><h2>ATT&CK distribution</h2></div><Fingerprint size={17} className="muted-icon" /></div>
        {stats.technique_distribution.slice(0, 6).map(item => <div className="technique-bar-row" key={item.id}><span><b>{item.id}</b><small>{item.name}</small></span><div className="rank-bar"><i style={{ width: `${item.count / Math.max(1, stats.technique_distribution[0]?.count) * 100}%` }} /></div><strong>{item.count}</strong></div>)}
        {!stats.technique_distribution.length && <p className="muted-copy">No ATT&CK techniques mapped yet.</p>}
      </section>
    </div>
    <div className="overview-grid lower-grid">
      <section className="panel list-panel"><div className="panel-heading"><div><span className="panel-kicker">SOURCE ACTIVITY</span><h2>Top source IPs</h2></div><Network size={17} className="muted-icon" /></div>
        {stats.top_ips.slice(0, 5).map((item, index) => <div className="rank-row" key={item.name}><span className="rank-number">0{index + 1}</span><span className="mono">{item.name}</span><span className="rank-bar"><i style={{ width: `${item.count / Math.max(1, stats.top_ips[0]?.count) * 100}%` }} /></span><b>{item.count}</b></div>)}
      </section>
      <section className="panel list-panel"><div className="panel-heading"><div><span className="panel-kicker">ASSET EXPOSURE</span><h2>Most active hosts</h2></div><HardDrive size={17} className="muted-icon" /></div>
        {stats.top_hosts.slice(0, 5).map((item, index) => <div className="rank-row" key={item.name}><span className="rank-number">0{index + 1}</span><span className="mono">{item.name}</span><span className="rank-bar"><i style={{ width: `${item.count / Math.max(1, stats.top_hosts[0]?.count) * 100}%` }} /></span><b>{item.count}</b></div>)}
      </section>
    </div>
  </>;
}

function IncidentTable({ incidents, compact = false }: { incidents: Incident[]; compact?: boolean }) {
  if (!incidents.length) return <div className="empty-state"><Shield size={21} /><b>No incidents found</b><span>Events will be correlated here when analysis identifies suspicious activity.</span></div>;
  return <div className="table-scroll"><table><thead><tr><th>Incident</th><th>Severity</th><th>Risk</th><th>Assets</th><th>Kill Chain</th><th>First seen</th></tr></thead><tbody>{incidents.map(item => <tr key={item.incident_id}>
    <td><Link className="incident-name" to={`/incidents/${item.incident_id}`}><span className="incident-id">INC-{String(item.incident_id).padStart(4, '0')}</span><b>{item.title}</b>{!compact && <small>{item.summary}</small>}</Link></td>
    <td><Severity value={item.severity} /></td><td><span className={`risk-score risk-${item.severity.toLowerCase()}`}>{item.risk_score}<small>/100</small></span></td>
    <td><span className="asset-count"><Server size={13} /> {item.affected_hosts.length} host</span><span className="asset-count"><Users size={13} /> {item.affected_users.length} user</span></td>
    <td><span className="progress-text">{item.kill_chain?.progress ?? '0/7'} stages</span><div className="mini-progress">{Array.from({ length: 7 }, (_, i) => <i key={i} className={i < (item.kill_chain?.stages.length ?? 0) ? 'on' : ''} />)}</div></td>
    <td className="time-cell">{displayTime(item.first_seen)}</td>
  </tr>)}</tbody></table></div>;
}

function IncidentsPage() {
  const [items, setItems] = useState<Incident[]>([]); const [error, setError] = useState(''); const [filter, setFilter] = useState('All');
  const load = () => api<Incident[]>('/incidents').then(setItems).catch((e: Error) => setError(e.message));
  useEffect(() => { void load(); }, []);
  const visible = filter === 'All' ? items : items.filter(item => item.severity === filter);
  return <><PageHeading eyebrow="CASE MANAGEMENT" title="Incidents" detail={`${items.length} correlated case${items.length === 1 ? '' : 's'} in the local queue.`} action={<Link className="button button-primary" to="/events"><Plus size={16} /> Add events</Link>} />
    <div className="filter-row"><div className="segmented">{['All', 'Critical', 'High', 'Medium', 'Low'].map(item => <button className={filter === item ? 'selected' : ''} onClick={() => setFilter(item)} key={item}>{item}</button>)}</div><button className="button button-quiet" onClick={() => void load()}><RefreshCw size={14} /> Refresh</button></div>
    {error ? <LoadingError error={error} onRetry={() => void load()} /> : <section className="panel table-panel"><IncidentTable incidents={visible} /></section>}
  </>;
}

type IncidentDetail = Incident & {
  duration_seconds: number;
  timeline: { timestamp: string; event_type: string; hostname?: string; user?: string; stage: string; severity: string; evidence: string }[];
  techniques: { id: string; name: string; tactic: string; confidence: number; evidence: string }[];
  risk_factors: { label: string; points: number }[];
  investigation_steps: string[]; containment_actions: string[];
  alerts: { rule_id: string; title: string; severity: string; evidence: string }[];
  indicators: { kind: string; value: string }[];
  events: EventRecord[];
};

function IncidentPage() {
  const { id } = useParams(); const [data, setData] = useState<IncidentDetail | null>(null); const [graph, setGraph] = useState<GraphPayload | null>(null); const [error, setError] = useState('');
  useEffect(() => { if (!id) return; Promise.all([api<IncidentDetail>(`/incidents/${id}`), api<GraphPayload>(`/incidents/${id}/attack-graph`)]).then(([detail, topology]) => { setData(detail); setGraph(topology); }).catch((e: Error) => setError(e.message)); }, [id]);
  if (error) return <LoadingError error={error} />;
  if (!data) return <div className="loading-line"><span /> Loading incident evidence</div>;
  return <><PageHeading eyebrow={`CASE FILE / INC-${String(data.incident_id).padStart(4, '0')}`} title={data.title} detail={`${data.summary} Attack duration: ${formatDuration(data.duration_seconds)}.`} action={<div className="button-row"><button className="button button-quiet" onClick={() => void downloadReport(data.incident_id, 'json')}><ArrowDownToLine size={15} /> JSON</button><button className="button button-primary" onClick={() => void downloadReport(data.incident_id, 'pdf')}><FileText size={15} /> Export PDF</button></div>} />
    <div className="incident-summary-grid"><div className="incident-score-panel"><div className="score-orbit"><b>{data.risk_score}</b><small>RISK</small></div><div><Severity value={data.severity} /><p>{data.confidence * 100}% confidence</p></div><div className="score-factors">{data.risk_factors.map(factor => <span key={factor.label}><i />{factor.label}<b>+{factor.points}</b></span>)}</div></div>
      <div className="panel meta-panel"><div><span>FIRST SEEN</span><b>{displayTime(data.first_seen)}</b></div><div><span>LAST SEEN</span><b>{displayTime(data.last_seen)}</b></div><div><span>AFFECTED HOSTS</span><b>{data.affected_hosts.join(', ') || '—'}</b></div><div><span>AFFECTED USERS</span><b>{data.affected_users.join(', ') || '—'}</b></div><div><span>SOURCE IP</span><b className="mono">{data.source_ips.join(', ') || '—'}</b></div><div><span>DESTINATION IP</span><b className="mono">{data.destination_ips.join(', ') || '—'}</b></div></div>
    </div>
    <section className="panel detail-chain"><div className="panel-heading"><div><span className="panel-kicker">{data.kill_chain.progress} STAGES OBSERVED</span><h2>Kill Chain progression</h2></div><span className="micro-count">CORRELATED EVIDENCE</span></div><div className="chain-track">{['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation', 'Command & Control', 'Actions on Objectives'].map((stage, index) => <div className={`chain-stage ${data.kill_chain.stages.includes(stage) ? 'detected' : ''}`} key={stage}><div className="chain-node">{data.kill_chain.stages.includes(stage) ? <Check size={14} /> : String(index + 1).padStart(2, '0')}</div><span>{stage}</span></div>)}</div></section>
    <div className="overview-grid detail-grid"><section className="panel"><div className="panel-heading"><div><span className="panel-kicker">CHRONOLOGY</span><h2>Investigation timeline</h2></div><span className="micro-count">{data.timeline.length} EVENTS</span></div><div className="timeline">{data.timeline.map((event, index) => <div className="timeline-item" key={`${event.timestamp}-${index}`}><div className="timeline-rail"><i className={event.severity.toLowerCase()} />{index < data.timeline.length - 1 && <span />}</div><div className="timeline-content"><div className="timeline-meta"><time>{displayTime(event.timestamp)}</time><Severity value={event.severity} /></div><b>{event.event_type.replaceAll('_', ' ')}</b><p>{event.evidence}</p><small>{event.hostname ?? 'Unknown host'} · {event.user ?? 'Unknown user'} · {event.stage || 'Unclassified'}</small></div></div>)}</div></section>
      <div className="stacked-panels"><section className="panel"><div className="panel-heading"><div><span className="panel-kicker">TECHNIQUE MAPPING</span><h2>MITRE ATT&CK</h2></div><Fingerprint size={17} className="muted-icon" /></div>{data.techniques.map(tech => <div className="technique-row" key={tech.id}><b>{tech.id}</b><span>{tech.name}<small>{tech.tactic} · {Math.round(tech.confidence * 100)}% confidence</small></span></div>)}</section>
        <section className="panel"><div className="panel-heading"><div><span className="panel-kicker">DETECTION EVIDENCE</span><h2>Matched rules</h2></div><CircleDot size={16} className="muted-icon" /></div>{data.alerts.length ? data.alerts.map(alert => <div className="alert-row" key={alert.rule_id}><Severity value={alert.severity} /><b>{alert.title}</b><p>{alert.evidence}</p></div>) : <p className="muted-copy">No specific correlation rule matched.</p>}</section>
      </div></div>
    <section className="panel graph-panel"><div className="panel-heading"><div><span className="panel-kicker">ENTITY CORRELATION</span><h2>Attack graph</h2></div><Link className="text-link" to="/attack-graph">Open graph <ArrowUpRight size={14} /></Link></div><GraphCanvas graph={graph} /></section>
    <div className="overview-grid lower-grid"><RecommendationPanel title="Investigate next" icon={<Search size={16} />} items={data.investigation_steps} /><RecommendationPanel title="Containment actions" icon={<LockKeyhole size={16} />} items={data.containment_actions} /></div>
    <section className="panel indicators-panel"><div className="panel-heading"><div><span className="panel-kicker">OBSERVED ARTIFACTS</span><h2>Indicators of compromise</h2></div><Fingerprint size={17} className="muted-icon" /></div><div className="indicator-list">{data.indicators.map(item => <span key={`${item.kind}-${item.value}`}><small>{item.kind}</small><code>{item.value}</code></span>)}</div></section>
  </>;
}

function RecommendationPanel({ title, icon, items }: { title: string; icon: React.ReactNode; items: string[] }) { return <section className="panel recommendation-panel"><div className="panel-heading"><div><span className="panel-kicker">RESPONSE PLAYBOOK</span><h2>{icon}{title}</h2></div></div><ol>{items.map((item, index) => <li key={item}><span>{String(index + 1).padStart(2, '0')}</span>{item}</li>)}</ol></section>; }

function GraphCanvas({ graph }: { graph: GraphPayload | null }) {
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null);
  const nodes: Node[] = graph?.nodes.map((node, index) => ({ id: node.id, position: { x: index * 230, y: index % 2 ? 130 : 30 }, data: { label: node.label, entity: node.entity, timestamp: node.timestamp, evidence: node.evidence }, style: { background: '#1c2420', color: '#ecf1ec', border: '1px solid #39453d', borderRadius: 6, minWidth: 156, fontSize: 12, padding: 12 } })) ?? [];
  const edges: Edge[] = graph?.edges.map((edge, index) => ({ ...edge, id: `edge-${index}`, animated: true, style: { stroke: '#82d49b', strokeWidth: 1.5 }, labelStyle: { fill: '#94a199', fontSize: 9 } })) ?? [];
  if (!nodes.length) return <div className="empty-graph"><Network size={20} />Graph evidence appears when an incident is selected.</div>;
  return <><div className="graph-canvas"><ReactFlow nodes={nodes} edges={edges} fitView nodesDraggable={false} onNodeClick={(_, node) => setSelected(node.data)}><Background color="#343d37" gap={22} /><Controls showInteractive={false} /></ReactFlow></div>{selected && <div className="node-evidence"><div><b>{String(selected.label)}</b><small>{String(selected.entity)} · {String(selected.timestamp)}</small></div><p>{String(selected.evidence)}</p><button className="icon-button" title="Close evidence" onClick={() => setSelected(null)}><X size={15} /></button></div>}</>;
}

function EventsPage() {
  const [events, setEvents] = useState<EventRecord[]>([]); const [error, setError] = useState(''); const [notice, setNotice] = useState(''); const [busy, setBusy] = useState(false);
  const load = () => api<EventRecord[]>('/events?limit=500').then(setEvents).catch((e: Error) => setError(e.message));
  useEffect(() => { void load(); }, []);
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('');
    const formElement = event.currentTarget;
    const form = new FormData(formElement); const timestamp = String(form.get('timestamp'));
    const payload = { timestamp: new Date(timestamp).toISOString(), event_type: String(form.get('event_type')), source_ip: String(form.get('source_ip') || '') || null, destination_ip: String(form.get('destination_ip') || '') || null, user: String(form.get('user') || '') || null, hostname: String(form.get('hostname') || '') || null, description: String(form.get('description') || '') };
    try { await api('/events', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }); const result = await api<{ incidents_created: number }>('/analyze', { method: 'POST' }); setNotice(`Event stored. ${result.incidents_created} incident${result.incidents_created === 1 ? '' : 's'} created or updated.`); formElement.reset(); await load(); }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  async function upload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]; if (!file) return; setBusy(true); setNotice(''); setError('');
    const form = new FormData(); form.append('file', file);
    try { const result = await api<{ accepted: number; rejected: number; incidents_created: number; errors: string[] }>('/events/upload', { method: 'POST', body: form }); setNotice(`${result.accepted} events accepted, ${result.rejected} rejected; ${result.incidents_created} new incidents.`); if (result.errors.length) setError(result.errors.slice(0, 3).join(' · ')); await load(); }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); event.target.value = ''; }
  }
  return <><PageHeading eyebrow="TELEMETRY PIPELINE" title="Event intake" detail="Upload structured logs or add a single observation for correlation." action={<label className="button button-primary upload-button"><CloudUpload size={16} /> Upload logs<input type="file" accept=".csv,.json,.txt" onChange={upload} disabled={busy} /></label>} />
    {notice && <div className="notice"><Check size={16} />{notice}</div>}{error && <LoadingError error={error} />}
    <div className="intake-grid"><section className="panel manual-panel"><div className="panel-heading"><div><span className="panel-kicker">MANUAL EVENT</span><h2>Add an observation</h2></div><Plus size={17} className="muted-icon" /></div>
      <form className="event-form" onSubmit={submit}><label>Event type<select name="event_type" required defaultValue="failed_login">{['failed_login','successful_login','phishing_attachment','phishing_link','powershell','command_shell','file_download','malware_execution','persistence','scheduled_task','credential_dumping','privilege_escalation','security_tool_disabled','remote_access','dns_request','c2_traffic','data_staging','data_transfer','network_scan','file_modification','process_creation','benign'].map(type => <option key={type} value={type}>{type.replaceAll('_', ' ')}</option>)}</select></label><label>Timestamp<input name="timestamp" type="datetime-local" required defaultValue={new Date().toISOString().slice(0, 16)} /></label><label>Source IP<input name="source_ip" placeholder="198.51.100.24" /></label><label>Destination IP<input name="destination_ip" placeholder="203.0.113.44" /></label><label>User<input name="user" placeholder="account name" /></label><label>Hostname<input name="hostname" placeholder="WS-014" /></label><label className="span-two">Description / evidence<textarea name="description" rows={3} placeholder="Describe observed behavior, command indicators, transfer volume..." maxLength={8000} /></label><button className="button button-primary span-two" disabled={busy}><Plus size={15} />{busy ? 'Processing…' : 'Store and analyze'}</button></form>
    </section><section className="panel upload-panel"><div className="upload-illustration"><Upload size={22} /></div><span className="panel-kicker">SUPPORTED FORMATS</span><h2>Bring in security telemetry</h2><p>CSV and JSON records are validated field by field. Plain-text logs are retained as unclassified evidence. Malformed records are reported without blocking valid rows.</p><div className="format-tags"><span>.CSV</span><span>.JSON</span><span>.TXT</span><span>5 MiB LIMIT</span></div><label className="button button-quiet upload-button"><CloudUpload size={15} /> Choose a file<input type="file" accept=".csv,.json,.txt" onChange={upload} disabled={busy} /></label></section></div>
    <section className="panel events-table-panel"><div className="panel-heading"><div><span className="panel-kicker">PERSISTED TELEMETRY</span><h2>Recent events</h2></div><span className="micro-count">{events.length} RECORDS</span></div><div className="table-scroll"><table><thead><tr><th>Time</th><th>Event</th><th>Asset / user</th><th>Kill Chain</th><th>ATT&CK</th><th>Severity</th><th>Incident</th></tr></thead><tbody>{events.slice(0, 80).map(event => <tr key={event.id}><td className="time-cell">{displayTime(event.timestamp)}</td><td><b className="event-type">{event.event_type.replaceAll('_', ' ')}</b><small className="event-description">{event.description}</small></td><td>{event.hostname ?? '—'}<small className="event-description">{event.user ?? '—'}</small></td><td>{event.kill_chain_stage || '—'}</td><td className="mono">{event.mitre_id ?? '—'}</td><td><Severity value={event.severity} /></td><td>{event.incident_id ? <Link to={`/incidents/${event.incident_id}`}>INC-{String(event.incident_id).padStart(4, '0')}</Link> : <span className="muted-copy">Context</span>}</td></tr>)}</tbody></table></div></section>
  </>;
}

function AttackGraphPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]); const [selected, setSelected] = useState(''); const [graph, setGraph] = useState<GraphPayload | null>(null); const [error, setError] = useState('');
  useEffect(() => { api<Incident[]>('/incidents').then(data => { setIncidents(data); if (data[0]) setSelected(String(data[0].incident_id)); }).catch((e: Error) => setError(e.message)); }, []);
  useEffect(() => { if (selected) api<GraphPayload>(`/incidents/${selected}/attack-graph`).then(setGraph).catch((e: Error) => setError(e.message)); }, [selected]);
  return <><PageHeading eyebrow="ENTITY RELATIONSHIPS" title="Attack graph" detail="Chronological event links derived from shared host, user, or IP evidence." action={<label className="select-wrap"><ListFilter size={15} /><select value={selected} onChange={event => setSelected(event.target.value)}>{incidents.map(item => <option key={item.incident_id} value={item.incident_id}>INC-{String(item.incident_id).padStart(4, '0')} · {item.title}</option>)}</select></label>} />
    {error && <LoadingError error={error} />}{selected ? <section className="panel full-graph-panel"><div className="graph-heading"><div><span className="panel-kicker">{graph?.nodes.length ?? 0} EVENT NODES</span><h2>{incidents.find(item => String(item.incident_id) === selected)?.title ?? 'Incident graph'}</h2></div><Link className="text-link" to={`/incidents/${selected}`}>Open case file <ArrowUpRight size={14} /></Link></div><GraphCanvas graph={graph} /></section> : <div className="empty-state"><Network size={22} /><b>No correlated cases</b><span>Run analysis after adding event data to build a graph.</span></div>}
    <div className="graph-legend"><span><i className="legend-dot green" /> Event relationship</span><span><i className="legend-square" /> Select any node for the supporting evidence</span><span><Clock3 size={14} /> Edges are ordered by event time</span></div>
  </>;
}

type Technique = { id: string; name: string; tactic: string; description: string; severity: number };
function MitrePage() {
  const [items, setItems] = useState<Technique[]>([]); const [query, setQuery] = useState(''); const [error, setError] = useState('');
  useEffect(() => { api<Technique[]>('/mitre/techniques').then(setItems).catch((e: Error) => setError(e.message)); }, []);
  const visible = items.filter(item => `${item.id} ${item.name} ${item.tactic}`.toLowerCase().includes(query.toLowerCase()));
  const tactics = [...new Set(visible.map(item => item.tactic))];
  return <><PageHeading eyebrow="LOCAL KNOWLEDGE BASE" title="ATT&CK technique library" detail={`${items.length} locally mapped techniques, linked to event rules and evidence.`} action={<div className="library-count"><Fingerprint size={16} /> {items.length} TECHNIQUES</div>} />{error && <LoadingError error={error} />}
    <div className="library-search"><Search size={16} /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search technique, ID, or tactic" /><kbd>⌘ K</kbd></div>
    <div className="tactic-grid">{tactics.map(tactic => <section className="tactic-column" key={tactic}><div className="tactic-heading"><span><i />{tactic}</span><small>{visible.filter(item => item.tactic === tactic).length}</small></div>{visible.filter(item => item.tactic === tactic).map(item => <article className="technique-card" key={item.id}><div><b>{item.id}</b><span className="tech-severity">SEV {item.severity}</span></div><h3>{item.name}</h3><p>{item.description}</p></article>)}</section>)}</div>
  </>;
}

async function downloadReport(id: number, format: 'json' | 'pdf') {
  const response = await fetch(`${API_BASE}/reports/${id}/generate?format=${format}`, { method: 'POST' });
  if (!response.ok) throw new Error('Report generation failed');
  const blob = await response.blob(); const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `incident-${id}-report.${format}`; anchor.click(); URL.revokeObjectURL(url);
}

function ReportsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]); const [error, setError] = useState(''); const [busy, setBusy] = useState<number | null>(null); const [notice, setNotice] = useState('');
  useEffect(() => { api<Incident[]>('/incidents').then(setIncidents).catch((e: Error) => setError(e.message)); }, []);
  async function generate(id: number, format: 'json' | 'pdf') { setBusy(id); setNotice(''); try { await downloadReport(id, format); setNotice(`Incident INC-${String(id).padStart(4, '0')} report generated.`); } catch (e) { setError((e as Error).message); } finally { setBusy(null); } }
  return <><PageHeading eyebrow="INVESTIGATION OUTPUT" title="Reports" detail="Generate evidence-backed incident reports in JSON or PDF." />{notice && <div className="notice"><Check size={16} />{notice}</div>}{error && <LoadingError error={error} />}
    <div className="report-list">{incidents.map(item => <article className="report-row" key={item.incident_id}><div className="report-icon"><FileText size={18} /></div><div className="report-info"><small>INC-{String(item.incident_id).padStart(4, '0')} · {displayTime(item.first_seen)}</small><b>{item.title}</b><span>{item.affected_hosts.join(', ') || 'No host identified'} · {item.kill_chain.progress} Kill Chain stages</span></div><Severity value={item.severity} /><div className="report-actions"><button className="button button-quiet" onClick={() => void generate(item.incident_id, 'json')} disabled={busy === item.incident_id}><ArrowDownToLine size={15} /> JSON</button><button className="button button-primary" onClick={() => void generate(item.incident_id, 'pdf')} disabled={busy === item.incident_id}><FileText size={15} /> PDF</button></div></article>)}{incidents.length === 0 && <div className="empty-state"><FileText size={22} /><b>No reports available</b><span>Reports are generated from correlated incident evidence.</span></div>}</div>
    <section className="report-method"><div className="method-icon"><Gauge size={19} /></div><div><span className="panel-kicker">REPORT CONTENT</span><h2>Every export carries its evidence</h2><p>Executive summary, event timeline, Kill Chain progression, ATT&CK techniques, transparent risk score, indicators, investigative steps, and containment guidance.</p></div></section>
  </>;
}

function SettingsPage() {
  return <><PageHeading eyebrow="ANALYZER CONFIGURATION" title="Configuration" detail="Current local analysis and storage behavior." />
    <div className="settings-grid"><section className="panel settings-section"><div className="panel-heading"><div><span className="panel-kicker">DATA SOURCE</span><h2><HardDrive size={17} /> Local SQLite store</h2></div><span className="config-state"><i /> ACTIVE</span></div><div className="setting-line"><span>API endpoint</span><code>{API_BASE}</code></div><div className="setting-line"><span>Database</span><code>backend/killchain.db</code></div><div className="setting-line"><span>Upload cap</span><code>5 MiB per file</code></div></section>
      <section className="panel settings-section"><div className="panel-heading"><div><span className="panel-kicker">DETECTION MODEL</span><h2><Bug size={17} /> Rule-based correlation</h2></div><span className="config-state"><i /> ENABLED</span></div>{[['KC-001', 'Repeated failed authentication', '5 attempts / 5 minutes'], ['KC-002', 'Failure followed by successful login', 'Same source and user / 10 minutes'], ['KC-003', 'Encoded PowerShell', 'Encoded or obfuscated command indicators'], ['KC-004', 'Executable after PowerShell', 'Download within 15 minutes'], ['KC-005', 'Outbound transfer after execution', 'Suspicious sequence / 8 hours'], ['KC-006', 'Suspicious DNS after malware', 'Beacon evidence / 8 hours']].map(([id, title, trigger]) => <div className="rule-setting" key={id}><span>{id}</span><b>{title}</b><small>{trigger}</small><Check size={14} /></div>)}</section>
      <section className="panel settings-section scoring-section"><div className="panel-heading"><div><span className="panel-kicker">TRANSPARENT SCORING</span><h2><Gauge size={17} /> Risk model</h2></div></div><p>Score combines the highest observed event severity, Kill Chain stage breadth, related-event count, distinct techniques, matched detection rules, and asset criticality. Evidence confidence scales the total. The result is clamped to 0–100.</p><div className="score-thresholds"><span>0–25 <b>Low</b></span><span>26–50 <b>Medium</b></span><span>51–75 <b>High</b></span><span>76–100 <b>Critical</b></span></div></section>
    </div>
  </>;
}

function NotFound() { const navigate = useNavigate(); return <div className="not-found"><CircleDot size={22} /><h1>View not found</h1><button className="button button-primary" onClick={() => navigate('/')}>Return to overview</button></div>; }

export default App;