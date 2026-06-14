import React, { useState, useEffect } from 'react';
import { Bolt, Play, FileText, Trash2 } from 'lucide-react';

const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? 'http://127.0.0.1:5000'
  : `${window.location.protocol}//${window.location.hostname}:5000`;

export default function App() {
  const [targets, setTargets] = useState([]);
  const [targetUrl, setTargetUrl] = useState('');
  const [progressData, setProgressData] = useState({});
  const [stats, setStats] = useState({ total: 0, high: 0, medium: 0, low: 0, waf: 0 });

  const fetchDashboardData = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/targets`);
      if (!res.ok) return;
      const data = await res.json();
      setTargets(data);

      let high = 0, med = 0, low = 0;
      data.forEach(t => {
        if (t.risk_score >= 80) high++;
        else if (t.risk_score >= 40) med++;
        else if (t.risk_score > 0) low++;
      });

      const wafRes = await fetch(`${API_BASE}/api/waf/stats`);
      const wafData = wafRes.ok ? await wafRes.json() : { total: 0 };

      setStats({
        total: data.length,
        high,
        medium: med,
        low,
        waf: wafData.total || 0
      });
    } catch (err) {
      console.error("Failed connecting to Bensec Core API server:", err);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const listenToProgress = (targetId) => {
    const eventSource = new EventSource(`${API_BASE}/api/targets/${targetId}/progress`);

    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setProgressData(prev => ({ ...prev, [targetId]: data }));

      if (data.done || data.error) {
        eventSource.close();
        fetchDashboardData();
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
    };
  };

  const handleAddTarget = async (e) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    try {
      const res = await fetch(`${API_BASE}/api/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl.trim() })
      });
      if (res.ok) {
        setTargetUrl('');
        fetchDashboardData();
      } else {
        const err = await res.json();
        alert(`Error mapping target: ${err.error}`);
      }
    } catch (err) {
      alert("Pipeline verification error connecting to API server backend.");
    }
  };

  const startScan = async (targetId) => {
    try {
      const res = await fetch(`${API_BASE}/api/targets/${targetId}/scan`, { method: 'POST' });
      if (res.ok) {
        setProgressData(prev => ({
          ...prev,
          [targetId]: { step: 'Initializing background execution thread...', pct: 4, findings: 0 }
        }));
        listenToProgress(targetId);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const downloadReport = async (targetId, url) => {
    try {
      const res = await fetch(`${API_BASE}/api/report/${targetId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'technical' })
      });
      if (res.ok) {
        const blob = await res.blob();
        const fileUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = fileUrl;
        let domain = url.replace('https://','').replace('http://','').split('/')[0].replace(':','_');
        a.download = `BENSEC-Audit-Report-${domain}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
    } catch (err) {
      alert("Network dropped report asset compilation loops.");
    }
  };

  const deleteTarget = async (targetId) => {
    if (!confirm("Are you sure you want to permanently clear this target's history statistics?")) return;
    try {
      const res = await fetch(`${API_BASE}/api/targets/${targetId}`, { method: 'DELETE' });
      if (res.ok) fetchDashboardData();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div style={{ maxWidth: '1250px', margin: '0 auto' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2.5rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Bolt size={28} color="var(--status-scan)" />
          <h1 style={{ fontSize: '1.6rem', fontWeight: 800, letterSpacing: '1px' }}>BENSEC</h1>
        </div>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Bensec Security Platform</div>
      </header>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.5rem', marginBottom: '2.5rem' }}>
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '1.5rem' }}>
          <h3 style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase', marginBottom: '0.75rem' }}>Total Targets</h3>
          <div style={{ fontSize: '2.2rem', fontWeight: 700 }}>{stats.total}</div>
        </div>
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '1.5rem' }}>
          <h3 style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase', marginBottom: '0.75rem' }}>WAF Blocked</h3>
          <div style={{ fontSize: '2.2rem', fontWeight: 700, color: 'var(--severity-high)' }}>{stats.waf}</div>
        </div>
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '1.5rem' }}>
          <h3 style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase', marginBottom: '0.75rem' }}>High-Risk Targets</h3>
          <div style={{ fontSize: '2.2rem', fontWeight: 700, color: 'var(--status-scan)' }}>{stats.high}</div>
        </div>
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '1.5rem' }}>
          <h3 style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase', marginBottom: '0.4rem' }}>Risk Breakdown</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}><span style={{ color: 'var(--severity-high)', fontWeight: 'bold' }}>High</span><span>{stats.high}</span></div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}><span style={{ color: 'var(--status-scan)', fontWeight: 'bold' }}>Medium</span><span>{stats.medium}</span></div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}><span style={{ color: 'var(--severity-low)', fontWeight: 'bold' }}>Low</span><span>{stats.low}</span></div>
          </div>
        </div>
      </div>

      <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '2rem', marginBottom: '2.5rem' }}>
        <div style={{ fontSize: '1rem', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '1rem', fontWeight: 700 }}>Add New Scanner Target</div>
        <form onSubmit={handleAddTarget} style={{ display: 'flex', gap: '1rem' }}>
          <input
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example-target.com"
            required
            style={{ flex: 1, backgroundColor: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '0.75rem 1rem', color: 'var(--text-main)', fontSize: '1rem', outline: 'none' }}
          />
          <button type="submit" className="btn" style={{ backgroundColor: 'var(--accent-primary)', color: 'var(--text-main)', border: 'none', borderRadius: '6px', padding: '0.75rem 1.5rem', fontWeight: 600, cursor: 'pointer', transition: 'background-color 0.2s' }}>Add Target</button>
        </form>
      </div>

      <div style={{ fontSize: '1.2rem', fontWeight: 800, textTransform: 'uppercase', marginBottom: '1rem' }}>Targets Auditing Control Deck</div>
      <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ background: 'rgba(254, 254, 254, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
              <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>#</th>
              <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Target URL</th>
              <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Scan Status</th>
              <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Live Execution Monitor</th>
              <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Risk Matrix</th>
              <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Action Panel</th>
            </tr>
          </thead>
          <tbody>
            {targets.length > 0 ? targets.map((t, index) => {
              const liveProg = progressData[t.id];
              const isScanning = t.scan_status === 'scanning' || (liveProg && !liveProg.done && !liveProg.error);
              
              return (
                <tr key={t.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '1rem 1.5rem' }}>{index + 1}</td>
                  <td style={{ padding: '1rem 1.5rem' }}><strong>{t.url}</strong></td>
                  <td style={{ padding: '1rem 1.5rem' }}>
                    <span className="status-badge" style={{ 
                      background: t.scan_status === 'scanning' ? 'rgba(245, 158, 11, 0.15)' : t.scan_status === 'completed' ? 'rgba(16, 185, 129, 0.15)' : 'var(--border-color)', 
                      color: t.scan_status === 'scanning' ? 'var(--status-scan)' : t.scan_status === 'completed' ? '#10b981' : 'var(--text-muted)' 
                    }}>
                      {t.scan_status}
                    </span>
                  </td>
                  <td style={{ padding: '1rem 1.5rem', fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                    {liveProg ? (
                      <span>
                        <span style={{ color: '#f59e0b', marginRight: '5px' }}>{liveProg.pct}%</span> — {liveProg.step} 
                        <span style={{ marginLeft: '6px', background: 'rgba(239,68,68,0.15)', padding: '2px 6px', borderRadius: '4px', color: '#ef4444', fontWeight: 'bold', fontSize: '0.75rem' }}>{liveProg.findings} vulns</span>
                      </span>
                    ) : '—'}
                  </td>
                  <td style={{ padding: '1rem 1.5rem', fontWeight: 700 }}>{t.risk_score || 0}</td>
                  <td style={{ padding: '1rem 1.5rem' }}>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button className="btn" disabled={isScanning} onClick={() => startScan(t.id)} style={{ width: '36px', height: '36px', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', border: 'none', borderRadius: '6px', cursor: 'pointer', backgroundColor: '#f59e0b', color: '#0a0b10' }}><Play size={16} /></button>
                      <button className="btn" disabled={t.scan_status !== 'completed'} onClick={() => downloadReport(t.id, t.url)} style={{ width: '36px', height: '36px', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', border: 'none', borderRadius: '6px', cursor: 'pointer', backgroundColor: '#10b981', color: '#fff' }}><FileText size={16} /></button>
                      <button className="btn" onClick={() => deleteTarget(t.id)} style={{ width: '36px', height: '36px', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', border: 'none', borderRadius: '6px', cursor: 'pointer', backgroundColor: '#dc2626', color: '#fff' }}><Trash2 size={16} /></button>
                    </div>
                  </td>
                </tr>
              );
            }) : (
              <tr><td colSpan="6" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>No diagnostic targets identified. Add a URL above to initialize audit modules.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
