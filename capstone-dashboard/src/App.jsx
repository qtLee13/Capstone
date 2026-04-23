import { useState, useEffect } from 'react'
import EmailLogs from './EmailLogs'

const API_BASE = 'http://127.0.0.1:8000'

function DarkModeToggle({ isDark, setIsDark }) {
  return (
    <button onClick={() => setIsDark(!isDark)} style={{
      position: 'fixed', bottom: 20, right: 20, zIndex: 999,
      width: 50, height: 50, borderRadius: '50%',
      background: isDark ? '#1f2937' : '#fff',
      border: `2px solid ${isDark ? '#374151' : '#e5e7eb'}`,
      cursor: 'pointer', fontSize: 24, display: 'flex', alignItems: 'center', justifyContent: 'center',
      boxShadow: '0 10px 25px rgba(0,0,0,0.2)',
      transition: 'all 0.3s ease'
    }}>
      {isDark ? '☀️' : '🌙'}
    </button>
  )
}

function initials(email) {
  return email.split('.').slice(0, 2).map(p => p[0].toUpperCase()).join('')
}
function fmt(n) {
  return n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n)
}

function getScorePolicy(score) {
  if (score > 80) return { label: 'Block', color: '#b91c1c' }
  if (score > 60) return { label: 'Quarantine', color: '#dc2626' }
  if (score >= 30) return { label: 'Warning', color: '#d97706' }
  return { label: 'Allow', color: '#15803d' }
}

function MiniBarChart({ data }) {
  const max = Math.max(...data.total, 1)
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 80 }}>
      {data.labels.map((label, i) => (
        <div key={label} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
          <div style={{ width: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', height: 64, gap: 1 }}>
            <div style={{ width: '100%', background: '#ef4444', opacity: 0.9, height: `${(data.phishing[i] / max) * 64}px`, borderRadius: '2px 2px 0 0', transition: 'height 0.6s ease' }} />
            <div style={{ width: '100%', background: '#3b82f6', opacity: 0.4, height: `${((data.total[i] - data.phishing[i]) / max) * 64}px` }} />
          </div>
          <div style={{ fontSize: 9, color: '#6b7280', textAlign: 'center', whiteSpace: 'nowrap' }}>
            {label.replace('Mar ', 'M').replace('Apr ', 'A')}
          </div>
        </div>
      ))}
    </div>
  )
}

function DonutChart({ segments }) {
  const total = segments.reduce((s, d) => s + d.count, 0)
  let offset = 0
  const r = 45, cx = 60, cy = 60, circ = 2 * Math.PI * r
  return (
    <svg viewBox="0 0 120 120" width="120" height="120">
      {segments.map((seg, i) => {
        const pct = seg.count / (total || 1)
        const dash = pct * circ
        const el = (
          <circle key={i} cx={cx} cy={cy} r={r} fill="none" stroke={seg.color}
            strokeWidth={18} strokeDasharray={`${dash} ${circ - dash}`}
            strokeDashoffset={-offset * circ + circ / 4}
            style={{ transition: 'stroke-dasharray 0.8s ease' }} />
        )
        offset += pct
        return el
      })}
      <text x={cx} y={cy - 6} textAnchor="middle" fontSize={20} fontWeight={600} fill="#111827">{fmt(total)}</text>
      <text x={cx} y={cy + 12} textAnchor="middle" fontSize={9} fill="#9ca3af">emails</text>
    </svg>
  )
}

function MetricCard({ label, value, sub, accent }) {
  return (
    <div style={{ background: '#fff', border: '1px solid #f3f4f6', borderRadius: 14, padding: '18px 20px', position: 'relative', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: accent, borderRadius: '14px 14px 0 0' }} />
      <div style={{ fontSize: 12, color: '#9ca3af', marginBottom: 6, fontWeight: 500, letterSpacing: '0.03em', textTransform: 'uppercase' }}>{label}</div>
      <div style={{ fontSize: 32, fontWeight: 700, color: accent, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: '#6b7280', marginTop: 5 }}>{sub}</div>}
    </div>
  )
}

function SectionHead({ children }) {
  return <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: '#9ca3af', marginBottom: 12 }}>{children}</div>
}

const DEFAULT_STATS = { emailsToday: 0, emailsChange: 0, phishingDetected: 0, phishingRate: 0, blocked: 0, quarantined: 0, blockRate: 0, avgRiskScore: 0 }
const DEFAULT_VOLUME = { labels: [], total: [], phishing: [] }
const DEFAULT_RISK = [
  { label: 'Low (0–40)',    count: 0, color: '#22c55e' },
  { label: 'Med (41–70)',   count: 0, color: '#f59e0b' },
  { label: 'High (71–100)', count: 0, color: '#ef4444' },
]

export default function PhishingDashboard() {
  const [stats,    setStats]   = useState(DEFAULT_STATS)
  const [volume,   setVolume]  = useState(DEFAULT_VOLUME)
  const [riskDist, setRisk]    = useState(DEFAULT_RISK)
  const [domains,  setDomains] = useState([])
  const [users,    setUsers]   = useState([])
  const [attackTypes, setAttackTypes] = useState([])
  const [loading,  setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [error,    setError]   = useState(null)
  const [volumeFilter, setVolumeFilter] = useState('7days')
  const [currentPage, setCurrentPage] = useState('dashboard')
  const [isDarkMode, setIsDarkMode] = useState(false)

  const fetchDashboard = async (period = volumeFilter) => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`${API_BASE}/dashboard?period=${period}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      if (data.stats)    setStats(data.stats)
      if (data.volume)   setVolume(data.volume)
      if (data.riskDist) setRisk(data.riskDist)
      if (data.domains)  setDomains(data.domains)
      if (data.users)    setUsers(data.users)
      if (data.types)    setAttackTypes(data.types)
      setLastUpdated(new Date())
    } catch (e) {
      setError('ไม่สามารถเชื่อมต่อ Backend ได้ — ' + e.message)
    }
    setLoading(false)
  }

  useEffect(() => {
    fetchDashboard(volumeFilter)
    const id = setInterval(() => fetchDashboard(volumeFilter), 60_000)
    return () => clearInterval(id)
  }, [volumeFilter])

  // Auto-refresh dashboard when new emails arrive
  useEffect(() => {
    let lastEmailCount = stats.emailsToday || 0
    
    const checkForNewEmails = async () => {
      try {
        const res = await fetch(`${API_BASE}/logs`)
        if (!res.ok) return
        const data = await res.json()
        const currentEmailCount = (data.data || []).length
        
        // If email count increased, refresh dashboard
        if (currentEmailCount > lastEmailCount) {
          console.log(`📧 New emails detected (${lastEmailCount} → ${currentEmailCount}), refreshing dashboard...`)
          fetchDashboard(volumeFilter)
          lastEmailCount = currentEmailCount
        }
      } catch (e) {
        console.error('Error checking for new emails:', e)
      }
    }

    const id = setInterval(checkForNewEmails, 5_000)
    return () => clearInterval(id)
  }, [volumeFilter, stats.emailsToday])

  const maxDomain = domains[0]?.count ?? 1
  const totalRisk = riskDist.reduce((s, d) => s + d.count, 0)
  const scorePolicy = getScorePolicy(Number(stats.avgRiskScore) || 0)
  
  // Today's email breakdown by policy (from actual data)
  const todayBreakdown = {
    allow: stats.allowed || 0,
    warning: stats.warning || 0,
    quarantine: stats.quarantined || 0,
    block: stats.blocked || 0
  }
  const totalTodayEmails = todayBreakdown.allow + todayBreakdown.warning + todayBreakdown.quarantine + todayBreakdown.block

  const darkStyles = {
    bg: isDarkMode ? '#111827' : '#f9fafb',
    bgCard: isDarkMode ? '#1f2937' : '#fff',
    text: isDarkMode ? '#f3f4f6' : '#111827',
    textSecondary: isDarkMode ? '#d1d5db' : '#6b7280',
    border: isDarkMode ? '#374151' : '#f3f4f6',
    input: isDarkMode ? '#374151' : '#fff'
  }

  return (
    <>
      <DarkModeToggle isDark={isDarkMode} setIsDark={setIsDarkMode} />
      {/* Navigation Tabs */}
      <div style={{ background: darkStyles.bgCard, borderBottom: `1px solid ${darkStyles.border}`, padding: 'clamp(12px,2vw,16px)', fontFamily: "'DM Sans','Segoe UI',sans-serif", boxShadow: '0 4px 6px rgba(0,0,0,0.1)', transition: 'all 0.3s ease' }}>
        <div style={{ display: 'flex', gap: 2, maxWidth: 1200, margin: '0 auto' }}>
          <button onClick={() => setCurrentPage('dashboard')} style={{ padding: '10px 18px', fontSize: 13, fontWeight: 600, background: currentPage === 'dashboard' ? 'linear-gradient(135deg,#1e40af,#7c3aed)' : 'transparent', color: currentPage === 'dashboard' ? '#fff' : darkStyles.text, border: 'none', borderRadius: 8, cursor: 'pointer', marginRight: 6, transition: 'all 0.3s ease', boxShadow: currentPage === 'dashboard' ? '0 4px 12px rgba(30,64,175,0.3)' : 'none' }}>
            📊 Dashboard
          </button>
          <button onClick={() => setCurrentPage('logs')} style={{ padding: '10px 18px', fontSize: 13, fontWeight: 600, background: currentPage === 'logs' ? 'linear-gradient(135deg,#1e40af,#7c3aed)' : 'transparent', color: currentPage === 'logs' ? '#fff' : darkStyles.text, border: 'none', borderRadius: 8, cursor: 'pointer', marginRight: 6, transition: 'all 0.3s ease', boxShadow: currentPage === 'logs' ? '0 4px 12px rgba(30,64,175,0.3)' : 'none' }}>
            📧 Email Logs
          </button>
        </div>
      </div>

      {/* Page Content */}
      {currentPage === 'dashboard' ? (
      <div style={{ background: darkStyles.bg, minHeight: 'calc(100vh - 60px)', padding: 'clamp(14px,2.4vw,32px)', fontFamily: "'DM Sans','Segoe UI',sans-serif", color: darkStyles.text, transition: 'background-color 0.3s ease' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 28 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: 'linear-gradient(135deg,#1e40af,#7c3aed)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16 }}>🛡️</div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0, color: '#111827' }}>Phishing Intelligence Dashboard</h1>
            {loading && <span style={{ fontSize: 11, color: '#9ca3af', background: '#f3f4f6', padding: '2px 8px', borderRadius: 20 }}>Refreshing…</span>}
          </div>
          <p style={{ fontSize: 13, color: '#9ca3af', margin: 0 }}>
            Step 7 — Threat Intelligence Overview
            {lastUpdated && ` · Updated ${lastUpdated.toLocaleTimeString('th-TH')}`}
          </p>
          {error && <p style={{ fontSize: 12, color: '#dc2626', margin: '4px 0 0', background: '#fee2e2', padding: '4px 10px', borderRadius: 6 }}>⚠ {error}</p>}
        </div>
        <button onClick={fetchDashboard} style={{ background: 'linear-gradient(135deg,#1e40af,#7c3aed)', color: '#fff', border: 'none', padding: '8px 18px', borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: 'pointer', transition: 'all 0.3s ease', boxShadow: '0 4px 12px rgba(30,64,175,0.3)' }}>
          ↻ Refresh
        </button>
      </div>

      {/* Metric cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 14, marginBottom: 24 }}>
        <MetricCard label="Emails today"          value={stats.emailsToday.toLocaleString()} sub={`+${stats.emailsChange}% vs yesterday`}                     accent="#3b82f6" />
        <div style={{ background: '#fff', border: '1px solid #f3f4f6', borderRadius: 14, padding: '18px 20px', position: 'relative', overflow: 'hidden' }}>
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: '#8b5cf6', borderRadius: '14px 14px 0 0' }} />
          <div style={{ fontSize: 12, color: '#9ca3af', marginBottom: 6, fontWeight: 500, letterSpacing: '0.03em', textTransform: 'uppercase' }}>Today's Policy Breakdown</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 8 }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#15803d' }}>{todayBreakdown.allow}</div>
              <div style={{ fontSize: 10, color: '#6b7280', marginTop: 2 }}>Allow</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#d97706' }}>{todayBreakdown.warning}</div>
              <div style={{ fontSize: 10, color: '#6b7280', marginTop: 2 }}>Warning</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#dc2626' }}>{todayBreakdown.quarantine}</div>
              <div style={{ fontSize: 10, color: '#6b7280', marginTop: 2 }}>Quarantine</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#b91c1c' }}>{todayBreakdown.block}</div>
              <div style={{ fontSize: 10, color: '#6b7280', marginTop: 2 }}>Block</div>
            </div>
          </div>
        </div>
      </div>

      {/* Risk distribution first */}
      <div style={{ background: '#fff', border: '1px solid #f3f4f6', borderRadius: 14, padding: '20px 22px', marginBottom: 14 }}>
        <SectionHead>Risk score distribution</SectionHead>
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <DonutChart segments={riskDist} />
          <div style={{ flex: 1 }}>
            {riskDist.map(seg => (
              <div key={seg.label} style={{ marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12 }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#374151' }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: seg.color, display: 'inline-block' }} />
                    {seg.label}
                  </span>
                  <span style={{ fontWeight: 600, color: seg.color }}>{totalRisk > 0 ? Math.round(seg.count / totalRisk * 100) : 0}%</span>
                </div>
                <div style={{ background: '#f3f4f6', borderRadius: 4, height: 6, overflow: 'hidden' }}>
                  <div style={{ height: '100%', background: seg.color, borderRadius: 4, width: `${totalRisk > 0 ? seg.count / totalRisk * 100 : 0}%`, transition: 'width 0.8s ease' }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Volume + Risk distribution */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(320px,1fr))', gap: 14, marginBottom: 14 }}>
        <div style={{ background: '#fff', border: '1px solid #f3f4f6', borderRadius: 14, padding: '20px 22px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <SectionHead>Email volume</SectionHead>
            <div style={{ display: 'flex', gap: 6 }}>
              <button onClick={() => setVolumeFilter('today')} style={{ padding: '4px 10px', fontSize: 11, fontWeight: 600, border: volumeFilter === 'today' ? 'none' : '1px solid #d1d5db', background: volumeFilter === 'today' ? '#1e40af' : '#fff', color: volumeFilter === 'today' ? '#fff' : '#374151', borderRadius: 6, cursor: 'pointer' }}>Today</button>
              <button onClick={() => setVolumeFilter('7days')} style={{ padding: '4px 10px', fontSize: 11, fontWeight: 600, border: volumeFilter === '7days' ? 'none' : '1px solid #d1d5db', background: volumeFilter === '7days' ? '#1e40af' : '#fff', color: volumeFilter === '7days' ? '#fff' : '#374151', borderRadius: 6, cursor: 'pointer' }}>7 days</button>
              <button onClick={() => setVolumeFilter('30days')} style={{ padding: '4px 10px', fontSize: 11, fontWeight: 600, border: volumeFilter === '30days' ? 'none' : '1px solid #d1d5db', background: volumeFilter === '30days' ? '#1e40af' : '#fff', color: volumeFilter === '30days' ? '#fff' : '#374151', borderRadius: 6, cursor: 'pointer' }}>30 days</button>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 14, marginBottom: 10, fontSize: 12, color: '#6b7280' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 10, height: 10, borderRadius: 2, background: '#3b82f6', opacity: 0.5, display: 'inline-block' }} />Total</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 10, height: 10, borderRadius: 2, background: '#ef4444', display: 'inline-block' }} />Phishing</span>
          </div>
          {volume.labels.length > 0
            ? <MiniBarChart data={volume} />
            : <div style={{ height: 80, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#d1d5db', fontSize: 13 }}>วิเคราะห์อีเมลก่อนเพื่อดูข้อมูล</div>}
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10, fontSize: 12 }}>
            <span style={{ color: '#9ca3af' }}>Total {volumeFilter === 'today' ? 'today' : volumeFilter === '7days' ? 'this week' : 'this month'}</span>
            <span style={{ fontWeight: 700, color: '#111827' }}>{volume.total.reduce((a, b) => a + b, 0).toLocaleString()}</span>
          </div>
        </div>

        <div style={{ background: '#fff', border: '1px solid #f3f4f6', borderRadius: 14, padding: '20px 22px' }}>
          <SectionHead>Attack types distribution</SectionHead>
          {attackTypes.length === 0
            ? <div style={{ color: '#d1d5db', fontSize: 13, textAlign: 'center', paddingTop: 20 }}>ยังไม่มีข้อมูล</div>
            : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {attackTypes.map((type, idx) => {
                  const totalAttacks = attackTypes.reduce((s, t) => s + t.count, 0)
                  const percentage = totalAttacks > 0 ? (type.count / totalAttacks) * 100 : 0
                  return (
                    <div key={type.label}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12 }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#374151' }}>
                          <span style={{ width: 8, height: 8, borderRadius: '50%', background: type.color, display: 'inline-block' }} />
                          {type.label}
                        </span>
                        <span style={{ fontWeight: 600, color: type.color }}>{type.count}</span>
                      </div>
                      <div style={{ background: '#f3f4f6', borderRadius: 4, height: 6, overflow: 'hidden' }}>
                        <div style={{ height: '100%', background: type.color, borderRadius: 4, width: `${percentage}%`, transition: 'width 0.8s ease' }} />
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
        </div>
      </div>

      {/* Top domains + Top users */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(320px,1fr))', gap: 14 }}>
        <div style={{ background: '#fff', border: '1px solid #f3f4f6', borderRadius: 14, padding: '20px 22px' }}>
          <SectionHead>Top attacker domains</SectionHead>
          {domains.length === 0
            ? <div style={{ color: '#d1d5db', fontSize: 13, textAlign: 'center', paddingTop: 20 }}>ยังไม่มีข้อมูล</div>
            : domains.map((d, i) => {
              const barColors = ['#ef4444','#f97316','#f59e0b','#84cc16','#22c55e']
              return (
                <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 11 }}>
                  <div style={{ width: 22, height: 22, borderRadius: 6, fontSize: 10, fontWeight: 700, background: i === 0 ? '#fee2e2' : '#f3f4f6', color: i === 0 ? '#dc2626' : '#6b7280', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{i + 1}</div>
                  <div style={{ flex: 1, overflow: 'hidden' }}>
                    <div style={{ fontSize: 12, color: '#374151', fontFamily: 'monospace', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{d.name}</div>
                    <div style={{ background: '#f3f4f6', borderRadius: 3, height: 5, marginTop: 4, overflow: 'hidden' }}>
                      <div style={{ height: '100%', borderRadius: 3, background: barColors[i], width: `${(d.count / maxDomain) * 100}%`, transition: 'width 0.8s ease' }} />
                    </div>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: i === 0 ? '#dc2626' : '#374151', minWidth: 28, textAlign: 'right' }}>{d.count}</div>
                </div>
              )
            })
          }
        </div>

        <div style={{ background: '#fff', border: '1px solid #f3f4f6', borderRadius: 14, padding: '20px 22px' }}>
          <SectionHead>Most targeted users</SectionHead>
          {users.length === 0
            ? <div style={{ color: '#d1d5db', fontSize: 13, textAlign: 'center', paddingTop: 20 }}>ยังไม่มีข้อมูล</div>
            : users.map((u, i) => {
              const avatarColors = [['#dbeafe','#1d4ed8'],['#dcfce7','#15803d'],['#fce7f3','#be185d'],['#ffedd5','#c2410c'],['#ede9fe','#6d28d9']]
              const [bg, fg] = avatarColors[i % avatarColors.length]
              return (
                <div key={u.email} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: i < users.length - 1 ? '1px solid #f9fafb' : 'none' }}>
                  <div style={{ width: 32, height: 32, borderRadius: '50%', background: bg, color: fg, fontSize: 11, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>{initials(u.email)}</div>
                  <div style={{ flex: 1, overflow: 'hidden' }}>
                    <div style={{ fontSize: 12, color: '#374151', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{u.email}</div>
                    <div style={{ fontSize: 11, color: '#9ca3af' }}>{u.dept}</div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 15, fontWeight: 700, color: '#dc2626' }}>{u.hits}</span>
                    <span style={{ fontSize: 10, padding: '2px 6px', background: '#fee2e2', color: '#991b1b', borderRadius: 20, fontWeight: 600 }}>attacks</span>
                  </div>
                </div>
              )
            })
          }
        </div>
      </div>

    </div>
    ) : (
      <EmailLogs isDarkMode={isDarkMode} />
    )}
    </>
  )
}