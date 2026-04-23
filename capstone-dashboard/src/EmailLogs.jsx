import { useState, useEffect } from 'react'

const API_BASE = 'http://127.0.0.1:8000'

function getStatusBadge(score) {
  if (score > 80) return { label: 'Block', color: '#b91c1c', bg: '#fecaca' }
  if (score > 60) return { label: 'Quarantine', color: '#dc2626', bg: '#fca5a5' }
  if (score >= 30) return { label: 'Warning', color: '#d97706', bg: '#fed7aa' }
  return { label: 'Allow', color: '#15803d', bg: '#bbf7d0' }
}

function formatTime(timestamp) {
  if (!timestamp) return 'N/A'
  try {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch {
    return 'N/A'
  }
}

function formatDate(timestamp) {
  if (!timestamp) return 'N/A'
  try {
    const date = new Date(timestamp)
    return date.toLocaleDateString('th-TH', { month: 'short', day: 'numeric' })
  } catch {
    return 'N/A'
  }
}

function DetailModal({ email, onClose, isDarkMode = false }) {
  if (!email) return null
  const status = getStatusBadge(email.final_score)
  
  const darkStyles = {
    bg: isDarkMode ? '#1f2937' : '#fff',
    text: isDarkMode ? '#f3f4f6' : '#111827',
    textSecondary: isDarkMode ? '#d1d5db' : '#6b7280',
    input: isDarkMode ? '#374151' : '#f3f4f6'
  }
  
  return (
    <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, animation: 'fadeIn 0.2s ease' }}>
      <div style={{ background: darkStyles.bg, borderRadius: 12, padding: '24px', maxWidth: '500px', width: '90vw', maxHeight: '80vh', overflow: 'auto', boxShadow: '0 20px 40px rgba(0,0,0,0.3)', animation: 'slideUp 0.3s ease' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 700, color: darkStyles.text }}>Email Details</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', fontSize: 24, cursor: 'pointer', color: darkStyles.text, transition: 'all 0.2s ease' }}>×</button>
        </div>

        <div style={{ display: 'grid', gap: 12, marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 11, color: darkStyles.textSecondary, fontWeight: 600, marginBottom: 4 }}>STATUS</div>
            <div style={{ display: 'inline-block', padding: '6px 12px', borderRadius: 20, background: status.bg, color: status.color, fontWeight: 600, fontSize: 12 }}>
              {status.label}
            </div>
          </div>

          <div>
            <div style={{ fontSize: 11, color: darkStyles.textSecondary, fontWeight: 600, marginBottom: 4 }}>RISK SCORE</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: status.color }}>{email.final_score.toFixed(2)}</div>
          </div>

          <div>
            <div style={{ fontSize: 11, color: darkStyles.textSecondary, fontWeight: 600, marginBottom: 4 }}>FROM</div>
            <div style={{ fontSize: 13, color: darkStyles.text, fontFamily: 'monospace', wordBreak: 'break-all' }}>{email.sender_domain || 'N/A'}</div>
          </div>

          <div>
            <div style={{ fontSize: 11, color: darkStyles.textSecondary, fontWeight: 600, marginBottom: 4 }}>TO</div>
            <div style={{ fontSize: 13, color: darkStyles.text, fontFamily: 'monospace', wordBreak: 'break-all' }}>{email.recipient || 'N/A'}</div>
          </div>

          <div>
            <div style={{ fontSize: 11, color: darkStyles.textSecondary, fontWeight: 600, marginBottom: 4 }}>SUBJECT</div>
            <div style={{ fontSize: 13, color: darkStyles.text }}>{email.subject || 'No Subject'}</div>
          </div>

          <div>
            <div style={{ fontSize: 11, color: darkStyles.textSecondary, fontWeight: 600, marginBottom: 4 }}>TIMESTAMP</div>
            <div style={{ fontSize: 13, color: darkStyles.text }}>{formatDate(email.timestamp)} {formatTime(email.timestamp)}</div>
          </div>

          <div style={{ background: darkStyles.input, borderRadius: 8, padding: 12 }}>
            <div style={{ fontSize: 11, color: darkStyles.textSecondary, fontWeight: 600, marginBottom: 8 }}>RISK COMPONENTS</div>
            <div style={{ display: 'grid', gap: 6, fontSize: 12, color: darkStyles.text }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>AI Score</span>
                <span style={{ fontWeight: 600 }}>{(email.ai_score || 0).toFixed(2)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Link Risk</span>
                <span style={{ fontWeight: 600 }}>{(email.link_risk || 0).toFixed(2)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Domain Risk</span>
                <span style={{ fontWeight: 600 }}>{(email.domain_risk || 0).toFixed(2)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Header Anomaly</span>
                <span style={{ fontWeight: 600 }}>{(email.header_anomaly || 0).toFixed(2)}</span>
              </div>
            </div>
          </div>
        </div>

        <button onClick={onClose} style={{ width: '100%', padding: '10px', background: 'linear-gradient(135deg,#1e40af,#7c3aed)', color: '#fff', border: 'none', borderRadius: 8, fontWeight: 600, cursor: 'pointer', transition: 'all 0.3s ease', boxShadow: '0 4px 12px rgba(30,64,175,0.3)' }}>
          Close
        </button>
      </div>
    </div>
  )
}

export default function EmailLogs({ isDarkMode = false }) {
  const [emails, setEmails] = useState([])
  const [selectedEmail, setSelectedEmail] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [filterStatus, setFilterStatus] = useState('all')
  const [currentPage, setCurrentPage] = useState(1)
  const ITEMS_PER_PAGE = 50

  const darkStyles = {
    bg: isDarkMode ? '#111827' : '#f9fafb',
    bgCard: isDarkMode ? '#1f2937' : '#fff',
    text: isDarkMode ? '#f3f4f6' : '#111827',
    textSecondary: isDarkMode ? '#d1d5db' : '#6b7280',
    border: isDarkMode ? '#374151' : '#f3f4f6',
    input: isDarkMode ? '#374151' : '#f3f4f6',
    inputText: isDarkMode ? '#f3f4f6' : '#111827'
  }

  const fetchEmails = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`${API_BASE}/logs`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      if (data.data) setEmails(data.data)
    } catch (e) {
      setError('ไม่สามารถเชื่อมต่อ Backend ได้ — ' + e.message)
    }
    setLoading(false)
  }

  useEffect(() => {
    fetchEmails()
    // Polling ทุก 5 วินาที
    const interval = setInterval(fetchEmails, 5000)
    return () => clearInterval(interval)
  }, [])

  // ฟังก์ชันกรองเมล
  const filteredEmails = emails.filter(email => {
    const matchesSearch = email.sender_domain?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          email.recipient?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          email.subject?.toLowerCase().includes(searchTerm.toLowerCase())
    
    let matchesStatus = true
    if (filterStatus !== 'all') {
      const score = email.final_score
      matchesStatus = 
        (filterStatus === 'allow' && score < 30) ||
        (filterStatus === 'warning' && score >= 30 && score < 60) ||
        (filterStatus === 'quarantine' && score >= 60 && score < 80) ||
        (filterStatus === 'block' && score >= 80)
    }
    
    return matchesSearch && matchesStatus
  })

  // Pagination
  const totalPages = Math.ceil(filteredEmails.length / ITEMS_PER_PAGE)
  const startIdx = (currentPage - 1) * ITEMS_PER_PAGE
  const endIdx = startIdx + ITEMS_PER_PAGE
  const paginatedEmails = filteredEmails.slice(startIdx, endIdx)

  // Reset to page 1 when filtering or searching
  useEffect(() => {
    setCurrentPage(1)
  }, [searchTerm, filterStatus])

  return (
    <div style={{ background: darkStyles.bg, minHeight: '100vh', padding: 'clamp(14px,2.4vw,32px)', fontFamily: "'DM Sans','Segoe UI',sans-serif", color: darkStyles.text, transition: 'background-color 0.3s ease' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 28 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: 'linear-gradient(135deg,#1e40af,#7c3aed)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16 }}>📧</div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0, color: darkStyles.text }}>Email Logs</h1>
            {loading && <span style={{ fontSize: 11, color: darkStyles.textSecondary, background: darkStyles.input, padding: '2px 8px', borderRadius: 20 }}>Scanning…</span>}
          </div>
          <p style={{ fontSize: 13, color: darkStyles.textSecondary, margin: 0 }}>
            Real-time email analysis and threat detection
          </p>
          {error && <p style={{ fontSize: 12, color: '#dc2626', margin: '4px 0 0', background: isDarkMode ? 'rgba(220,38,38,0.2)' : '#fee2e2', padding: '4px 10px', borderRadius: 6 }}>⚠ {error}</p>}
        </div>
        <button onClick={fetchEmails} style={{ background: 'linear-gradient(135deg,#1e40af,#7c3aed)', color: '#fff', border: 'none', padding: '8px 18px', borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: 'pointer', transition: 'all 0.3s ease', boxShadow: '0 4px 12px rgba(30,64,175,0.3)' }}>
          ↻ Refresh
        </button>
      </div>

      {/* Search & Filter */}
      <div style={{ background: darkStyles.bgCard, border: `1px solid ${darkStyles.border}`, borderRadius: 12, padding: '16px', marginBottom: 20, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 12, boxShadow: isDarkMode ? 'none' : '0 2px 8px rgba(0,0,0,0.05)', transition: 'all 0.3s ease' }}>
        <div>
          <label style={{ fontSize: 11, fontWeight: 600, color: darkStyles.textSecondary, display: 'block', marginBottom: 6 }}>SEARCH</label>
          <input
            type="text"
            placeholder="Search by sender, recipient, or subject..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%', padding: '10px 12px', borderRadius: 8,
              border: `1px solid ${darkStyles.border}`,
              background: darkStyles.input, color: darkStyles.inputText,
              fontSize: 13, fontFamily: 'inherit',
              transition: 'all 0.3s ease',
              boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
            }}
          />
        </div>
        <div>
          <label style={{ fontSize: 11, fontWeight: 600, color: darkStyles.textSecondary, display: 'block', marginBottom: 6 }}>FILTER STATUS</label>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            style={{
              width: '100%', padding: '10px 12px', borderRadius: 8,
              border: `1px solid ${darkStyles.border}`,
              background: darkStyles.input, color: darkStyles.inputText,
              fontSize: 13, fontFamily: 'inherit',
              transition: 'all 0.3s ease',
              boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
            }}
          >
            <option value="all">All Statuses</option>
            <option value="allow">Allow</option>
            <option value="warning">Warning</option>
            <option value="quarantine">Quarantine</option>
            <option value="block">Block</option>
          </select>
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-end' }}>
          <button onClick={() => { setSearchTerm(''); setFilterStatus('all') }} style={{ width: '100%', padding: '10px 12px', borderRadius: 8, border: `1px solid ${darkStyles.border}`, background: 'transparent', color: darkStyles.text, fontSize: 13, fontWeight: 600, cursor: 'pointer', transition: 'all 0.3s ease' }}>
            Reset Filters
          </button>
        </div>
      </div>

      {/* Email List */}
      <div style={{ background: darkStyles.bgCard, border: `1px solid ${darkStyles.border}`, borderRadius: 14, overflow: 'hidden', boxShadow: isDarkMode ? '0 4px 12px rgba(0,0,0,0.3)' : '0 4px 12px rgba(0,0,0,0.1)', transition: 'all 0.3s ease' }}>
        {filteredEmails.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: darkStyles.textSecondary }}>
            <p style={{ fontSize: 14, margin: 0 }}>{emails.length === 0 ? 'ยังไม่มีอีเมลเข้ามา' : 'ไม่พบผลลัพธ์'}</p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: darkStyles.input, borderBottom: `1px solid ${darkStyles.border}` }}>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: darkStyles.textSecondary, textTransform: 'uppercase' }}>Time</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: darkStyles.textSecondary, textTransform: 'uppercase' }}>From</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: darkStyles.textSecondary, textTransform: 'uppercase' }}>To</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: darkStyles.textSecondary, textTransform: 'uppercase' }}>Subject</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: darkStyles.textSecondary, textTransform: 'uppercase' }}>Status</th>
                  <th style={{ padding: '12px 16px', textAlign: 'center', fontSize: 12, fontWeight: 600, color: darkStyles.textSecondary, textTransform: 'uppercase' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {paginatedEmails.map((email, idx) => {
                  const status = getStatusBadge(email.final_score)
                  return (
                    <tr key={idx} style={{ borderBottom: idx < paginatedEmails.length - 1 ? `1px solid ${darkStyles.border}` : 'none', transition: 'all 0.2s ease' }}>
                      <td style={{ padding: '12px 16px', fontSize: 12, color: darkStyles.text, whiteSpace: 'nowrap' }}>{formatTime(email.timestamp)}</td>
                      <td style={{ padding: '12px 16px', fontSize: 12, color: darkStyles.text, fontFamily: 'monospace', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={email.sender_domain}>{email.sender_domain || 'N/A'}</td>
                      <td style={{ padding: '12px 16px', fontSize: 12, color: darkStyles.text, fontFamily: 'monospace', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={email.recipient}>{email.recipient || 'N/A'}</td>
                      <td style={{ padding: '12px 16px', fontSize: 12, color: darkStyles.text, maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={email.subject}>{email.subject || 'No Subject'}</td>
                      <td style={{ padding: '12px 16px', fontSize: 12 }}>
                        <span style={{ display: 'inline-block', padding: '4px 10px', borderRadius: 12, background: status.bg, color: status.color, fontWeight: 600, fontSize: 11 }}>
                          {status.label}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                        <button onClick={() => setSelectedEmail(email)} style={{ background: 'linear-gradient(135deg,#1e40af,#7c3aed)', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600, cursor: 'pointer', transition: 'all 0.3s ease', boxShadow: '0 2px 8px rgba(30,64,175,0.2)' }}>
                          View
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {/* Pagination */}
            <div style={{ padding: '16px', borderTop: `1px solid ${darkStyles.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: darkStyles.input }}>
              <div style={{ fontSize: 12, color: darkStyles.textSecondary }}>
                Showing {startIdx + 1} to {Math.min(endIdx, filteredEmails.length)} of {filteredEmails.length}
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  style={{
                    padding: '8px 12px', fontSize: 12, fontWeight: 600,
                    border: `1px solid ${darkStyles.border}`, borderRadius: 6,
                    background: currentPage === 1 ? darkStyles.input : darkStyles.bgCard,
                    color: darkStyles.text, cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                    opacity: currentPage === 1 ? 0.5 : 1, transition: 'all 0.2s ease'
                  }}>
                  ← Previous
                </button>
                <div style={{ padding: '8px 12px', fontSize: 12, fontWeight: 600, color: darkStyles.text, minWidth: 80, textAlign: 'center' }}>
                  Page {currentPage} / {totalPages || 1}
                </div>
                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  style={{
                    padding: '8px 12px', fontSize: 12, fontWeight: 600,
                    border: `1px solid ${darkStyles.border}`, borderRadius: 6,
                    background: currentPage === totalPages ? darkStyles.input : darkStyles.bgCard,
                    color: darkStyles.text, cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
                    opacity: currentPage === totalPages ? 0.5 : 1, transition: 'all 0.2s ease'
                  }}>
                  Next →
                </button>
              </div>
            </div>
            </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedEmail && <DetailModal email={selectedEmail} onClose={() => setSelectedEmail(null)} isDarkMode={isDarkMode} />}
    </div>
  )
}
