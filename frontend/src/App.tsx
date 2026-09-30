/**
 * The dashboard shell: navigation plus the analysis context.
 *
 * One analysis is loaded at a time and shared by every view, so the Overview,
 * Protocol, Traffic, Security, Threat, Evidence and Reports tabs all describe
 * the *same* canonical bundle rather than each fetching their own copy.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { NavLink, Navigate, Route, Routes, useNavigate, useParams } from 'react-router-dom'
import { ApiError, api } from './api/client'
import { AnalysisBundle, Capabilities } from './api/types'
import AnalyzeView from './views/AnalyzeView'
import EvidenceView from './views/EvidenceView'
import HistoryView from './views/HistoryView'
import OverviewView from './views/OverviewView'
import ProtocolView from './views/ProtocolView'
import ReportsView from './views/ReportsView'
import SecurityView from './views/SecurityView'
import ThreatView from './views/ThreatView'
import TrafficView from './views/TrafficView'

interface AnalysisContextValue {
  bundle: AnalysisBundle | null
  capabilities: Capabilities | null
  load: (id: string) => Promise<void>
  setBundle: (bundle: AnalysisBundle | null) => void
  reload: () => Promise<void>
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null)

/** Access the currently loaded analysis. Throws outside the provider. */
export function useAnalysis(): AnalysisContextValue {
  const value = useContext(AnalysisContext)
  if (!value) throw new Error('useAnalysis must be used inside the FERA analysis provider')
  return value
}

const NAV = [
  { to: '/analyze', label: 'Analyze' },
  { to: '/analysis', label: 'Overview' },
  { to: '/protocol', label: 'Protocol' },
  { to: '/traffic', label: 'Traffic' },
  { to: '/security', label: 'Security' },
  { to: '/threats', label: 'Threats' },
  { to: '/evidence', label: 'Evidence' },
  { to: '/history', label: 'History' },
  { to: '/reports', label: 'Reports' },
]

export default function App() {
  const [bundle, setBundle] = useState<AnalysisBundle | null>(null)
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    // Capabilities are advisory: a failure here must not block the dashboard,
    // so the error is recorded but no view depends on it being present.
    api
      .capabilities()
      .then(setCapabilities)
      .catch((cause: unknown) => setLoadError(cause instanceof ApiError ? cause.message : String(cause)))
  }, [])

  const load = useCallback(
    async (id: string) => {
      setLoadError(null)
      try {
        setBundle(await api.getAnalysis(id))
      } catch (cause) {
        setBundle(null)
        const message = cause instanceof ApiError ? cause.message : String(cause)
        setLoadError(message)
        throw cause
      }
    },
    [setBundle],
  )

  const reload = useCallback(async () => {
    if (bundle) await load(bundle.analysis_id)
  }, [bundle, load])

  const value = useMemo(
    () => ({ bundle, capabilities, load, setBundle, reload }),
    [bundle, capabilities, load, reload],
  )

  return (
    <AnalysisContext.Provider value={value}>
      <div className="app">
        <header className="masthead">
          <div>
            <h1>FERA</h1>
            <p className="muted">IPsec traffic analysis &middot; evidence-aware, offline-first</p>
          </div>
          {bundle ? (
            <p className="current">
              <span className="muted">Analysis</span> <code>{bundle.analysis_id}</code>{' '}
              <span className={`tag tag-${bundle.status}`}>{bundle.status}</span>
            </p>
          ) : (
            <p className="current muted">No analysis loaded</p>
          )}
        </header>

        <nav className="nav">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
              onClick={() => {
                if (item.to !== '/analyze' && item.to !== '/history') navigate(item.to)
              }}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        {loadError ? <p className="banner banner-error">{loadError}</p> : null}

        <main>
          <Routes>
            <Route path="/" element={<Navigate to="/analyze" replace />} />
            <Route path="/analyze" element={<AnalyzeView onAnalyzed={setBundle} />} />
            <Route path="/analyses/:analysisId" element={<LoadRoute onLoad={load} />} />
            <Route path="/analysis" element={<OverviewView />} />
            <Route path="/protocol" element={<ProtocolView />} />
            <Route path="/traffic" element={<TrafficView />} />
            <Route path="/security" element={<SecurityView />} />
            <Route path="/threats" element={<ThreatView />} />
            <Route path="/evidence" element={<EvidenceView />} />
            <Route path="/history" element={<HistoryView />} />
            <Route path="/reports" element={<ReportsView />} />
            <Route path="*" element={<p className="muted">Page not found.</p>} />
          </Routes>
        </main>

        <footer className="footer">
          <p className="muted">
            Every value shown here is reproduced from the canonical analysis bundle. The dashboard performs no
            analysis of its own and never upgrades an evidence status.
          </p>
        </footer>
      </div>
    </AnalysisContext.Provider>
  )
}

/** Loads the analysis named in the route, then renders its children. */
function LoadRoute({ onLoad }: { onLoad: (id: string) => Promise<void> }) {
  const { analysisId = '' } = useParams()
  useEffect(() => {
    if (analysisId) void onLoad(analysisId).catch(() => undefined)
  }, [analysisId, onLoad])
  return null
}
