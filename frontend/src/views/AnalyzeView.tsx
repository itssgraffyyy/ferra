/**
 * Analyze: upload a capture, or record a bounded live capture.
 *
 * Progress is a state label (READY / UPLOADING / ANALYZING / COMPLETE / PARTIAL
 * / FAILED), never a percentage. Neither `fetch` nor the API exposes real
 * progress, so a spinner that claimed "60% done" would be fiction.
 */
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ApiError, api } from '../api/client'
import { bytes } from '../api/format'
import type { AnalysisBundle, Capabilities } from '../api/types'
import { useAnalysis } from '../App'

type Phase = 'ready' | 'uploading' | 'analyzing' | 'complete' | 'failed'

const PHASE_LABEL: Record<Phase, string> = {
  ready: 'READY',
  uploading: 'UPLOADING',
  analyzing: 'ANALYZING',
  complete: 'COMPLETE',
  failed: 'FAILED',
}

export default function AnalyzeView({ onAnalyzed }: { onAnalyzed: (bundle: AnalysisBundle) => void }) {
  const { capabilities } = useAnalysis()
  const navigate = useNavigate()
  const [file, setFile] = useState<File | null>(null)
  const [phase, setPhase] = useState<Phase>('ready')
  const [failure, setFailure] = useState<{ message: string; hint: string | null } | null>(null)
  const [interfaceName, setInterfaceName] = useState('any')
  const [duration, setDuration] = useState(10)
  const [liveResult, setLiveResult] = useState<AnalysisBundle | null>(null)

  const live = capabilities?.capabilities?.live_capture
  const liveAvailable = live?.status === 'available'
  const bounds = live?.bounds ?? { default_duration_s: 10, max_duration_s: 60 }

  const runUpload = async () => {
    if (!file) return
    setFailure(null)
    setPhase('uploading')
    // The request is sent as one unit; the "analyzing" label is entered as soon
    // as the body is written, which is the only transition we can actually observe.
    window.setTimeout(() => setPhase('analyzing'), 0)
    try {
      const bundle = await api.analyze(file)
      onAnalyzed(bundle)
      setPhase('complete')
      navigate(`/analyses/${bundle.analysis_id}`)
    } catch (cause) {
      setPhase('failed')
      setFailure(cause instanceof ApiError ? { message: cause.message, hint: cause.hint } : { message: String(cause), hint: null })
    }
  }

  const runLive = async () => {
    setFailure(null)
    setPhase('analyzing')
    try {
      const bundle = await api.analyzeLive({ interface: interfaceName, duration_s: duration })
      onAnalyzed(bundle)
      setLiveResult(bundle)
      setPhase('complete')
    } catch (cause) {
      setPhase('failed')
      setFailure(cause instanceof ApiError ? { message: cause.message, hint: cause.hint } : { message: String(cause), hint: null })
    }
  }

  return (
    <div className="view">
      <h2>Analyze a capture</h2>

      <section className="card">
        <h3>Upload a PCAP</h3>
        <p className="muted">The capture is analysed locally. Nothing leaves this machine.</p>
        <input
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null)
            setPhase('ready')
            setFailure(null)
          }}
        />
        {file ? (
          <p className="muted">
            Selected: <strong>{file.name}</strong> ({bytes(file.size)})
          </p>
        ) : (
          <p className="muted">No file selected.</p>
        )}
        <button type="button" onClick={runUpload} disabled={!file || phase === 'uploading' || phase === 'analyzing'}>
          Analyze capture
        </button>
      </section>

      <section className="card">
        <h3>Record a live capture</h3>
        {liveAvailable ? (
          <>
            <p className="muted">
              Records between {bounds.default_duration_s}s and {bounds.max_duration_s}s, then runs the same analysis
              pipeline as an uploaded file.
            </p>
            <label>
              Interface
              <input value={interfaceName} onChange={(event) => setInterfaceName(event.target.value)} />
            </label>
            <label>
              Duration (seconds)
              <input
                type="number"
                min={bounds.default_duration_s}
                max={bounds.max_duration_s}
                value={duration}
                onChange={(event) => setDuration(Number(event.target.value))}
              />
            </label>
            <button type="button" onClick={runLive} disabled={phase === 'analyzing'}>
              Start capture
            </button>
          </>
        ) : (
          <>
            <p className="note note-warning">
              Live capture is unavailable on this machine. {live?.reason ? `Reason: ${live.reason}` : ''}
            </p>
            <p className="muted">Uploaded captures are unaffected and work without a capture tool.</p>
          </>
        )}
      </section>

      <section className="card">
        <h3>Status</h3>
        <p>
          <span className={`tag tag-${phase}`}>{PHASE_LABEL[phase]}</span>
        </p>
        {failure ? (
          <div className="note note-warning">
            <p className="note-title">Analysis failed</p>
            <p>{failure.message}</p>
            {failure.hint ? <p className="muted">{failure.hint}</p> : null}
          </div>
        ) : null}
        {liveResult ? (
          <p className="muted">
            Live capture stored as <code>{liveResult.analysis_id}</code> with status{' '}
            <span className={`tag tag-${liveResult.status}`}>{liveResult.status}</span>.
          </p>
        ) : null}
      </section>
    </div>
  )
}

/** Re-exported so the History view can render capabilities without a prop. */
export type { Capabilities }
