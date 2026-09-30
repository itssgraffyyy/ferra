/**
 * History: real records from the local SQLite store.
 *
 * There is no demo data here. Every row is a stored analysis, and opening one
 * re-reads its canonical bundle rather than re-running the pipeline.
 */
import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ApiError, api } from '../api/client'
import { bytes, percent, show, timestamp } from '../api/format'
import type { HistoryRow } from '../api/types'
import { useAnalysis } from '../App'
import { BandTag, Card, Table } from '../components/ui'

export default function HistoryView() {
  const { setBundle } = useAnalysis()
  const navigate = useNavigate()
  const [rows, setRows] = useState<HistoryRow[]>([])
  const [failure, setFailure] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [filter, setFilter] = useState({ risk_band: '', source_mode: '' })

  const load = useCallback(async () => {
    setBusy(true)
    setFailure(null)
    try {
      const result = await api.listAnalyses({ limit: 100, risk_band: filter.risk_band, source_mode: filter.source_mode })
      setRows(result.analyses)
    } catch (cause) {
      setFailure(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }, [filter])

  useEffect(() => {
    void load()
  }, [load])

  const open = async (id: string) => {
    try {
      setBundle(await api.getAnalysis(id))
      navigate(`/analyses/${id}`)
    } catch (cause) {
      setFailure(cause instanceof ApiError ? cause.message : String(cause))
    }
  }

  const remove = async (row: HistoryRow) => {
    const confirmed = window.confirm(
      `Delete analysis ${row.analysis_id} (${row.display_filename})? Its stored bundle will be removed. This cannot be undone.`,
    )
    if (!confirmed) return
    try {
      await api.deleteAnalysis(row.analysis_id)
      await load()
    } catch (cause) {
      setFailure(cause instanceof ApiError ? cause.message : String(cause))
    }
  }

  return (
    <div className="view">
      <h2>Analysis history</h2>
      <p className="muted">
        {rows.length} stored {rows.length === 1 ? 'analysis' : 'analyses'}. Opening a record re-reads its stored
        bundle; the pipeline is not re-run.
      </p>

      <section className="card">
        <div className="filters">
          <label>
            Risk band
            <select value={filter.risk_band} onChange={(event) => setFilter({ ...filter, risk_band: event.target.value })}>
              <option value="">any</option>
              <option value="LOW">LOW</option>
              <option value="MODERATE">MODERATE</option>
              <option value="HIGH">HIGH</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </label>
          <label>
            Source
            <select value={filter.source_mode} onChange={(event) => setFilter({ ...filter, source_mode: event.target.value })}>
              <option value="">any</option>
              <option value="upload">upload</option>
              <option value="live">live</option>
              <option value="path">path</option>
            </select>
          </label>
          <button type="button" onClick={() => void load()} disabled={busy}>
            {busy ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </section>

      {failure ? <p className="banner banner-error">{failure}</p> : null}

      <Card title="Stored analyses">
        <Table
          headers={['When', 'Capture', 'Source', 'Traffic', 'Confidence', 'Security', 'Risk', 'State', 'Actions']}
          rows={rows.map((row) => [
            timestamp(row.created_at),
            `${row.display_filename} (${bytes(row.capture_size)})`,
            row.source_mode,
            row.traffic_prediction ?? 'not classified',
            row.traffic_confidence === null ? '—' : percent(row.traffic_confidence),
            row.security_score === null ? 'not scored' : show(row.security_score),
            <BandTag key="band" band={row.risk_band} />,
            row.analysis_state,
            <span key="actions">
              <button type="button" onClick={() => void open(row.analysis_id)}>
                Open
              </button>{' '}
              <button type="button" className="danger" onClick={() => void remove(row)}>
                Delete
              </button>
            </span>,
          ])}
        />
        {rows.length === 0 && !busy ? (
          <p className="muted">Nothing stored yet. Analyse a capture to create the first record.</p>
        ) : null}
      </Card>
    </div>
  )
}
