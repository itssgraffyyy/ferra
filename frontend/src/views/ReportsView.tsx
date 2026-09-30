/**
 * Reports: download links served by the backend.
 *
 * The dashboard renders no report itself. Every artefact is produced by the API
 * from the stored bundle, which is what guarantees a report can never contain
 * something the analysis did not produce.
 */
import { useState } from 'react'
import { api } from '../api/client'
import { useAnalysis } from '../App'
import { Card, Field, Fields, UnavailableNote } from '../components/ui'
import { NoAnalysis } from '../components/NoAnalysis'

const REPORTS = [
  { type: 'executive', label: 'Executive report', description: 'One page for a decision maker: posture, score, top findings, actions, and what could not be verified.' },
  { type: 'technical', label: 'Technical report', description: 'The full sectioned account: protocol, cryptography, SAs, findings with evidence, threat matrix, privacy exposure.' },
  { type: 'json', label: 'Raw JSON export', description: 'The canonical bundle exactly as the analysis produced it.' },
]

export default function ReportsView() {
  const { bundle, capabilities } = useAnalysis()
  const [format, setFormat] = useState<'html' | 'pdf'>('html')
  if (!bundle) return <NoAnalysis />

  const reporting = capabilities?.capabilities?.report_generation
  const pdfAvailable = reporting?.formats?.includes('pdf') ?? false

  return (
    <div className="view">
      <h2>Reports</h2>
      <p className="muted">
        Reports are rendered by the backend from the stored bundle. Nothing is re-analysed to produce them, so a
        report cannot claim evidence the analysis does not have.
      </p>

      {reporting && reporting.status === 'unavailable' ? <UnavailableNote bundle={bundle} stage="security" /> : null}

      {pdfAvailable ? (
        <label className="inline">
          Format
          <select value={format} onChange={(event) => setFormat(event.target.value as 'html' | 'pdf')}>
            <option value="html">HTML (printable)</option>
            <option value="pdf">PDF</option>
          </select>
        </label>
      ) : (
        <p className="muted">
          PDF export needs the optional <code>reportlab</code> package. {reporting?.pdf_reason ?? ''}
        </p>
      )}

      <Card title="Available reports">
        <ul className="report-list">
          {REPORTS.map((report) => (
            <li key={report.type}>
              <div>
                <strong>{report.label}</strong>
                <p className="muted">{report.description}</p>
              </div>
              <a
                className="button"
                href={api.reportUrl(bundle.analysis_id, report.type, report.type === 'json' ? 'html' : format)}
                target="_blank"
                rel="noreferrer"
                download
              >
                Download
              </a>
            </li>
          ))}
          <li>
            <div>
              <strong>Bundle export</strong>
              <p className="muted">The canonical document, byte for byte.</p>
            </div>
            <a className="button" href={api.exportUrl(bundle.analysis_id)} target="_blank" rel="noreferrer" download>
              Download
            </a>
          </li>
        </ul>
      </Card>

      <Card title="Analysis">
        <Fields>
          <Field label="Analysis ID" value={bundle.analysis_id} />
          <Field label="Bundle schema" value={bundle.schema_version} />
          <Field label="Created at" value={bundle.created_at} />
        </Fields>
      </Card>
    </div>
  )
}
