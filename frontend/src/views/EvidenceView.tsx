/**
 * Evidence: FERA's provenance model, made visible.
 *
 * This is the view that answers "how do I know that?". Every conclusion is
 * grouped by its evidence status, so an inferred result never reads like an
 * observed one and an unanswerable question is visibly unanswered rather than
 * quietly absent.
 */
import { useAnalysis } from '../App'
import { EVIDENCE_LABEL, payload, show } from '../api/format'
import type { AnalysisBundle, EvidenceStatus } from '../api/types'
import { Card, EvidenceTag, Table } from '../components/ui'
import { NoAnalysis } from '../components/NoAnalysis'

interface Finding {
  rule_id?: string
  title?: string
  status?: string
  severity?: string
  evidence_status?: string
  explanation?: string
  confidence?: number
  evidence?: unknown
}

const GROUPS: EvidenceStatus[] = ['OBSERVED', 'CONFIGURED', 'INFERRED', 'NOT_VERIFIABLE']

/** A few headline protocol conclusions, shown with the status the analyser gave them. */
function protocolEvidence(bundle: AnalysisBundle): { conclusion: string; status: string; note: string }[] {
  const protocol = payload(bundle, 'protocol')
  const details = (protocol.details as Record<string, unknown> | undefined) ?? {}
  const scan = (details.scan as Record<string, unknown> | undefined) ?? {}
  const pfs = (protocol.pfs as Record<string, unknown> | undefined) ?? (details.pfs as Record<string, unknown> | undefined) ?? {}
  const rows: { conclusion: string; status: string; note: string }[] = []
  if (protocol.ike_packets ?? scan.ike_packets) {
    rows.push({ conclusion: 'IKE traffic present', status: 'OBSERVED', note: `${show(protocol.ike_packets ?? scan.ike_packets)} packet(s)` })
  }
  if (protocol.esp_packets ?? scan.esp_packets) {
    rows.push({ conclusion: 'ESP traffic present', status: 'OBSERVED', note: `${show(protocol.esp_packets ?? scan.esp_packets)} packet(s)` })
  }
  rows.push({
    conclusion: 'Perfect forward secrecy',
    status: pfs.status === 'NOT_VERIFIABLE' ? 'NOT_VERIFIABLE' : 'OBSERVED',
    note: show(pfs.reason, 'established from the capture'),
  })
  rows.push({
    conclusion: 'Anti-replay enforcement',
    status: 'NOT_VERIFIABLE',
    note: 'a passive capture shows the sequence numbers sent, never whether they were accepted',
  })
  return rows
}

export default function EvidenceView() {
  const { bundle } = useAnalysis()
  if (!bundle) return <NoAnalysis />

  const security = payload(bundle, 'security')
  const privacy = payload(bundle, 'privacy')
  const traffic = payload(bundle, 'traffic')
  const findings = (security.findings as Finding[] | undefined) ?? []

  const rows: { conclusion: string; status: string; note: string }[] = [
    ...protocolEvidence(bundle),
    ...(traffic.predicted_class
      ? [
          {
            conclusion: `Traffic class: ${show(traffic.predicted_class)}`,
            status: 'INFERRED',
            note: `model confidence ${(Number(traffic.confidence) * 100 || 0).toFixed(0)}% (${show(traffic.model_id)})`,
          },
        ]
      : []),
  ]

  return (
    <div className="view">
      <h2>Evidence</h2>
      <p className="muted">
        FERA records where each conclusion came from. Results are not equally certain, and this page makes that
        difference visible instead of flattening everything into one list of facts.
      </p>

      <Card title="Headline conclusions">
        <Table
          headers={['Conclusion', 'Evidence status', 'Basis']}
          rows={rows.map((row) => [row.conclusion, <EvidenceTag key="s" status={row.status} />, row.note])}
        />
      </Card>

      {GROUPS.map((group) => {
        const inGroup = findings.filter((item) => (item.evidence_status ?? '').toUpperCase() === group)
        return (
          <Card key={group} title={EVIDENCE_LABEL[group]}>
            {inGroup.length === 0 ? (
              <p className="muted">No finding rests on {EVIDENCE_LABEL[group].toLowerCase()} in this analysis.</p>
            ) : (
              <ul className="findings">
                {inGroup.map((finding) => (
                  <li key={finding.rule_id ?? finding.title}>
                    <EvidenceTag status={finding.evidence_status} />
                    <strong>{show(finding.title, 'untitled')}</strong>
                    <span className="muted"> {show(finding.severity)}</span>
                    {finding.explanation ? <p className="muted">{finding.explanation}</p> : null}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        )
      })}

      <Card title="Privacy observations">
        <Table
          headers={['Observation', 'Topic', 'Exposure', 'Evidence']}
          rows={((privacy.observations as Record<string, unknown>[] | undefined) ?? []).map((item) => [
            show(item.title, 'observation'),
            show(item.topic),
            show(item.exposure),
            show((item.evidence as string[] | undefined)?.join('; ')),
          ])}
        />
      </Card>
    </div>
  )
}
