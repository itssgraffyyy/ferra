/**
 * Security assessment: the backend's verdict, unmodified.
 *
 * The score, the band and every finding come straight from the assessment
 * engine. This view deliberately computes nothing: recomputing a score in the
 * browser is exactly the kind of second source of truth the bundle exists to
 * prevent. NOT_VERIFIABLE is displayed as its own status and is never merged
 * into a failure.
 */
import { useAnalysis } from '../App'
import { hasPayload, payload, percent, show, sortFindings } from '../api/format'
import { Card, EvidenceTag, Field, Fields, NotVerifiableNote, ScoreCard, StatusTag, Table, UnavailableNote } from '../components/ui'
import { NoAnalysis } from '../components/NoAnalysis'

interface Finding {
  rule_id?: string
  title?: string
  status?: string
  severity?: string
  evidence_status?: string
  category?: string
  explanation?: string
  recommendation?: string
  points_deducted?: number
}

interface CategoryScore {
  category?: string
  score?: number
  max_score?: number
  weight?: number
  coverage?: number
}

interface Recommendation {
  priority?: number
  recommendation?: string
  reason?: string
  severity?: string
}

export default function SecurityView() {
  const { bundle } = useAnalysis()
  if (!bundle) return <NoAnalysis />
  if (!hasPayload(bundle, 'security')) {
    return (
      <div className="view">
        <h2>Security assessment</h2>
        <UnavailableNote bundle={bundle} stage="security" />
      </div>
    )
  }

  const security = payload(bundle, 'security')
  const findings = sortFindings((security.findings as Finding[] | undefined) ?? [])
  const categories = (security.category_scores as CategoryScore[] | undefined) ?? []
  const recommendations = (security.recommendations as Recommendation[] | undefined) ?? []
  const metadata = (security.metadata_exposure as Record<string, unknown> | undefined) ?? {}
  const observable = (metadata.observable as Record<string, unknown> | undefined) ?? {}

  return (
    <div className="view">
      <h2>Security assessment</h2>

      <div className="grid grid-2">
        <Card title="Overall">
          <ScoreCard score={security.security_score} band={security.risk_level} />
          <p className="muted">{show(security.summary, 'not scored')}</p>
          <Fields>
            <Field label="Evidence coverage" value={percent(security.evidence_coverage)} />
            <Field label="Findings evaluated" value={findings.length} />
          </Fields>
        </Card>

        <Card title="Category scores">
          <Table
            headers={['Category', 'Score', 'Max', 'Coverage']}
            rows={categories.map((item) => [
              show(item.category, 'general').replace(/_/g, ' '),
              show(item.score),
              show(item.max_score),
              percent(item.coverage),
            ])}
          />
        </Card>
      </div>

      <Card
        title="Findings"
        subtitle="Weaknesses first. NOT VERIFIABLE is an unanswered question, not a failure."
      >
        {findings.length === 0 ? (
          <p className="muted">No findings were produced.</p>
        ) : (
          <ul className="findings detailed">
            {findings.map((finding) => (
              <li key={finding.rule_id ?? finding.title}>
                <div className="finding-head">
                  <StatusTag status={finding.status} />
                  <strong>{show(finding.title, 'untitled')}</strong>
                  <span className="muted">{show(finding.severity)}</span>
                  <EvidenceTag status={finding.evidence_status} />
                </div>
                {finding.explanation ? <p className="muted">{finding.explanation}</p> : null}
                {finding.recommendation ? <p className="advice">{finding.recommendation}</p> : null}
              </li>
            ))}
          </ul>
        )}
        <NotVerifiableNote />
      </Card>

      <Card title="Metadata exposure">
        <Fields>
          <Field label="Fingerprintability" value={metadata.fingerprintability} />
          <Field label="Inference risk" value={metadata.inference_risk} />
          <Field label="Capture packets" value={observable.capture_packets} />
          <Field label="ESP flows" value={observable.esp_flows} />
          <Field label="Distinct ESP SPIs" value={observable.distinct_esp_spi} />
        </Fields>
      </Card>

      <Card title="Recommendations">
        <Table
          headers={['#', 'Recommendation', 'Why']}
          rows={recommendations.map((item) => [
            show(item.priority),
            show(item.recommendation),
            show(item.reason),
          ])}
        />
      </Card>
    </div>
  )
}
