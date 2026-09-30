/**
 * Overview: the one-page summary of an analysis.
 *
 * Nothing here is computed. Where the backend did not determine a property,
 * this view shows NOT VERIFIABLE rather than a value, because a blank or a zero
 * would read as "fine" when it actually means "not known".
 */
import { useAnalysis } from '../App'
import { NOT_VERIFIABLE, bytes, payload, percent, show, sortFindings, timestamp } from '../api/format'
import { Card, EvidenceTag, Field, Fields, NotVerifiableNote, ScoreCard, StatusTag, UnavailableNote } from '../components/ui'
import { NoAnalysis } from '../components/NoAnalysis'

interface Finding {
  rule_id?: string
  title?: string
  status?: string
  severity?: string
  evidence_status?: string
}

export default function OverviewView() {
  const { bundle } = useAnalysis()
  if (!bundle) return <NoAnalysis />

  const protocol = payload(bundle, 'protocol')
  const details = (protocol.details as Record<string, unknown> | undefined) ?? {}
  const scan = (details.scan as Record<string, unknown> | undefined) ?? {}
  const pfs = (protocol.pfs as Record<string, unknown> | undefined) ?? (details.pfs as Record<string, unknown> | undefined) ?? {}
  const security = payload(bundle, 'security')
  const traffic = payload(bundle, 'traffic')
  const privacy = payload(bundle, 'privacy')
  const findings = (security.findings as Finding[] | undefined) ?? []
  const weaknesses = sortFindings(findings).filter((item) => item.status === 'FAIL' || item.status === 'WARNING')

  return (
    <div className="view">
      <h2>Overview</h2>

      <Card title="Analysis">
        <Fields>
          <Field label="Analysis ID" value={bundle.analysis_id} />
          <Field label="Created at" value={timestamp(bundle.created_at)} />
          <Field label="Source" value={bundle.source.kind} />
          <Field label="Capture" value={bundle.source.filename} />
          <Field label="Size" value={bytes(bundle.source.size_bytes)} />
          <Field label="Overall status" value={bundle.status} />
        </Fields>
      </Card>

      <div className="grid grid-2">
        <Card title="Security posture">
          <ScoreCard score={security.security_score} band={security.risk_level} />
          <p className="muted">{show(security.summary, 'not scored')}</p>
          <Fields>
            <Field label="Evidence coverage" value={percent(security.evidence_coverage)} />
            <Field label="Findings" value={`${findings.length} evaluated`} />
            <Field label="Weaknesses" value={`${weaknesses.length}`} />
          </Fields>
        </Card>

        <Card title="IPsec posture" subtitle="From what the capture actually carried">
          <Fields>
            <Field label="Packets" value={protocol.packets ?? scan.packets} />
            <Field label="IKE packets" value={protocol.ike_packets ?? scan.ike_packets} />
            <Field label="ESP packets" value={protocol.esp_packets ?? scan.esp_packets} />
            <Field label="AH packets" value={scan.ah_packets ?? 0} fallback="none seen" />
            <Field label="IPv4 packets" value={scan.ipv4_packets} />
            <Field label="IPv6 packets" value={scan.ipv6_packets} />
            <Field label="PFS" value={pfs.status} fallback={NOT_VERIFIABLE} />
          </Fields>
        </Card>
      </div>


      <Card
        title="Traffic intelligence"
        subtitle="A model's inference about ciphertext behaviour, not an observation of content"
      >
        {traffic.predicted_class ? (
          <>
            <p>
              <strong>{show(traffic.predicted_class)}</strong> &middot; confidence{' '}
              <strong>{percent(traffic.confidence)}</strong> &middot; <EvidenceTag status="INFERRED" />
            </p>
            {traffic.low_confidence ? (
              <p className="note note-warning">
                Confidence is below the configured threshold; treat this label as weak.
              </p>
            ) : null}
            <Fields>
              <Field label="Model" value={traffic.model_id} />
              <Field label="Model version" value={traffic.model_version} />
              <Field label="Feature schema" value={traffic.feature_schema} />
            </Fields>
          </>
        ) : (
          <UnavailableNote bundle={bundle} stage="traffic" />
        )}
      </Card>

      <Card title="Metadata exposure">
        <Fields>
          <Field label="Exposure score" value={privacy.privacy_risk} />
          <Field label="Exposure level" value={privacy.exposure_level} />
          <Field label="Most observable" value={privacy.top_observable} />
          <Field label="Coverage" value={percent(privacy.coverage)} />
        </Fields>
      </Card>

      <Card title="Major findings" subtitle="Weaknesses first; NOT VERIFIABLE is not a failure">
        {weaknesses.length === 0 ? (
          <p className="muted">No failing or warning findings were raised.</p>
        ) : (
          <ul className="findings">
            {weaknesses.slice(0, 8).map((finding) => (
              <li key={finding.rule_id ?? finding.title}>
                <StatusTag status={finding.status} />
                <strong>{show(finding.title, 'untitled')}</strong>
                <span className="muted"> {show(finding.severity)}</span>
                <EvidenceTag status={finding.evidence_status} />
              </li>
            ))}
          </ul>
        )}
        <NotVerifiableNote />
      </Card>

      <Card title="Stage coverage">
        <Fields>
          {Object.entries(bundle.components).map(([name, component]) => (
            <Field key={name} label={name} value={component.status} />
          ))}
        </Fields>
        {bundle.status === 'partial' ? (
          <p className="note">
            This analysis is <strong>partial</strong>: the core protocol stage succeeded, but at least one
            optional stage could not run here. The sections it would have filled show their reason instead.
          </p>
        ) : null}
      </Card>
    </div>
  )
}
