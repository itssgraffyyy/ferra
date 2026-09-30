/**
 * Threat matrix: rendered from the assessment engine's own output.
 *
 * No threat is invented, re-ranked or re-scored here. Likelihood and impact are
 * shown only when the backend actually supplied them, so the table never
 * implies a precision the assessment did not produce.
 */
import { useAnalysis } from '../App'
import { hasPayload, payload, show } from '../api/format'
import { BandTag, Card, Table, UnavailableNote } from '../components/ui'
import { NoAnalysis } from '../components/NoAnalysis'

interface Threat {
  threat_id?: string
  threat?: string
  category?: string
  risk?: string
  likelihood?: string
  impact?: string
  evidence?: string
  recommendation?: string
  rule_ids?: string[]
}

export default function ThreatView() {
  const { bundle } = useAnalysis()
  if (!bundle) return <NoAnalysis />
  if (!hasPayload(bundle, 'security')) {
    return (
      <div className="view">
        <h2>Threat matrix</h2>
        <UnavailableNote bundle={bundle} stage="security" />
      </div>
    )
  }

  const security = payload(bundle, 'security')
  const threats = (security.threat_matrix as Threat[] | undefined) ?? []
  const hasAxes = threats.some((item) => item.likelihood || item.impact)
  const headers = hasAxes
    ? ['Threat', 'Risk', 'Likelihood', 'Impact', 'Evidence', 'Recommendation']
    : ['Threat', 'Risk', 'Evidence', 'Recommendation']

  return (
    <div className="view">
      <h2>Threat matrix</h2>
      <p className="muted">
        Every row is a threat the assessment engine raised from evidence in this capture. Nothing here is
        speculative: a threat appears because a rule fired, and its evidence names the rule.
      </p>

      <Card title={`${threats.length} threat${threats.length === 1 ? '' : 's'}`}>
        {threats.length === 0 ? (
          <p className="muted">No threats were raised for this capture.</p>
        ) : (
          <Table
            headers={headers}
            rows={threats.map((item) => {
              const core = [
                show(item.threat ?? item.threat_id, 'threat'),
                <BandTag key="risk" band={item.risk} />,
              ]
              if (hasAxes) core.push(show(item.likelihood), show(item.impact))
              core.push(show(item.evidence), show(item.recommendation))
              return core
            })}
          />
        )}
      </Card>
    </div>
  )
}
