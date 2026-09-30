/**
 * Traffic intelligence: the classifier's prediction, kept honestly INFERRED.
 *
 * The most important behaviour here is the unavailable path: with no trained
 * model the view says exactly that, in words, rather than showing an empty bar
 * chart or a generic error.
 */
import { useAnalysis } from '../App'
import { payload, percent, show } from '../api/format'
import { Card, EvidenceTag, Field, Fields, UnavailableNote } from '../components/ui'
import { NoAnalysis } from '../components/NoAnalysis'

export default function TrafficView() {
  const { bundle } = useAnalysis()
  if (!bundle) return <NoAnalysis />

  const traffic = payload(bundle, 'traffic')
  const probabilities = (traffic.probabilities as Record<string, number> | undefined) ?? {}
  const entries = Object.entries(probabilities).sort((a, b) => b[1] - a[1])
  const predicted = traffic.predicted_class as string | undefined

  return (
    <div className="view">
      <h2>Traffic intelligence</h2>

      {!predicted ? (
        <div className="note note-warning">
          <p className="note-title">Traffic classification unavailable.</p>
          <p>
            Reason:{' '}
            {show(
              (bundle.components.traffic?.error?.message) ?? 'no compatible trained model',
            )}
          </p>
          {bundle.components.traffic?.error?.hint ? (
            <p className="muted">How to fix: {bundle.components.traffic.error.hint}</p>
          ) : null}
          <p className="muted">
            Protocol, security and privacy analysis are unaffected: only this optional stage is missing.
          </p>
        </div>
      ) : (
        <>
          <Card title="Prediction" subtitle="Derived from packet size and timing statistics">
            <p className="prediction">
              <strong>{show(predicted)}</strong>
            </p>
            <p>
              Confidence: <strong>{percent(traffic.confidence)}</strong> &middot; <EvidenceTag status="INFERRED" />
            </p>
            {traffic.low_confidence ? (
              <p className="note note-warning">
                This prediction is below the confidence threshold ({percent(traffic.confidence_threshold)}) and
                should be treated as weak.
              </p>
            ) : null}
            <Fields>
              <Field label="Model ID" value={traffic.model_id} />
              <Field label="Model version" value={traffic.model_version} />
              <Field label="Feature schema" value={traffic.feature_schema} />
              <Field label="Confidence threshold" value={percent(traffic.confidence_threshold)} />
            </Fields>
            <p className="note">
              <strong>Inferred</strong>, not observed. Encryption hides the payload; it does not hide the shape
              or the timing of the traffic carrying it.
            </p>
          </Card>

          <Card title="Class probabilities">
            {entries.length === 0 ? (
              <p className="muted">The model returned no probability table.</p>
            ) : (
              <ul className="bars">
                {entries.map(([name, value]) => (
                  <li key={name}>
                    <span className="bar-label">{name}</span>
                    <span className="bar-track">
                      <span
                        className={name === predicted ? 'bar-fill predicted' : 'bar-fill'}
                        style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }}
                      />
                    </span>
                    <span className="bar-value">{value.toFixed(2)}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}

      {bundle.components.traffic && !predicted ? <UnavailableNote bundle={bundle} stage="traffic" /> : null}
    </div>
  )
}
