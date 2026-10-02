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
  // The decision is read from the backend, never recomputed here from the
  // confidence value: a UI threshold here would silently disagree with the
  // model's own policy the first time either changed.
  const rejected = Boolean(traffic.rejected)
  const decision = (traffic.decision as string | undefined) ?? (rejected ? 'UNKNOWN' : 'KNOWN')
  const closest = traffic.closest_known_class as string | undefined
  const reason = traffic.rejection_reason as string | undefined
  const calibrated = Boolean(traffic.calibrated)
  const isUnavailable = !predicted

  return (
    <div className="view">
      <h2>Traffic intelligence</h2>

      {isUnavailable ? (
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
          <Card
            title="Prediction"
            subtitle={
              rejected
                ? 'No known class had sufficient support'
                : 'Derived from packet size and timing statistics'
            }
          >
            {rejected ? (
              <>
                <p className="prediction">
                  <strong>UNKNOWN</strong>
                </p>
                <p className="muted">
                  FERA did not find sufficient support for any traffic class known to the current model.
                  This is not a warning and not an anomaly.
                </p>
                {closest ? (
                  <p className="muted">
                    Closest known class: <strong>{show(closest)}</strong>
                    {reason ? <> &middot; reason: {show(reason)}</> : null}
                  </p>
                ) : null}
              </>
            ) : (
              <p className="prediction">
                <strong>{show(predicted)}</strong>
              </p>
            )}
            <p>
              {rejected ? 'Closest-class probability' : 'Confidence'}:{' '}
              <strong>{percent(traffic.confidence)}</strong> &middot;{' '}
              <EvidenceTag status="INFERRED" />
            </p>
            <p className="muted">
              Confidence calibration:{' '}
              <strong>{calibrated ? 'CALIBRATED' : 'UNCALIBRATED'}</strong>
              {calibrated ? '' : ' — these probabilities have not been calibrated against held-out data'}
            </p>
            {traffic.low_confidence ? (
              <p className="note note-warning">
                This prediction is below the confidence threshold ({percent(traffic.confidence_threshold)}) and
                should be treated as weak.
              </p>
            ) : null}
            <Fields>
              <Field label="Decision" value={decision} />
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
                        className={name === (rejected ? closest : predicted) ? 'bar-fill predicted' : 'bar-fill'}
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

      {bundle.components.traffic && isUnavailable ? (
        <UnavailableNote bundle={bundle} stage="traffic" />
      ) : null}
    </div>
  )
}
