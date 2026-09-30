/**
 * The canonical analysis bundle, as the API serves it.
 *
 * These types mirror `fera.core.bundle`. They exist so the dashboard reads the
 * backend's own vocabulary instead of inventing its own: a component is either
 * present with data or absent, and a stage that did not run says so.
 */

export type StageStatus = 'ok' | 'partial' | 'unavailable' | 'failed' | 'skipped'

export type OverallStatus = 'complete' | 'partial' | 'failed'

/** Provenance of a single conclusion. */
export type EvidenceStatus = 'OBSERVED' | 'CONFIGURED' | 'INFERRED' | 'NOT_VERIFIABLE'

export type FindingStatus = 'PASS' | 'FAIL' | 'WARNING' | 'NOT_VERIFIABLE' | 'NOT_APPLICABLE'

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface StageError {
  code: string
  message: string
  hint: string | null
  details: Record<string, unknown>
}

/** One stage of the pipeline: its status, its payload, and why if it failed. */
export interface Component {
  component: string
  status: StageStatus
  available: boolean
  data: Record<string, unknown> | null
  error: StageError | null
  duration_ms: number
  limitations: string[]
}

export interface AnalysisBundle {
  schema_version: string
  analysis_id: string
  created_at: string
  status: OverallStatus
  source: {
    kind: string
    filename: string
    path?: string
    size_bytes: number
    sha256: string | null
    captured_at: string | null
  }
  components: Record<string, Component>
  limitations: string[]
  provenance: Record<string, unknown>
  live_capture?: Record<string, unknown>
}

export interface HistoryRow {
  analysis_id: string
  created_at: string
  source_mode: string
  display_filename: string
  capture_size: number
  capture_hash: string | null
  bundle_schema: string | null
  protocol_summary: string | null
  traffic_prediction: string | null
  traffic_confidence: number | null
  security_score: number | null
  risk_band: string | null
  privacy_band: string | null
  analysis_state: string | null
}

export interface Capability {
  status: 'available' | 'unavailable'
  reason?: string | null
  formats?: string[]
  bounds?: { default_duration_s: number; max_duration_s: number }
  /** Why PDF export is unavailable. Without this, the index signature makes it `unknown`. */
  pdf_reason?: string | null
  [key: string]: unknown
}

export interface Capabilities {
  schema_version: string
  capabilities: Record<string, Capability>
}

export interface ModelStatus {
  available: boolean
  reason: string | null
  artefacts: unknown[]
  [key: string]: unknown
}

export interface ApiErrorBody {
  error: { code: string; message: string; hint: string | null; details: Record<string, unknown> }
}
