/**
 * Thin client for the local FERA API.
 *
 * Two rules this file enforces:
 *
 * 1. **No invented data.** A failed request throws an `ApiError` carrying the
 *    backend's own code, message and hint. Callers render that; they never
 *    substitute a placeholder value.
 * 2. **No protocol knowledge.** The dashboard does not parse, score or infer.
 *    It reads `components.<name>.data` and displays it.
 */
import type {
  AnalysisBundle,
  ApiErrorBody,
  Capabilities,
  HistoryRow,
  ModelStatus,
} from './types'

/** Base path; `vite.config.ts` proxies /api to the local FastAPI process. */
const BASE = '/api'

/** A structured failure from the API, or a transport failure. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly hint: string | null

  constructor(status: number, code: string, message: string, hint: string | null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.hint = hint
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${BASE}${path}`, init)
  } catch (cause) {
    throw new ApiError(0, 'NETWORK_ERROR', `could not reach the FERA API: ${String(cause)}`, 'is it running? python -m fera.api.main')
  }
  if (!response.ok) {
    let code = `HTTP_${response.status}`
    let message = response.statusText
    let hint: string | null = null
    try {
      const body = (await response.json()) as ApiErrorBody
      if (body?.error) {
        code = body.error.code
        message = body.error.message
        hint = body.error.hint
      }
    } catch {
      // A non-JSON error body is still an error; keep the status-derived text.
    }
    throw new ApiError(response.status, code, message, hint)
  }
  return (await response.json()) as T
}

export const api = {
  health: () => request<{ status: string }>('/health'),

  version: () => request<Record<string, string>>('/version'),

  capabilities: () => request<Capabilities>('/capabilities'),

  modelStatus: () => request<ModelStatus>('/models/status'),

  listAnalyses: (params: { limit?: number; source_mode?: string; risk_band?: string; traffic_class?: string } = {}) => {
    const query = new URLSearchParams()
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== '') query.set(key, String(value))
    }
    const suffix = query.toString()
    return request<{ count: number; analyses: HistoryRow[] }>(`/analyses${suffix ? `?${suffix}` : ''}`)
  },

  getAnalysis: (id: string) => request<AnalysisBundle>(`/analyses/${encodeURIComponent(id)}`),

  deleteAnalysis: (id: string) => request<{ deleted: string }>(`/analyses/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  reportUrl: (id: string, type: string, format = 'html') =>
    `${BASE}/analyses/${encodeURIComponent(id)}/report?type=${encodeURIComponent(type)}&format=${encodeURIComponent(format)}`,

  exportUrl: (id: string) => `${BASE}/analyses/${encodeURIComponent(id)}/export`,

  /**
   * Upload a capture for analysis.
   *
   * Progress is reported as a *state*, not a percentage: `fetch` cannot observe
   * how many bytes have been sent, and the API does not expose stage progress
   * either. Inventing a percentage would be a claim the product cannot support,
   * so the UI shows "UPLOADING" and then "ANALYZING".
   */
  analyze(file: File): Promise<AnalysisBundle> {
    const form = new FormData()
    form.append('file', file)
    return request<AnalysisBundle>('/analyze', { method: 'POST', body: form })
  },

  /**
   * Record a bounded live capture and analyse it.
   *
   * Sent as JSON because the parameters are structured; the endpoint validates
   * them and reports a missing capture tool as a 503 rather than faking traffic.
   */
  analyzeLive(body: { interface: string; duration_s: number; capture_filter?: string | null }): Promise<AnalysisBundle> {
    return request<AnalysisBundle>('/live/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  },
}
