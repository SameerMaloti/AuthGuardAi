export type BackendReputation = 'unknown' | 'safe' | 'suspicious' | 'malicious';
export type BackendRiskLevel = 'low' | 'medium' | 'high';
export type BackendDecision = 'allow' | 'verify' | 'block';

export interface BackendRiskAssessment {
  risk_score: number;
  risk_level: BackendRiskLevel;
  decision: BackendDecision;
  reasons: string[];
  recommended_action: string;
  analysis_mode: string;
  event_id: number;
  created_at: string;
}

export interface BackendRiskEvent {
  event_id: number;
  hostname: string;
  risk_score: number;
  risk_level: BackendRiskLevel;
  decision: BackendDecision;
  reasons: string[];
  created_at: string;
}

export interface BackendRiskEventsResponse {
  items: BackendRiskEvent[];
  limit: number;
  offset: number;
}

export interface BackendDashboardSummary {
  total_events: number;
  high_risk_events: number;
  medium_risk_events: number;
  low_risk_events: number;
  blocked_events: number;
}

const API_ORIGIN = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');
const API_ROOT = `${API_ORIGIN}/api/v1`;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_ROOT}${path}`, {
      ...init,
      headers: {
        ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
        ...init?.headers,
      },
    });
  } catch {
    throw new Error(
      'Could not reach the AuthGuard backend. Start the API server and try again.'
    );
  }

  if (!response.ok) {
    let detail = `Backend request failed (${response.status}).`;
    try {
      const payload = await response.json();
      if (typeof payload.detail === 'string') detail = payload.detail;
      else if (Array.isArray(payload.detail)) {
        detail = payload.detail.map((item: { msg?: string }) => item.msg).filter(Boolean).join(' ');
      }
    } catch {
      // Keep the status-based message when the response has no JSON body.
    }
    throw new Error(detail);
  }

  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export function checkBackendHealth() {
  return request<{ status: string; service: string }>('/health');
}

export function analyzeWebsiteRisk(input: {
  hostname: string;
  otp_field_detected: boolean;
  redirect_count: number;
  reputation: BackendReputation;
}) {
  return request<BackendRiskAssessment>('/risk/analyze', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function getRiskEvents(limit = 100) {
  return request<BackendRiskEventsResponse>(`/risk/events?limit=${limit}`);
}

export function getDashboardSummary() {
  return request<BackendDashboardSummary>('/dashboard/summary');
}

export function clearRiskEvents() {
  return request<void>('/risk/events', { method: 'DELETE' });
}
