import type { GenerationRequest, JobSnapshot } from './types'

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, '') ?? ''

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init)
  if (!response.ok) {
    const payload = await response.json().catch(() => null)
    throw new Error(payload?.detail?.message ?? payload?.detail ?? `Request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

export async function submitJob(payload: GenerationRequest): Promise<{ job_id: string; status: string }> {
  return request('/v1/rules/generate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getJob(jobId: string): Promise<JobSnapshot> {
  return request(`/v1/jobs/${jobId}`)
}

export function cancelJob(jobId: string): Promise<JobSnapshot> {
  return request(`/v1/jobs/${jobId}`, { method: 'DELETE' })
}

export function streamUrl(jobId: string): string {
  return `${API_BASE}/v1/jobs/${jobId}/stream`
}