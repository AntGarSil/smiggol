import { useEffect, useRef, useState } from 'react'
import { cancelJob, getJob, streamUrl, submitJob } from '../api/client'
import type { GenerationRequest, JobSnapshot } from '../api/types'

const terminal = new Set(['succeeded', 'failed', 'cancelled'])

export interface JobEntry {
  key: number
  params: GenerationRequest
  snapshot: JobSnapshot | null
  error: string | null
  transport: 'sse' | 'polling' | null
}

type Handle = { source: EventSource | null; poll: number | null }

export function useJobQueue() {
  const [jobs, setJobs] = useState<JobEntry[]>([])
  const handles = useRef(new Map<number, Handle>())

  function stopJob(key: number) {
    const h = handles.current.get(key)
    if (!h) return
    h.source?.close()
    if (h.poll !== null) window.clearInterval(h.poll)
    handles.current.delete(key)
  }

  function patchJob(key: number, patch: Partial<JobEntry>) {
    setJobs(prev => prev.map(j => (j.key === key ? { ...j, ...patch } : j)))
  }

  function mergeSnapshot(key: number, next: JobSnapshot) {
    setJobs(prev =>
      prev.map(j => {
        if (j.key !== key) return j
        const snapshot: JobSnapshot = j.snapshot
          ? {
              ...next,
              stages_done: [...new Set([...j.snapshot.stages_done, ...next.stages_done])],
              warnings: [...new Set([...j.snapshot.warnings, ...next.warnings])],
            }
          : next
        return { ...j, snapshot }
      }),
    )
    if (terminal.has(next.status)) stopJob(key)
  }

  function startPolling(key: number, jobId: string) {
    const h = handles.current.get(key) ?? { source: null, poll: null }
    if (h.poll !== null) window.clearInterval(h.poll)
    patchJob(key, { transport: 'polling' })
    const tick = () =>
      getJob(jobId)
        .then(s => mergeSnapshot(key, s))
        .catch((e: Error) => patchJob(key, { error: e.message }))
    void tick()
    h.poll = window.setInterval(tick, 1500)
    handles.current.set(key, h)
  }

  function startStream(key: number, jobId: string) {
    const h = handles.current.get(key) ?? { source: null, poll: null }
    h.source?.close()
    patchJob(key, { transport: 'sse' })
    const source = new EventSource(streamUrl(jobId))
    h.source = source
    handles.current.set(key, h)
    const receive = (ev: MessageEvent<string>) => mergeSnapshot(key, JSON.parse(ev.data) as JobSnapshot)
    source.addEventListener('snapshot', receive as EventListener)
    source.addEventListener('terminal', receive as EventListener)
    source.onerror = () => {
      source.close()
      startPolling(key, jobId)
    }
  }

  async function submit(params: GenerationRequest): Promise<number> {
    const key = Date.now()
    setJobs(prev => [{ key, params, snapshot: null, error: null, transport: null }, ...prev])
    handles.current.set(key, { source: null, poll: null })
    try {
      const accepted = await submitJob(params)
      mergeSnapshot(key, { job_id: accepted.job_id, status: 'queued', stages_done: [], warnings: [] })
      startStream(key, accepted.job_id)
    } catch (e) {
      patchJob(key, { error: e instanceof Error ? e.message : 'Unable to submit job' })
    }
    return key
  }

  async function cancel(key: number) {
    const job = jobs.find(j => j.key === key)
    if (!job?.snapshot) return
    try {
      mergeSnapshot(key, await cancelJob(job.snapshot.job_id))
    } catch (e) {
      patchJob(key, { error: e instanceof Error ? e.message : 'Unable to cancel' })
    }
  }

  function dismiss(key: number) {
    stopJob(key)
    setJobs(prev => prev.filter(j => j.key !== key))
  }

  useEffect(() => () => { for (const key of handles.current.keys()) stopJob(key) }, [])

  return { jobs, submit, cancel, dismiss }
}
