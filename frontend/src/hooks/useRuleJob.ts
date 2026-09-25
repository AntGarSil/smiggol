import { useEffect, useRef, useState } from 'react'
import { cancelJob, getJob, streamUrl, submitJob } from '../api/client'
import type { GenerationRequest, JobSnapshot } from '../api/types'

const terminal = new Set(['succeeded', 'failed', 'cancelled'])

export function useRuleJob() {
  const [snapshot, setSnapshot] = useState<JobSnapshot | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [transport, setTransport] = useState<'sse' | 'polling' | null>(null)
  const sourceRef = useRef<EventSource | null>(null)
  const pollRef = useRef<number | null>(null)

  function stopUpdates() {
    sourceRef.current?.close()
    sourceRef.current = null
    if (pollRef.current !== null) window.clearInterval(pollRef.current)
    pollRef.current = null
  }

  function merge(next: JobSnapshot) {
    setSnapshot((current) => {
      if (!current) return next
      return {
        ...next,
        stages_done: [...new Set([...current.stages_done, ...next.stages_done])],
        warnings: [...new Set([...current.warnings, ...next.warnings])],
      }
    })
    if (terminal.has(next.status)) stopUpdates()
  }

  function startPolling(jobId: string) {
    stopUpdates()
    setTransport('polling')
    const refresh = () => getJob(jobId).then(merge).catch((reason: Error) => setError(reason.message))
    void refresh()
    pollRef.current = window.setInterval(refresh, 1500)
  }

  function startStream(jobId: string) {
    stopUpdates()
    setTransport('sse')
    const source = new EventSource(streamUrl(jobId))
    sourceRef.current = source
    const receive = (event: MessageEvent<string>) => merge(JSON.parse(event.data) as JobSnapshot)
    source.addEventListener('snapshot', receive as EventListener)
    source.addEventListener('terminal', receive as EventListener)
    source.onerror = () => {
      source.close()
      startPolling(jobId)
    }
  }

  async function submit(payload: GenerationRequest) {
    stopUpdates()
    setError(null)
    setSnapshot(null)
    try {
      const accepted = await submitJob(payload)
      merge({ job_id: accepted.job_id, status: 'queued', stages_done: [], warnings: [] })
      startStream(accepted.job_id)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to submit job')
    }
  }

  async function cancel() {
    if (!snapshot) return
    try {
      merge(await cancelJob(snapshot.job_id))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to cancel job')
    }
  }

  useEffect(() => stopUpdates, [])

  return { snapshot, error, transport, submit, cancel }
}