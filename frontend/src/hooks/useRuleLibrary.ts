import { useCallback, useState } from 'react'
import type { GenerationRequest, GenerationResult } from '../api/types'

const STORAGE_KEY = 'smiggol_rule_library_v1'

export interface LibraryEntry {
  cveId: string
  params: GenerationRequest
  result: GenerationResult
  jobId: string
  savedAt: string
}

function loadFromStorage(): LibraryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as LibraryEntry[]) : []
  } catch {
    return []
  }
}

export function useRuleLibrary() {
  const [entries, setEntries] = useState<LibraryEntry[]>(loadFromStorage)

  const upsert = useCallback((entry: LibraryEntry) => {
    setEntries(prev => {
      const next = [entry, ...prev.filter(e => e.cveId !== entry.cveId)]
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(next)) } catch { /* storage quota exceeded */ }
      return next
    })
  }, [])

  const remove = useCallback((cveId: string) => {
    setEntries(prev => {
      const next = prev.filter(e => e.cveId !== cveId)
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(next)) } catch { /* storage quota exceeded */ }
      return next
    })
  }, [])

  return { entries, upsert, remove }
}
