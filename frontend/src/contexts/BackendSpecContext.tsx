import React, { createContext, useContext, useState, ReactNode } from 'react'

export interface BackendSpec {
  stack: {
    language: 'node' | 'python'
    framework: string
    database: string
    orm: string
  }
  entities: Array<{
    name: string
    fields: Array<{
      name: string
      type: string
      required: boolean
      unique: boolean
      default?: string
    }>
  }>
  auth: {
    strategy: 'jwt' | 'session' | 'oauth'
    roles?: string[]
  }
  api: Array<{
    resource: string
    operations: ('list' | 'get' | 'create' | 'update' | 'delete')[]
    relations?: string[]
  }>
  env: string[]
  extras?: {
    queue?: string
    cache?: string
    storage?: string
    thirdParty?: string[]
  }
  name?: string
}

interface BackendSpecContextType {
  spec: BackendSpec | null
  setSpec: (spec: BackendSpec | null) => void
  isLoading: boolean
  setIsLoading: (loading: boolean) => void
  error: string | null
  setError: (error: string | null) => void
}

const BackendSpecContext = createContext<BackendSpecContextType | undefined>(undefined)

export function BackendSpecProvider({ children }: { children: ReactNode }) {
  const [spec, setSpec] = useState<BackendSpec | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  return (
    <BackendSpecContext.Provider
      value={{
        spec,
        setSpec,
        isLoading,
        setIsLoading,
        error,
        setError,
      }}
    >
      {children}
    </BackendSpecContext.Provider>
  )
}

export function useBackendSpec() {
  const context = useContext(BackendSpecContext)
  if (context === undefined) {
    throw new Error('useBackendSpec must be used within a BackendSpecProvider')
  }
  return context
}
