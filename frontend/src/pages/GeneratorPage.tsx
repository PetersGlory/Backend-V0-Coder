import { useState } from 'react'
import { useBackendSpec } from '../contexts/BackendSpecContext'
import PromptInput from '../components/PromptInput'
import SpecDisplay from '../components/SpecDisplay'
import ScaffoldButton from '../components/ScaffoldButton'
import { Loader2, CheckCircle, AlertCircle, Sparkles, Clock, FolderOpen, MessageSquare, Settings, Zap, History, BookOpen, Code } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'
import AppLayout from '../components/AppLayout'

export default function GeneratorPage() {
  const { spec, isLoading, error } = useBackendSpec()
  const [isScaffolding, setIsScaffolding] = useState(false)
  const [scaffoldResult, setScaffoldResult] = useState<{
    success: boolean
    message: string
    localPath?: string
  } | null>(null)
  const location = useLocation()

  const examplePrompts = [
    "Build a REST API for a task management app with user authentication, projects, and tasks. Use Express, Prisma, and PostgreSQL.",
    "Create a FastAPI backend for an e-commerce platform with products, orders, users, and payment processing. Use SQLModel and PostgreSQL.",
    "Generate a Node.js backend for a social media app with user profiles, posts, comments, and real-time notifications.",
    "Build a Python backend for a booking system with rooms, reservations, and payment integration. Use FastAPI and PostgreSQL."
  ]

  return (
    <AppLayout
      title="Welcome back to Backend V0"
      subtitle="Ready to generate your next backend?"
    >
      <div className="space-y-6">
        {/* Prompt Input */}
        <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm">
          <PromptInput />
        </div>

        {/* Loading State */}
        {isLoading && (
          <div className="bg-white rounded-2xl p-8 border border-gray-200 shadow-sm">
            <div className="text-center">
              <div className="w-16 h-16 bg-gradient-to-r from-purple-100 to-pink-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Loader2 className="w-8 h-8 animate-spin text-purple-600" />
              </div>
              <p className="text-gray-600 text-lg font-medium">AI is generating your backend specification...</p>
              <p className="text-gray-500 text-sm mt-2">This usually takes 10-30 seconds</p>
            </div>
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="bg-red-50 rounded-2xl p-6 border border-red-200">
            <div className="flex items-center space-x-3">
              <AlertCircle className="w-6 h-6 text-red-500" />
              <div>
                <h3 className="font-medium text-red-800 text-lg">Generation Failed</h3>
                <p className="text-red-700">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Generated Specification */}
        {spec && (
          <div className="space-y-6">
            <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
              <SpecDisplay spec={spec} />
            </div>
            
            {/* Scaffold Actions */}
            <div className="bg-white rounded-2xl p-8 border border-gray-200 shadow-sm">
              <div className="text-center mb-6">
                <h3 className="text-2xl font-bold text-gray-900 mb-2">
                  Ready to Scaffold?
                </h3>
                <p className="text-gray-600 text-lg">
                  Generate the complete project files and start building your backend.
                </p>
              </div>
              
              {scaffoldResult ? (
                <div className={`p-6 rounded-xl ${
                  scaffoldResult.success 
                    ? 'bg-green-50 border border-green-200' 
                    : 'bg-red-50 border border-red-200'
                }`}>
                  <div className="flex items-center space-x-3">
                    {scaffoldResult.success ? (
                      <CheckCircle className="w-6 h-6 text-green-500" />
                    ) : (
                      <AlertCircle className="w-6 h-6 text-red-500" />
                    )}
                    <div>
                      <p className={`font-medium text-lg ${
                        scaffoldResult.success ? 'text-green-800' : 'text-red-800'
                      }`}>
                        {scaffoldResult.message}
                      </p>
                      {scaffoldResult.localPath && (
                        <p className="text-green-700 text-sm mt-1">
                          Project generated at: {scaffoldResult.localPath}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <ScaffoldButton
                  spec={spec}
                  onScaffoldStart={() => setIsScaffolding(true)}
                  onScaffoldComplete={(result) => {
                    setIsScaffolding(false)
                    setScaffoldResult(result)
                  }}
                  isScaffolding={isScaffolding}
                />
              )}
            </div>
          </div>
        )}

        {/* Welcome Message */}
        {!spec && !isLoading && !error && (
          <div className="bg-white rounded-2xl p-12 border border-gray-200 shadow-sm text-center">
            <div className="w-20 h-20 bg-gradient-to-br from-purple-100 to-pink-100 rounded-3xl flex items-center justify-center mx-auto mb-6 shadow-lg">
              <Sparkles className="w-10 h-10 text-purple-600" />
            </div>
            <h3 className="text-2xl font-bold text-gray-900 mb-3">
              Start Building Your Backend
            </h3>
            <p className="text-gray-600 mb-8 max-w-lg mx-auto text-lg leading-relaxed">
              Describe your backend requirements in natural language and let AI generate a complete specification with all the code you need.
            </p>
            <div className="flex flex-wrap gap-3 justify-center">
              {examplePrompts.slice(0, 2).map((prompt, index) => (
                <button
                  key={index}
                  onClick={() => {
                    const textarea = document.getElementById('prompt') as HTMLTextAreaElement
                    if (textarea) {
                      textarea.value = prompt
                      textarea.dispatchEvent(new Event('input', { bubbles: true }))
                    }
                  }}
                  className="px-6 py-3 bg-purple-50 hover:bg-purple-100 text-purple-700 hover:text-purple-800 rounded-xl text-sm font-medium transition-all duration-200 border border-purple-200 hover:border-purple-300 hover:shadow-md"
                >
                  {prompt.split(' ').slice(0, 4).join(' ')}...
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  )
}
