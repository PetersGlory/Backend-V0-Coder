import { useState } from 'react'
import { useBackendSpec } from '../contexts/BackendSpecContext'
import { Send, Sparkles, Lightbulb } from 'lucide-react'

export default function PromptInput() {
  const [prompt, setPrompt] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const { setSpec, setIsLoading, setError } = useBackendSpec()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!prompt.trim() || isSubmitting) return

    setIsSubmitting(true)
    setIsLoading(true)
    setError(null)
    setSpec(null)

    try {
      const response = await fetch('https://v0-coder.onrender.com/api/spec', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ prompt: prompt.trim() }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Failed to generate specification')
      }

      if (data.success && data.spec) {
        setSpec(data.spec)
      } else {
        throw new Error('Invalid response from server')
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'An unexpected error occurred')
    } finally {
      setIsSubmitting(false)
      setIsLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-3 mb-4">
        <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl flex items-center justify-center shadow-md">
          <Sparkles className="w-5 h-5 text-white" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-gray-900">Describe Your Backend</h2>
          <p className="text-sm text-gray-600">Be as detailed as possible for better results</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="relative">
          <textarea
            id="prompt"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            placeholder="Describe your backend requirements in natural language... For example: 'Build a REST API for a task management app with user authentication, projects, and tasks. Use Express, Prisma, and PostgreSQL.'"
            className="w-full px-6 py-5 min-h-[160px] resize-none bg-white border-2 border-gray-200 rounded-2xl text-gray-900 placeholder-gray-500 focus:outline-none focus:ring-4 focus:ring-purple-100 focus:border-purple-500 transition-all duration-300 shadow-sm text-base leading-relaxed"
            disabled={isSubmitting}
          />
          
          {/* Character count */}
          <div className="absolute bottom-4 left-4 text-xs text-gray-400">
            {prompt.length} characters
          </div>

          {/* Submit button */}
          <button
            type="submit"
            disabled={!prompt.trim() || isSubmitting}
            className="absolute bottom-4 right-4 p-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 disabled:from-gray-400 disabled:to-gray-500 text-white rounded-xl transition-all duration-300 disabled:cursor-not-allowed transform hover:scale-105 hover:shadow-lg hover:shadow-purple-500/25 disabled:transform-none"
          >
            {isSubmitting ? (
              <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
            ) : (
              <Send className="w-5 h-5" />
            )}
          </button>
        </div>
      </form>

      {/* Tips */}
      <div className="bg-gradient-to-r from-purple-50 to-pink-50 rounded-xl p-4 border border-purple-200">
        <div className="flex items-start space-x-3">
          <Lightbulb className="w-5 h-5 text-purple-600 mt-0.5 flex-shrink-0" />
          <div className="text-sm text-purple-800">
            <p className="font-medium mb-1">💡 Pro Tips:</p>
            <ul className="space-y-1 text-purple-700">
              <li>• Mention the tech stack you prefer (Node.js, Python, etc.)</li>
              <li>• Include authentication requirements (JWT, OAuth, etc.)</li>
              <li>• Specify database needs (PostgreSQL, MongoDB, etc.)</li>
              <li>• Describe the main entities and their relationships</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
