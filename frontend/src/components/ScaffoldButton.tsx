import { useState } from 'react'
import { Download, FolderOpen, Loader2, CheckCircle, ArrowRight } from 'lucide-react'
import { BackendSpec } from '../contexts/BackendSpecContext'

interface ScaffoldButtonProps {
  spec: BackendSpec
  onScaffoldStart: () => void
  onScaffoldComplete: (result: { success: boolean; message: string; localPath?: string }) => void
  isScaffolding: boolean
}

export default function ScaffoldButton({
  spec,
  onScaffoldStart,
  onScaffoldComplete,
  isScaffolding,
}: ScaffoldButtonProps) {
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null)

  const handleScaffold = async () => {
    onScaffoldStart()

    try {
      const response = await fetch('https://v0-coder.onrender.com/api/scaffold', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ spec }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Failed to scaffold project')
      }

      // Check if response is a zip file
      const contentType = response.headers.get('content-type')
      if (contentType && contentType.includes('application/zip')) {
        // Create blob and download
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        
        // Get filename from Content-Disposition header
        const contentDisposition = response.headers.get('content-disposition')
        let filename = `${getProjectName()}.zip`
        if (contentDisposition) {
          const filenameMatch = contentDisposition.match(/filename="(.+)"/)
          if (filenameMatch) {
            filename = filenameMatch[1]
          }
        }
        
        // Create download link and trigger download
        const link = document.createElement('a')
        link.href = url
        link.download = filename
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        window.URL.revokeObjectURL(url)
        
        onScaffoldComplete({
          success: true,
          message: 'Project downloaded successfully!',
        })
      } else {
        throw new Error('Invalid response format from server')
      }
    } catch (error) {
      onScaffoldComplete({
        success: false,
        message: error instanceof Error ? error.message : 'An unexpected error occurred',
      })
    }
  }

  const getProjectName = () => {
    return spec.name || `backend-${spec.stack.language}-${Date.now()}`
  }

  return (
    <div className="space-y-8">
      {/* Main Action */}
      <div className="text-center">
        <button
          onClick={handleScaffold}
          disabled={isScaffolding}
          className="group relative inline-flex items-center justify-center space-x-3 px-8 py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 disabled:from-gray-400 disabled:to-gray-500 text-white font-semibold text-lg rounded-2xl transition-all duration-300 transform hover:scale-105 hover:shadow-2xl hover:shadow-purple-500/25 disabled:cursor-not-allowed disabled:transform-none shadow-lg"
        >
          {isScaffolding ? (
            <>
              <Loader2 className="w-6 h-6 animate-spin" />
              <span>Generating Project...</span>
            </>
          ) : (
            <>
              <FolderOpen className="w-6 h-6" />
              <span>Generate Project Files</span>
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform duration-300" />
            </>
          )}
        </button>
      </div>

      {/* What You'll Get */}
      <div className="bg-gradient-to-r from-gray-50 to-white rounded-2xl p-6 border border-gray-200">
        <h4 className="text-lg font-semibold text-gray-900 mb-4 flex items-center space-x-2">
          <CheckCircle className="w-5 h-5 text-green-600" />
          <span>What You'll Get</span>
        </h4>
        <div className="grid md:grid-cols-2 gap-4">
          <div className="space-y-3">
            <div className="flex items-center space-x-3 text-sm text-gray-700">
              <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
              <span>Complete project structure</span>
            </div>
            <div className="flex items-center space-x-3 text-sm text-gray-700">
              <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
              <span>Package configuration</span>
            </div>
            <div className="flex items-center space-x-3 text-sm text-gray-700">
              <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
              <span>Database schema & migrations</span>
            </div>
            <div className="flex items-center space-x-3 text-sm text-gray-700">
              <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
              <span>API routes & controllers</span>
            </div>
          </div>
          <div className="space-y-3">
            <div className="flex items-center space-x-3 text-sm text-gray-700">
              <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
              <span>Authentication middleware</span>
            </div>
            <div className="flex items-center space-x-3 text-sm text-gray-700">
              <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
              <span>Docker configuration</span>
            </div>
            <div className="flex items-center space-x-3 text-sm text-gray-700">
              <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
              <span>CI/CD pipeline setup</span>
            </div>
            <div className="flex items-center space-x-3 text-sm text-gray-700">
              <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
              <span>Environment configuration</span>
            </div>
          </div>
        </div>
      </div>

      {/* Next Steps */}
      <div className="bg-gradient-to-r from-blue-50 to-cyan-50 rounded-2xl p-6 border border-blue-200">
        <h4 className="text-lg font-semibold text-blue-900 mb-4 flex items-center space-x-2">
          <ArrowRight className="w-5 h-5 text-blue-600" />
          <span>Next Steps After Scaffolding</span>
        </h4>
        <div className="space-y-3">
          <div className="flex items-start space-x-3 text-sm text-blue-800">
            <span className="w-6 h-6 bg-blue-200 text-blue-800 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">1</span>
            <span>Navigate to the generated project directory</span>
          </div>
          <div className="flex items-start space-x-3 text-sm text-blue-800">
            <span className="w-6 h-6 bg-blue-200 text-blue-800 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">2</span>
            <span>Install dependencies with <code className="bg-blue-200 px-2 py-1 rounded text-blue-800 font-mono">npm install</code> or <code className="bg-blue-200 px-2 py-1 rounded text-blue-800 font-mono">pip install -r requirements.txt</code></span>
          </div>
          <div className="flex items-start space-x-3 text-sm text-blue-800">
            <span className="w-6 h-6 bg-blue-200 text-blue-800 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">3</span>
            <span>Set up your database and environment variables</span>
          </div>
          <div className="flex items-start space-x-3 text-sm text-blue-800">
            <span className="w-6 h-6 bg-blue-200 text-blue-800 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">4</span>
            <span>Run the development server</span>
          </div>
          <div className="flex items-start space-x-3 text-sm text-blue-800">
            <span className="w-6 h-6 bg-blue-200 text-blue-800 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">5</span>
            <span>Customize and extend as needed</span>
          </div>
        </div>
      </div>

      {/* Download Section (if available) */}
      {downloadUrl && (
        <div className="text-center">
          <a
            href={downloadUrl}
            download={`${getProjectName()}.zip`}
            className="inline-flex items-center space-x-3 px-6 py-3 bg-gray-100 hover:bg-gray-200 text-gray-700 hover:text-gray-900 font-medium rounded-xl border border-gray-300 hover:border-gray-400 transition-all duration-300 hover:shadow-md"
          >
            <Download className="w-5 h-5" />
            <span>Download ZIP</span>
          </a>
        </div>
      )}
    </div>
  )
}
