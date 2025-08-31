import { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Sparkles, Clock, History, BookOpen, Code, Settings, Zap, MessageSquare } from 'lucide-react'

interface AppLayoutProps {
  children: ReactNode
  title: string
  subtitle: string
}

export default function AppLayout({ children, title, subtitle }: AppLayoutProps) {
  const location = useLocation()

  const examplePrompts = [
    "Build a REST API for a task management app with user authentication, projects, and tasks. Use Express, Prisma, and PostgreSQL.",
    "Create a FastAPI backend for an e-commerce platform with products, orders, users, and payment processing. Use SQLModel and PostgreSQL.",
    "Generate a Node.js backend for a social media app with user profiles, posts, comments, and real-time notifications.",
    "Build a Python backend for a booking system with rooms, reservations, and payment integration. Use FastAPI and PostgreSQL."
  ]

  const navItems = [
    { path: '/generate', label: 'Generate', icon: MessageSquare },
    { path: '/history', label: 'History', icon: History },
    { path: '/templates', label: 'Templates', icon: BookOpen },
    { path: '/docs', label: 'Documentation', icon: Code },
    { path: '/settings', label: 'Settings', icon: Settings },
  ]

  return (
    <div className="min-h-screen bg-gray-50 flex">
      {/* Left Sidebar - Controls & Navigation */}
      <div className="w-64 bg-white border-r border-gray-200 flex flex-col shadow-sm">
        {/* Header Section */}
        <div className="p-4 border-b border-gray-100 bg-gradient-to-br from-purple-50 to-pink-50">
          <div className="flex items-center space-x-2 mb-2">
            <div className="w-8 h-8 bg-gradient-to-br from-purple-600 to-pink-600 rounded-lg flex items-center justify-center shadow-md">
              <Sparkles className="w-4 h-4 text-white" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-gray-900">Backend V0</h2>
              <p className="text-xs text-gray-600">AI-powered generator</p>
            </div>
          </div>
        </div>

        {/* Navigation Icons */}
        <div className="p-3 border-b border-gray-100">
          <div className="flex flex-col space-y-2">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path
              
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`w-10 h-10 rounded-lg flex items-center justify-center transition-all duration-200 ${
                    isActive
                      ? 'bg-gradient-to-r from-purple-500 to-pink-500 text-white shadow-md'
                      : 'text-gray-400 hover:text-purple-600 hover:bg-purple-50'
                  }`}
                  title={item.label}
                >
                  <Icon className="w-4 h-4" />
                </Link>
              )
            })}
          </div>
        </div>

        {/* Example Prompts Section */}
        <div className="flex-1 p-3 overflow-y-auto">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3 flex items-center space-x-2">
            <Zap className="w-3 h-3" />
            <span>Examples</span>
          </h3>
          <div className="space-y-2">
            {examplePrompts.map((prompt, index) => (
              <button
                key={index}
                onClick={() => {
                  // Navigate to generate page with the prompt
                  window.location.href = `/generate?prompt=${encodeURIComponent(prompt)}`
                }}
                className="w-full text-left p-3 text-xs text-gray-600 hover:text-gray-900 hover:bg-purple-50 rounded-lg border border-gray-200 hover:border-purple-300 transition-all duration-200 bg-white hover:shadow-sm group"
              >
                <div className="flex items-start space-x-2">
                  <Clock className="w-3 h-3 text-purple-400 mt-0.5 flex-shrink-0 group-hover:scale-110 transition-transform duration-200" />
                  <span className="line-clamp-3 leading-relaxed">{prompt}</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* User Profile */}
        <div className="p-3 border-t border-gray-100 bg-gray-50">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center shadow-sm">
              <span className="text-white text-xs font-medium">U</span>
            </div>
            <div>
              <p className="text-xs font-medium text-gray-900">User</p>
              <p className="text-xs text-gray-500">Developer</p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 bg-white flex flex-col">
        {/* Top Header */}
        <div className="p-6 border-b border-gray-100 bg-white shadow-sm">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center shadow-md">
                <span className="text-white text-lg font-medium">U</span>
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">{title}</h1>
                <p className="text-gray-600 text-sm">{subtitle}</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <button className="px-4 py-2 bg-purple-100 text-purple-700 rounded-xl font-medium flex items-center space-x-2 hover:bg-purple-200 transition-colors duration-200 shadow-sm">
                <Sparkles className="w-4 h-4" />
                <span>AI Model</span>
              </button>
            </div>
          </div>
        </div>

        {/* Page Content */}
        <div className="flex-1 p-6 overflow-y-auto bg-gray-50">
          <div className="max-w-4xl mx-auto">
            {children}
          </div>
        </div>
      </div>
    </div>
  )
}
