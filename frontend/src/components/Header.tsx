import { Link, useLocation } from 'react-router-dom'
import { Code, Zap, Sparkles, History, BookOpen, Settings } from 'lucide-react'

export default function Header() {
  const location = useLocation()

  const navItems = [
    { path: '/', label: 'Home', icon: Code },
    { path: '/generate', label: 'Generate', icon: Zap },
    { path: '/history', label: 'History', icon: History },
    { path: '/templates', label: 'Templates', icon: BookOpen },
    { path: '/docs', label: 'Docs', icon: BookOpen },
    { path: '/settings', label: 'Settings', icon: Settings },
  ]

  return (
    <header className="bg-white/95 backdrop-blur-md border-b border-gray-200 sticky top-0 z-50 shadow-sm">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <Link to="/" className="flex items-center space-x-3 group">
            <div className="w-10 h-10 bg-gradient-to-br from-purple-600 to-pink-600 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform duration-300 shadow-lg">
              <Sparkles className="w-6 h-6 text-white" />
            </div>
            <span className="text-xl font-bold bg-gradient-to-r from-purple-600 to-pink-600 bg-clip-text text-transparent">
              Backend V0
            </span>
          </Link>

          <nav className="flex items-center space-x-2">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path
              
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-sm font-medium transition-all duration-300 ${
                    isActive
                      ? 'bg-gradient-to-r from-purple-100 to-pink-100 text-purple-700 border border-purple-200 shadow-sm'
                      : 'text-gray-600 hover:text-purple-700 hover:bg-gray-50 border border-transparent hover:border-purple-200'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </Link>
              )
            })}
          </nav>
        </div>
      </div>
    </header>
  )
}
