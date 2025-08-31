import { useState } from 'react'
import { BookOpen, Search, ChevronRight, ExternalLink, Code, Database, Shield, Rocket, FileText, Video, Book, HelpCircle } from 'lucide-react'
import AppLayout from '../components/AppLayout'

interface DocSection {
  id: string
  title: string
  description: string
  icon: any
  articles: DocArticle[]
}

interface DocArticle {
  id: string
  title: string
  description: string
  type: 'guide' | 'api' | 'example' | 'video'
  readTime: string
  difficulty: 'beginner' | 'intermediate' | 'advanced'
}

export default function DocumentationPage() {
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedSection, setExpandedSection] = useState<string | null>('getting-started')

  // Mock data - in real app this would come from API
  const docSections: DocSection[] = [
    {
      id: 'getting-started',
      title: 'Getting Started',
      description: 'Learn the basics of Backend V0',
      icon: BookOpen,
      articles: [
        {
          id: 'gs-1',
          title: 'Quick Start Guide',
          description: 'Get up and running with your first backend in 5 minutes',
          type: 'guide',
          readTime: '5 min',
          difficulty: 'beginner'
        },
        {
          id: 'gs-2',
          title: 'Understanding Backend Specs',
          description: 'Learn how to read and modify generated specifications',
          type: 'guide',
          readTime: '10 min',
          difficulty: 'beginner'
        }
      ]
    },
    {
      id: 'nodejs',
      title: 'Node.js Backends',
      description: 'Express, Prisma, and PostgreSQL',
      icon: Code,
      articles: [
        {
          id: 'node-1',
          title: 'Express.js Best Practices',
          description: 'Learn how to structure and organize your Express applications',
          type: 'guide',
          readTime: '15 min',
          difficulty: 'intermediate'
        },
        {
          id: 'node-2',
          title: 'Prisma Database Operations',
          description: 'Complete guide to database operations with Prisma ORM',
          type: 'guide',
          readTime: '20 min',
          difficulty: 'intermediate'
        }
      ]
    },
    {
      id: 'python',
      title: 'Python Backends',
      description: 'FastAPI, SQLModel, and PostgreSQL',
      icon: Code,
      articles: [
        {
          id: 'py-1',
          title: 'FastAPI Fundamentals',
          description: 'Build high-performance APIs with FastAPI',
          type: 'guide',
          readTime: '12 min',
          difficulty: 'intermediate'
        },
        {
          id: 'py-2',
          title: 'SQLModel Integration',
          description: 'Using SQLModel for database models and validation',
          type: 'guide',
          readTime: '18 min',
          difficulty: 'intermediate'
        }
      ]
    },
    {
      id: 'deployment',
      title: 'Deployment',
      description: 'Deploy your backends to production',
      icon: Rocket,
      articles: [
        {
          id: 'dep-1',
          title: 'Docker Deployment',
          description: 'Containerize and deploy with Docker',
          type: 'guide',
          readTime: '8 min',
          difficulty: 'intermediate'
        },
        {
          id: 'dep-2',
          title: 'CI/CD with GitHub Actions',
          description: 'Automate your deployment pipeline',
          type: 'guide',
          readTime: '12 min',
          difficulty: 'advanced'
        }
      ]
    },
    {
      id: 'security',
      title: 'Security',
      description: 'Secure your backends',
      icon: Shield,
      articles: [
        {
          id: 'sec-1',
          title: 'JWT Authentication',
          description: 'Implement secure JWT-based authentication',
          type: 'guide',
          readTime: '15 min',
          difficulty: 'intermediate'
        },
        {
          id: 'sec-2',
          title: 'Input Validation',
          description: 'Validate and sanitize user inputs',
          type: 'guide',
          readTime: '10 min',
          difficulty: 'beginner'
        }
      ]
    }
  ]

  const filteredSections = docSections.map(section => ({
    ...section,
    articles: section.articles.filter(article =>
      article.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      article.description.toLowerCase().includes(searchTerm.toLowerCase())
    )
  })).filter(section => section.articles.length > 0 || searchTerm === '')

  const getArticleIcon = (type: string) => {
    switch (type) {
      case 'guide': return <Book className="w-4 h-4" />
      case 'api': return <Code className="w-4 h-4" />
      case 'example': return <FileText className="w-4 h-4" />
      case 'video': return <Video className="w-4 h-4" />
      default: return <Book className="w-4 h-4" />
    }
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'bg-green-100 text-green-800'
      case 'intermediate': return 'bg-yellow-100 text-yellow-800'
      case 'advanced': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  return (
    <AppLayout
      title="Documentation"
      subtitle="Learn how to use Backend V0 and build production-ready backends"
    >
      {/* Search */}
      <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm mb-8">
        <div className="relative max-w-2xl">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search documentation..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent text-lg"
          />
        </div>
      </div>

      {/* Documentation Sections */}
      <div className="space-y-6">
        {filteredSections.map((section) => {
          const Icon = section.icon
          const isExpanded = expandedSection === section.id
          
          return (
            <div key={section.id} className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
              {/* Section Header */}
              <button
                onClick={() => setExpandedSection(isExpanded ? null : section.id)}
                className="w-full p-6 text-left hover:bg-gray-50 transition-colors duration-200"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="w-12 h-12 bg-gradient-to-br from-purple-100 to-pink-100 rounded-xl flex items-center justify-center">
                      <Icon className="w-6 h-6 text-purple-600" />
                    </div>
                    <div>
                      <h2 className="text-xl font-semibold text-gray-900">{section.title}</h2>
                      <p className="text-gray-600">{section.description}</p>
                    </div>
                  </div>
                  <ChevronRight 
                    className={`w-5 h-5 text-gray-400 transition-transform duration-200 ${
                      isExpanded ? 'rotate-90' : ''
                    }`} 
                  />
                </div>
              </button>

              {/* Section Content */}
              {isExpanded && (
                <div className="border-t border-gray-100 bg-gray-50">
                  <div className="p-6">
                    <div className="grid md:grid-cols-2 gap-4">
                      {section.articles.map((article) => (
                        <div key={article.id} className="bg-white rounded-xl p-4 border border-gray-200 hover:border-purple-300 transition-colors duration-200">
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center space-x-2 text-purple-600">
                              {getArticleIcon(article.type)}
                              <span className="text-xs font-medium uppercase tracking-wider">
                                {article.type}
                              </span>
                            </div>
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getDifficultyColor(article.difficulty)}`}>
                              {article.difficulty}
                            </span>
                          </div>
                          
                          <h3 className="font-semibold text-gray-900 mb-2">{article.title}</h3>
                          <p className="text-gray-600 text-sm mb-3 leading-relaxed">{article.description}</p>
                          
                          <div className="flex items-center justify-between">
                            <span className="text-xs text-gray-500">{article.readTime} read</span>
                            <button className="flex items-center space-x-1 text-purple-600 hover:text-purple-700 text-sm font-medium transition-colors duration-200">
                              <span>Read</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Help Section */}
      <div className="mt-12 bg-gradient-to-r from-purple-50 to-pink-50 rounded-2xl p-8 border border-purple-200">
        <div className="text-center">
          <HelpCircle className="w-16 h-16 text-purple-600 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Need Help?</h2>
          <p className="text-gray-600 mb-6 max-w-2xl mx-auto">
            Can't find what you're looking for? Our team is here to help you build amazing backends.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <button className="px-6 py-3 bg-purple-600 text-white rounded-xl font-medium hover:bg-purple-700 transition-colors duration-200">
              Contact Support
            </button>
            <button className="px-6 py-3 bg-white text-purple-700 rounded-xl font-medium border border-purple-200 hover:bg-purple-50 transition-colors duration-200">
              Join Community
            </button>
          </div>
        </div>
      </div>
    </AppLayout>
  )
}
