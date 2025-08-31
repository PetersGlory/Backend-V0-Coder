import { useState } from 'react'
import { BookOpen, Search, Filter, Star, Download, Eye, Code, Database, Zap } from 'lucide-react'
import AppLayout from '../components/AppLayout'

interface Template {
  id: string
  name: string
  description: string
  category: string
  stack: string
  difficulty: 'beginner' | 'intermediate' | 'advanced'
  rating: number
  downloads: number
  tags: string[]
}

export default function TemplatesPage() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [selectedDifficulty, setSelectedDifficulty] = useState('all')

  const categories = ['all', 'api', 'auth', 'database', 'ecommerce', 'social', 'blog', 'dashboard']
  const difficulties = ['all', 'beginner', 'intermediate', 'advanced']

  // Mock data - in real app this would come from API
  const templates: Template[] = [
    {
      id: '1',
      name: 'REST API Starter',
      description: 'Complete REST API template with authentication, validation, and error handling',
      category: 'api',
      stack: 'Node.js + Express + Prisma',
      difficulty: 'beginner',
      rating: 4.8,
      downloads: 1250,
      tags: ['REST', 'Authentication', 'Validation']
    },
    {
      id: '2',
      name: 'E-commerce Backend',
      description: 'Full-featured e-commerce backend with payment processing and inventory management',
      category: 'ecommerce',
      stack: 'Python + FastAPI + SQLModel',
      difficulty: 'intermediate',
      rating: 4.9,
      downloads: 890,
      tags: ['E-commerce', 'Payments', 'Inventory']
    },
    {
      id: '3',
      name: 'Social Media Platform',
      description: 'Real-time social media backend with WebSocket support and file uploads',
      category: 'social',
      stack: 'Node.js + Express + Socket.io',
      difficulty: 'advanced',
      rating: 4.7,
      downloads: 567,
      tags: ['Real-time', 'WebSocket', 'File Upload']
    },
    {
      id: '4',
      name: 'Blog CMS',
      description: 'Content management system for blogs with user roles and rich text editing',
      category: 'blog',
      stack: 'Node.js + Express + MongoDB',
      difficulty: 'intermediate',
      rating: 4.6,
      downloads: 432,
      tags: ['CMS', 'Blog', 'Rich Text']
    }
  ]

  const filteredTemplates = templates.filter(template => {
    const matchesSearch = template.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         template.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         template.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))
    const matchesCategory = selectedCategory === 'all' || template.category === selectedCategory
    const matchesDifficulty = selectedDifficulty === 'all' || template.difficulty === selectedDifficulty
    return matchesSearch && matchesCategory && matchesDifficulty
  })

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'bg-green-100 text-green-800 border-green-200'
      case 'intermediate': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'advanced': return 'bg-red-100 text-red-800 border-red-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'api': return <Code className="w-4 h-4" />
      case 'ecommerce': return <Zap className="w-4 h-4" />
      case 'social': return <Database className="w-4 h-4" />
      case 'blog': return <BookOpen className="w-4 h-4" />
      default: return <Code className="w-4 h-4" />
    }
  }

  return (
    <AppLayout
      title="Backend Templates"
      subtitle="Browse and use pre-built backend templates to jumpstart your development"
    >
      {/* Search and Filters */}
      <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm mb-6">
        <div className="flex flex-col lg:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search templates..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
            />
          </div>
          <div className="flex gap-2">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
            >
              {categories.map(category => (
                <option key={category} value={category}>
                  {category === 'all' ? 'All Categories' : category.charAt(0).toUpperCase() + category.slice(1)}
                </option>
              ))}
            </select>
            <select
              value={selectedDifficulty}
              onChange={(e) => setSelectedDifficulty(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
            >
              {difficulties.map(difficulty => (
                <option key={difficulty} value={difficulty}>
                  {difficulty === 'all' ? 'All Levels' : difficulty.charAt(0).toUpperCase() + difficulty.slice(1)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Templates Grid */}
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredTemplates.length === 0 ? (
          <div className="col-span-full bg-white rounded-2xl p-12 border border-gray-200 shadow-sm text-center">
            <BookOpen className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-900 mb-2">No templates found</h3>
            <p className="text-gray-600">Try adjusting your search or filters</p>
          </div>
        ) : (
          filteredTemplates.map((template) => (
            <div key={template.id} className="bg-white rounded-2xl border border-gray-200 shadow-sm hover:shadow-md transition-shadow duration-200 overflow-hidden">
              <div className="p-6">
                {/* Header */}
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center space-x-2">
                    {getCategoryIcon(template.category)}
                    <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                      {template.category}
                    </span>
                  </div>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getDifficultyColor(template.difficulty)}`}>
                    {template.difficulty}
                  </span>
                </div>

                {/* Title and Description */}
                <h3 className="text-lg font-semibold text-gray-900 mb-2">{template.name}</h3>
                <p className="text-gray-600 text-sm mb-4 leading-relaxed">{template.description}</p>

                {/* Stack */}
                <div className="flex items-center space-x-2 mb-4 text-sm text-gray-500">
                  <Database className="w-4 h-4" />
                  <span>{template.stack}</span>
                </div>

                {/* Tags */}
                <div className="flex flex-wrap gap-2 mb-4">
                  {template.tags.map((tag, index) => (
                    <span key={index} className="px-2 py-1 bg-gray-100 text-gray-700 rounded-md text-xs">
                      {tag}
                    </span>
                  ))}
                </div>

                {/* Stats */}
                <div className="flex items-center justify-between text-sm text-gray-500 mb-4">
                  <div className="flex items-center space-x-1">
                    <Star className="w-4 h-4 text-yellow-500 fill-current" />
                    <span>{template.rating}</span>
                  </div>
                  <span>{template.downloads} downloads</span>
                </div>

                {/* Actions */}
                <div className="flex gap-2">
                  <button className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-purple-100 text-purple-700 rounded-lg hover:bg-purple-200 transition-colors duration-200 text-sm font-medium">
                    <Eye className="w-4 h-4" />
                    <span>Preview</span>
                  </button>
                  <button className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-lg hover:from-purple-500 hover:to-pink-500 transition-all duration-200 text-sm font-medium">
                    <Download className="w-4 h-4" />
                    <span>Use Template</span>
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </AppLayout>
  )
}
