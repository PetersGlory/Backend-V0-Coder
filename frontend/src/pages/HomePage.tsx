import { Link } from 'react-router-dom'
import { ArrowRight, Code, Database, Shield, Rocket, Sparkles, CheckCircle, Users } from 'lucide-react'

export default function HomePage() {
  const features = [
    {
      icon: Code,
      title: 'AI-Powered Generation',
      description: 'Describe your backend in natural language and let AI generate the complete specification with all the code you need.',
      gradient: 'from-purple-500 to-pink-500',
      benefits: ['Natural language input', 'Intelligent code generation', 'Best practices included']
    },
    {
      icon: Database,
      title: 'Multiple Stacks',
      description: 'Support for Node.js (Express + Prisma) and Python (FastAPI + SQLModel) with PostgreSQL.',
      gradient: 'from-blue-500 to-cyan-500',
      benefits: ['Node.js & Python', 'Modern frameworks', 'Production-ready ORMs']
    },
    {
      icon: Shield,
      title: 'Production Ready',
      description: 'Generated backends include authentication, validation, Docker, and CI/CD pipelines.',
      gradient: 'from-green-500 to-emerald-500',
      benefits: ['JWT authentication', 'Input validation', 'Docker & CI/CD']
    },
    {
      icon: Rocket,
      title: 'One-Click Deploy',
      description: 'Deploy your generated backend to Railway, Render, or any cloud platform.',
      gradient: 'from-orange-500 to-red-500',
      benefits: ['Cloud deployment', 'Environment config', 'Auto-scaling ready']
    },
  ]

  const stats = [
    { number: '100%', label: 'AI-Powered', description: 'No manual coding required' },
    { number: '2', label: 'Language Stacks', description: 'Node.js & Python support' },
    { number: '∞', label: 'Possibilities', description: 'Unlimited backend ideas' },
  ]

  const testimonials = [
    {
      quote: "Backend V0 saved me hours of setup time. The generated code is production-ready and follows best practices.",
      author: "Sarah Chen",
      role: "Full-Stack Developer",
      company: "TechCorp"
    },
    {
      quote: "I was able to prototype a complete backend API in minutes instead of days. Incredible tool!",
      author: "Marcus Rodriguez",
      role: "Backend Engineer",
      company: "StartupXYZ"
    }
  ]

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-purple-50/30">
      {/* Hero Section */}
      <section className="relative overflow-hidden pt-20 pb-16">
        <div className="absolute inset-0 bg-gradient-to-r from-purple-100/20 via-transparent to-pink-100/20"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            {/* Badge */}
            <div className="inline-flex items-center px-4 py-2 bg-purple-100 text-purple-700 rounded-full text-sm font-medium mb-8 border border-purple-200">
              <Sparkles className="w-4 h-4 mr-2" />
              <span>LAUNCHING 2025</span>
            </div>

            {/* Main Heading */}
            <h1 className="text-5xl md:text-7xl font-bold text-gray-900 mb-8 leading-tight">
              Generate Production-Ready
              <span className="block bg-gradient-to-r from-purple-600 via-pink-600 to-purple-600 bg-clip-text text-transparent">
                Backends
              </span>
              with AI
            </h1>

            {/* Subtitle */}
            <p className="text-xl md:text-2xl text-gray-600 mb-12 max-w-4xl mx-auto leading-relaxed">
              Describe your backend requirements in plain English and get a complete, deployable project 
              with authentication, database models, API endpoints, and deployment configuration.
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row gap-6 justify-center mb-16">
              <Link
                to="/generate"
                className="group relative px-8 py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white font-semibold text-lg rounded-2xl transition-all duration-300 transform hover:scale-105 hover:shadow-2xl hover:shadow-purple-500/25 inline-flex items-center space-x-3"
              >
                <span>Start Generating</span>
                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform duration-300" />
              </Link>
              <a
                href="https://github.com/your-repo"
                target="_blank"
                rel="noopener noreferrer"
                className="px-8 py-4 bg-white hover:bg-gray-50 text-gray-700 hover:text-gray-900 font-semibold text-lg rounded-2xl border-2 border-gray-200 hover:border-purple-300 transition-all duration-300 shadow-sm hover:shadow-md"
              >
                View on GitHub
              </a>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto">
              {stats.map((stat, index) => (
                <div key={index} className="text-center">
                  <div className="text-4xl font-bold bg-gradient-to-r from-purple-600 to-pink-600 bg-clip-text text-transparent mb-2">
                    {stat.number}
                  </div>
                  <div className="text-gray-900 font-semibold mb-1">{stat.label}</div>
                  <div className="text-gray-600 text-sm">{stat.description}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              Everything You Need to Build
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              From simple APIs to complex microservices, Backend V0 generates production-ready code with modern best practices.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            {features.map((feature, index) => {
              const Icon = feature.icon
              return (
                <div key={index} className="group relative">
                  <div className="absolute inset-0 bg-gradient-to-r from-gray-50 to-white rounded-3xl border border-gray-200 shadow-sm transition-all duration-300 group-hover:shadow-xl group-hover:border-purple-200"></div>
                  <div className="relative p-8 rounded-3xl">
                    <div className={`w-16 h-16 bg-gradient-to-br ${feature.gradient} rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300 shadow-lg`}>
                      <Icon className="w-8 h-8 text-white" />
                    </div>
                    <h3 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-transparent group-hover:bg-gradient-to-r group-hover:from-purple-600 group-hover:to-pink-600 group-hover:bg-clip-text transition-all duration-300">
                      {feature.title}
                    </h3>
                    <p className="text-gray-600 leading-relaxed mb-6 group-hover:text-gray-700 transition-colors duration-300">
                      {feature.description}
                    </p>
                    <ul className="space-y-2">
                      {feature.benefits.map((benefit, benefitIndex) => (
                        <li key={benefitIndex} className="flex items-center space-x-2 text-sm text-gray-600">
                          <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
                          <span>{benefit}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              How It Works
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Three simple steps to get your backend up and running
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl font-bold text-purple-600">1</span>
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">Describe Your Needs</h3>
              <p className="text-gray-600">Tell us what you want to build in plain English</p>
            </div>
            <div className="text-center">
              <div className="w-16 h-16 bg-pink-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl font-bold text-pink-600">2</span>
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">AI Generates Code</h3>
              <p className="text-gray-600">Our AI creates a complete backend specification</p>
            </div>
            <div className="text-center">
              <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl font-bold text-purple-600">3</span>
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">Deploy & Scale</h3>
              <p className="text-gray-600">Generate files and deploy to your preferred platform</p>
            </div>
          </div>
        </div>
      </section>

      {/* Testimonials Section */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              Loved by Developers
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              See what developers are saying about Backend V0
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            {testimonials.map((testimonial, index) => (
              <div key={index} className="bg-gray-50 rounded-3xl p-8 border border-gray-200">
                <div className="flex items-center space-x-4 mb-4">
                  <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center">
                    <Users className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <div className="font-semibold text-gray-900">{testimonial.author}</div>
                    <div className="text-sm text-gray-600">{testimonial.role} at {testimonial.company}</div>
                  </div>
                </div>
                <p className="text-gray-700 italic">"{testimonial.quote}"</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-gradient-to-r from-purple-600 to-pink-600">
        <div className="max-w-4xl mx-auto text-center px-4">
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Ready to Build Your Backend?
          </h2>
          <p className="text-xl text-purple-100 mb-8 leading-relaxed">
            Join the future of backend development. Generate, customize, and deploy in minutes, not hours.
          </p>
          <Link 
            to="/generate" 
            className="inline-flex items-center px-10 py-4 bg-white hover:bg-gray-50 text-purple-600 hover:text-purple-700 font-semibold text-xl rounded-2xl transition-all duration-300 transform hover:scale-105 shadow-2xl hover:shadow-3xl"
          >
            <span>Get Started Now</span>
            <ArrowRight className="w-6 h-6 ml-3 group-hover:translate-x-1 transition-transform duration-300" />
          </Link>
        </div>
      </section>
    </div>
  )
}
