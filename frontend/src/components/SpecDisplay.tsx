import { useState } from 'react'
import { ChevronDown, ChevronRight, Code, Database, Shield, Zap, Settings } from 'lucide-react'
import { BackendSpec } from '../contexts/BackendSpecContext'

interface SpecDisplayProps {
  spec: BackendSpec
}

export default function SpecDisplay({ spec }: SpecDisplayProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['stack', 'entities']))

  const toggleSection = (section: string) => {
    const newExpanded = new Set(expandedSections)
    if (newExpanded.has(section)) {
      newExpanded.delete(section)
    } else {
      newExpanded.add(section)
    }
    setExpandedSections(newExpanded)
  }

  const renderField = (field: any) => (
    <div key={field.name} className="flex items-center space-x-4 py-3 border-b border-gray-100 last:border-b-0">
      <div className="flex-1">
        <span className="font-medium text-gray-900">{field.name}</span>
        <span className="text-gray-500 ml-2">({field.type})</span>
      </div>
      <div className="flex items-center space-x-2">
        {field.required && (
          <span className="px-2 py-1 text-xs bg-red-100 text-red-800 rounded-full border border-red-200">Required</span>
        )}
        {field.unique && (
          <span className="px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded-full border border-blue-200">Unique</span>
        )}
        {field.default && (
          <span className="px-2 py-1 text-xs bg-green-100 text-green-800 rounded-full border border-green-200">
            Default: {field.default}
          </span>
        )}
      </div>
    </div>
  )

  const renderSection = (
    key: string,
    title: string,
    icon: any,
    children: React.ReactNode,
    defaultExpanded = false
  ) => {
    const isExpanded = expandedSections.has(key)
    const Icon = icon

    return (
      <div key={key} className="border-b border-gray-100 last:border-b-0">
        <button
          onClick={() => toggleSection(key)}
          className="w-full flex items-center justify-between text-left p-6 hover:bg-gray-50 transition-colors duration-200"
        >
          <div className="flex items-center space-x-3">
            <Icon className="w-6 h-6 text-purple-600" />
            <h3 className="text-xl font-semibold text-gray-900">{title}</h3>
          </div>
          {isExpanded ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </button>
        
        {isExpanded && (
          <div className="px-6 pb-6">
            {children}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-0">
      <div className="p-6 border-b border-gray-100 bg-gray-50">
        <h2 className="text-2xl font-bold text-gray-900">Generated Specification</h2>
      </div>
      
      {/* Stack Configuration */}
      {renderSection('stack', 'Stack Configuration', Code, (
        <div className="grid md:grid-cols-2 gap-4">
          <div className="p-4 bg-gray-50 rounded-xl border border-gray-200">
            <span className="text-sm font-medium text-gray-600">Language</span>
            <p className="text-xl font-semibold text-gray-900 capitalize">{spec.stack.language}</p>
          </div>
          <div className="p-4 bg-gray-50 rounded-xl border border-gray-200">
            <span className="text-sm font-medium text-gray-600">Framework</span>
            <p className="text-xl font-semibold text-gray-900">{spec.stack.framework}</p>
          </div>
          <div className="p-4 bg-gray-50 rounded-xl border border-gray-200">
            <span className="text-sm font-medium text-gray-600">Database</span>
            <p className="text-xl font-semibold text-gray-900">{spec.stack.database}</p>
          </div>
          <div className="p-4 bg-gray-50 rounded-xl border border-gray-200">
            <span className="text-sm font-medium text-gray-600">ORM</span>
            <p className="text-xl font-semibold text-gray-900">{spec.stack.orm}</p>
          </div>
        </div>
      ))}

      {/* Entities */}
      {renderSection('entities', 'Data Models', Database, (
        <div className="space-y-4">
          {spec.entities.map((entity) => (
            <div key={entity.name} className="border border-gray-200 rounded-xl p-4 bg-gray-50">
              <h4 className="font-semibold text-gray-900 mb-4">{entity.name}</h4>
              <div className="space-y-1">
                {entity.fields.map(renderField)}
              </div>
            </div>
          ))}
        </div>
      ))}

      {/* Authentication */}
      {renderSection('auth', 'Authentication', Shield, (
        <div className="space-y-4">
          <div className="p-4 bg-gray-50 rounded-xl border border-gray-200">
            <span className="text-sm font-medium text-gray-600">Strategy</span>
            <p className="text-xl font-semibold text-gray-900 capitalize">{spec.auth.strategy}</p>
          </div>
          {spec.auth.roles && spec.auth.roles.length > 0 && (
            <div className="p-4 bg-gray-50 rounded-xl border border-gray-200">
              <span className="text-sm font-medium text-gray-600">Roles</span>
              <div className="flex flex-wrap gap-2 mt-2">
                {spec.auth.roles.map((role) => (
                  <span key={role} className="px-3 py-1 bg-purple-100 text-purple-800 rounded-full text-sm border border-purple-200">
                    {role}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      ))}

      {/* API Endpoints */}
      {renderSection('api', 'API Endpoints', Zap, (
        <div className="space-y-3">
          {spec.api.map((resource) => (
            <div key={resource.resource} className="flex items-center justify-between p-4 bg-gray-50 rounded-xl border border-gray-200">
              <div>
                <span className="font-medium text-gray-900">/{resource.resource}</span>
                {resource.relations && resource.relations.length > 0 && (
                  <span className="text-sm text-gray-500 ml-2">
                    Relations: {resource.relations.join(', ')}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap gap-2">
                {resource.operations.map((op) => (
                  <span key={op} className="px-2 py-1 bg-purple-100 text-purple-800 rounded text-xs font-medium border border-purple-200">
                    {op.toUpperCase()}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      ))}

      {/* Environment Variables */}
      {renderSection('env', 'Environment Variables', Settings, (
        <div className="grid md:grid-cols-2 gap-3">
          {spec.env.map((envVar) => (
            <div key={envVar} className="p-3 bg-gray-50 rounded-xl border border-gray-200">
              <code className="text-sm font-mono text-cyan-700">{envVar}</code>
            </div>
          ))}
        </div>
      ))}

      {/* Extras */}
      {spec.extras && Object.keys(spec.extras).length > 0 && (
        renderSection('extras', 'Additional Features', Zap, (
          <div className="space-y-3">
            {spec.extras.queue && (
              <div className="p-3 bg-gray-50 rounded-xl border border-gray-200">
                <span className="text-sm font-medium text-gray-600">Queue System:</span>
                <span className="ml-2 text-gray-900">{spec.extras.queue}</span>
              </div>
            )}
            {spec.extras.cache && (
              <div className="p-3 bg-gray-50 rounded-xl border border-gray-200">
                <span className="text-sm font-medium text-gray-600">Caching:</span>
                <span className="ml-2 text-gray-900">{spec.extras.cache}</span>
              </div>
            )}
            {spec.extras.storage && (
              <div className="p-3 bg-gray-50 rounded-xl border border-gray-200">
                <span className="text-sm font-medium text-gray-600">File Storage:</span>
                <span className="ml-2 text-gray-900">{spec.extras.storage}</span>
              </div>
            )}
            {spec.extras.thirdParty && spec.extras.thirdParty.length > 0 && (
              <div className="p-3 bg-gray-50 rounded-xl border border-gray-200">
                <span className="text-sm font-medium text-gray-600">Third Party Services:</span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {spec.extras.thirdParty.map((service) => (
                    <span key={service} className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs border border-blue-200">
                      {service}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))
      )}
    </div>
  )
}
