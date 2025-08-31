import { Routes, Route, useLocation } from 'react-router-dom'
import Header from './components/Header'
import Footer from './components/Footer'
import HomePage from './pages/HomePage'
import GeneratorPage from './pages/GeneratorPage'
import HistoryPage from './pages/HistoryPage'
import TemplatesPage from './pages/TemplatesPage'
import DocumentationPage from './pages/DocumentationPage'
import SettingsPage from './pages/SettingsPage'
import { BackendSpecProvider } from './contexts/BackendSpecContext'

function App() {
  const location = useLocation()
  const isGeneratorPage = location.pathname === '/'

  return (
    <BackendSpecProvider>
      <div className="min-h-screen bg-gray-50 flex flex-col">
        {isGeneratorPage && <Header />}
        <main className="flex-1">
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/generate" element={<GeneratorPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/templates" element={<TemplatesPage />} />
            <Route path="/docs" element={<DocumentationPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>
        {isGeneratorPage && <Footer />}
      </div>
    </BackendSpecProvider>
  )
}

export default App
