# Backend V0 Frontend

A modern React-based web UI for the Backend V0 MVP - an AI-powered backend generator.

## Features

- 🎯 **Natural Language Input**: Describe your backend requirements in plain English
- 🤖 **AI-Powered Generation**: Uses Hugging Face models to generate backend specifications
- 📊 **Interactive Spec Display**: View and explore generated specifications with collapsible sections
- 🏗️ **Project Scaffolding**: Generate complete project files with one click
- 🎨 **Modern UI**: Built with React, TypeScript, and Tailwind CSS
- 📱 **Responsive Design**: Works seamlessly on desktop and mobile devices

## Tech Stack

- **Frontend**: React 18 + TypeScript + Vite
- **Styling**: Tailwind CSS + Lucide React Icons
- **State Management**: React Context API
- **Routing**: React Router DOM
- **Build Tool**: Vite

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Backend V0 API running on port 4000

### Installation

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

4. Open your browser and navigate to `http://localhost:3000`

### Development

- **Development server**: `npm run dev` (runs on port 3000)
- **Build**: `npm run build`
- **Preview build**: `npm run preview`
- **Lint**: `npm run lint`

## Project Structure

```
frontend/
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── Header.tsx      # Navigation header
│   │   ├── PromptInput.tsx # AI prompt input form
│   │   ├── SpecDisplay.tsx # Specification viewer
│   │   └── ScaffoldButton.tsx # Project generation
│   ├── contexts/           # React contexts
│   │   └── BackendSpecContext.tsx # Global state management
│   ├── pages/              # Page components
│   │   ├── HomePage.tsx    # Landing page
│   │   └── GeneratorPage.tsx # Main generator interface
│   ├── App.tsx             # Main app component
│   ├── main.tsx            # Entry point
│   └── index.css           # Global styles
├── public/                 # Static assets
├── package.json            # Dependencies and scripts
├── vite.config.ts          # Vite configuration
├── tailwind.config.js      # Tailwind CSS configuration
└── tsconfig.json           # TypeScript configuration
```

## API Integration

The frontend communicates with the Backend V0 API through the following endpoints:

- `POST /api/spec` - Generate backend specification from prompt
- `POST /api/scaffold` - Generate project files from specification

The API proxy is configured in `vite.config.ts` to forward `/api/*` requests to `http://localhost:4000`.

## Usage

1. **Home Page**: Learn about features and get started
2. **Generate Page**: 
   - Enter your backend requirements in natural language
   - View the AI-generated specification
   - Scaffold the complete project
   - Download or explore generated files

## Example Prompts

- "Build a REST API for a task management app with user authentication, projects, and tasks. Use Express, Prisma, and PostgreSQL."
- "Create a FastAPI backend for an e-commerce platform with products, orders, users, and payment processing. Use SQLModel and PostgreSQL."

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see the main project README for details.
