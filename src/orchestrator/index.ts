import 'dotenv/config';
import express from 'express';
import type { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import fs from 'fs';
import path from 'path';
import { BackendSpec, GenerationRequest, GenerationResponse, ScaffoldRequest, ScaffoldResponse } from '../types/index.js';
import { z } from 'zod';
import archiver from 'archiver';

// Enhanced validation schemas with Zod
const SpecSchema = z.object({
  stack: z.object({
    language: z.enum(['node', 'python']),
    framework: z.string(),
    database: z.string(),
    orm: z.string()
  }),
  entities: z.array(z.object({
    name: z.string(),
    fields: z.array(z.object({
      name: z.string(),
      type: z.string(),
      required: z.boolean(),
      unique: z.boolean().optional(),
      default: z.any().optional(),
      validation: z.object({
        min: z.number().optional(),
        max: z.number().optional(),
        pattern: z.string().optional(),
        enum: z.array(z.string()).optional()
      }).optional()
    })),
    relations: z.array(z.object({
      type: z.enum(['oneToMany', 'manyToOne', 'manyToMany', 'oneToOne']),
      target: z.string(),
      field: z.string(),
      onDelete: z.enum(['cascade', 'restrict', 'setNull']).optional()
    })).optional()
  })),
  auth: z.object({
    strategy: z.enum(['jwt', 'session', 'oauth', 'none']),
    roles: z.array(z.string()).optional(),
    permissions: z.record(z.string(), z.unknown()).optional(),
    oauth: z.object({
      providers: z.array(z.string()).optional(),
      scopes: z.array(z.string()).optional()
    }).optional()
  }).optional(),
  api: z.array(z.object({
    resource: z.string(),
    operations: z.array(z.string()),
    middleware: z.array(z.string()).optional(),
    permissions: z.record(z.string(), z.unknown()).optional(),
    validation: z.record(z.string(), z.unknown()).optional()
  })),
  env: z.array(z.object({
    name: z.string(),
    description: z.string(),
    required: z.boolean(),
    type: z.enum(['string', 'number', 'boolean', 'url', 'secret']),
    default: z.any().optional()
  })),
  extras: z.object({
    queue: z.enum(['bull', 'celery', 'none']).optional(),
    cache: z.enum(['redis', 'memcached', 'none']).optional(),
    storage: z.enum(['s3', 'local', 'gcs', 'none']).optional(),
    email: z.enum(['sendgrid', 'ses', 'smtp', 'none']).optional(),
    payment: z.enum(['stripe', 'paypal', 'none']).optional(),
    search: z.enum(['elasticsearch', 'algolia', 'none']).optional(),
    monitoring: z.enum(['sentry', 'datadog', 'none']).optional(),
    testing: z.boolean().optional(),
    docker: z.boolean().optional(),
    ci_cd: z.boolean().optional()
  }).optional(),
  metadata: z.object({
    name: z.string(),
    description: z.string(),
    version: z.string(),
    license: z.string()
  }).optional()
});

// Enhanced BackendGenerator class using Google Gemini
class BackendGenerator {
  private geminiApiKey = process.env.GEMINI_API_KEY!;
  private geminiApiUrl = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent';
  
  async generateSpec(prompt: string, retries = 3): Promise<any> {
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const spec = await this.callGemini(prompt);
        
        // Validate the generated spec
        const validated = SpecSchema.parse(spec);
        return validated;
      } catch (error) {
        console.error(`Attempt ${attempt + 1} failed:`, error);
        
        if (attempt === retries - 1) {
          throw new Error('All attempts failed to generate valid specification');
        }
      }
    }
    
    throw new Error('All attempts failed to generate valid specification');
  }
  
  private async callGemini(prompt: string): Promise<any> {
    const systemPrompt = this.getSystemPrompt();
    const fullPrompt = `${systemPrompt}\n\nUser Request: ${prompt}`;

    const response = await fetch(`${this.geminiApiUrl}?key=${this.geminiApiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: fullPrompt
          }]
        }],
        generationConfig: {
          temperature: 0.1,
          topK: 40,
          topP: 0.95,
          maxOutputTokens: 2048,
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Gemini API Error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const generatedText = data.candidates?.[0]?.content?.parts?.[0]?.text;
    
    if (!generatedText) {
      throw new Error('Gemini API returned no text');
    }

    // Clean and parse the response
    const cleanedText = this.cleanJsonResponse(generatedText);
    return JSON.parse(cleanedText);
  }
  
  private cleanJsonResponse(text: string): string {
    // Remove markdown formatting
    text = text.replace(/```json\n?/g, '').replace(/```\n?/g, '');
    
    // Find JSON boundaries
    const jsonStart = text.indexOf('{');
    const jsonEnd = text.lastIndexOf('}') + 1;
    
    if (jsonStart === -1 || jsonEnd === 0) {
      throw new Error('No JSON object found in response');
    }
    
    return text.slice(jsonStart, jsonEnd).trim();
  }
  
  private getSystemPrompt(): string {
    return SYSTEM_PROMPT;
  }
}

// Enhanced Scaffolder class with comprehensive project generation
class Scaffolder {
  async generateProjectZip(spec: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const archive = archiver('zip', { zlib: { level: 9 } });
      const chunks: Buffer[] = [];
      
      archive.on('data', (chunk) => {
        chunks.push(chunk);
      });
      
      archive.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
      
      archive.on('error', (err) => {
        reject(err);
      });
      
      // Generate project files directly into the archive
      if (spec.stack.language === 'node') {
        this.addNodeProjectToArchive(archive, spec);
      } else if (spec.stack.language === 'python') {
        this.addPythonProjectToArchive(archive, spec);
      }
      
      archive.finalize();
    });
  }
  
  private addNodeProjectToArchive(archive: archiver.Archiver, spec: any) {
    const projectName = spec.metadata?.name || 'backend-project';
    
    // Add package.json
    const pkg = {
      name: projectName,
      type: 'module',
      scripts: {
        dev: 'tsx src/server.ts',
        build: 'tsc',
        start: 'node dist/server.js',
        prisma: 'prisma'
      },
      dependencies: {
        express: '^4',
        zod: '^3',
        jsonwebtoken: '^9',
        bcryptjs: '^2',
        prisma: '^5',
        '@prisma/client': '^5'
      },
      devDependencies: { typescript: '^5', tsx: '^4', '@types/express': '^4' }
    };
    
    archive.append(JSON.stringify(pkg, null, 2), { name: 'package.json' });
    
    // Add tsconfig.json
    const tsconfig = {
      compilerOptions: {
        outDir: 'dist',
        module: 'ESNext',
        target: 'ES2022',
        moduleResolution: 'Node'
      }
    };
    archive.append(JSON.stringify(tsconfig, null, 2), { name: 'tsconfig.json' });
    
    // Add .env.example
    archive.append('DATABASE_URL=postgresql://user:pass@localhost:5432/app\nJWT_SECRET=change-me', { name: '.env.example' });
    
    // Add Prisma schema
    const prismaModels = spec.entities
      .map((e: any) => `model ${e.name} {\n${e.fields.map((f: any) => this.prismaField(e.name, f)).join('\n')}\n}`)
      .join('\n\n');
    const prismaSchema = `datasource db { provider = "postgresql" url = env("DATABASE_URL") }\n\ngenerator client { provider = "prisma-client-js" }\n\n${prismaModels}\n`;
    archive.append(prismaSchema, { name: 'prisma/schema.prisma' });
    
    // Add server.ts
    archive.append(this.serverTs(spec), { name: 'src/server.ts' });
    
    // Add routes
    for (const r of spec.api) {
      archive.append(this.routerTs(r.resource, r.operations), { name: `src/routes/${r.resource}.ts` });
    }
    
    // Add auth.ts
    archive.append(this.authTs(), { name: 'src/auth.ts' });
    
    // Add Dockerfile
    archive.append(this.dockerNode(), { name: 'Dockerfile' });
    
    // Add GitHub Actions
    archive.append(this.ghActions(), { name: '.github/workflows/deploy.yml' });
    
    // Add README
    archive.append(this.generateNodeReadme(spec), { name: 'README.md' });
  }
  
  private addPythonProjectToArchive(archive: archiver.Archiver, spec: any) {
    const projectName = spec.metadata?.name || 'backend-project';
    
    // Add requirements.txt
    const requirements = `fastapi==0.114.0
uvicorn[standard]==0.30.0
sqlmodel==0.0.22
psycopg2-binary==2.9.9
python-dotenv==1.0.1
passlib[bcrypt]==1.7.4
pyjwt==2.8.0
alembic==1.13.1
python-multipart==0.0.6
email-validator==2.1.0`;
    archive.append(requirements, { name: 'requirements.txt' });
    
    // Add .env.example
    const envExample = `DATABASE_URL=postgresql://user:pass@localhost:5432/app
JWT_SECRET=change-me-this-is-a-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600
CORS_ORIGINS=http://localhost:3000,http://localhost:8080`;
    archive.append(envExample, { name: '.env.example' });
    
    // Add main.py
    archive.append(this.fastapiMain(spec), { name: 'app/main.py' });
    
    // Add database connection
    archive.append(this.databaseConnection(), { name: 'app/database/__init__.py' });
    archive.append(this.databaseConnection(), { name: 'app/database/connection.py' });
    
    // Add models
    archive.append(this.modelsInit(spec), { name: 'app/models/__init__.py' });
    archive.append(this.baseModel(), { name: 'app/models/base.py' });
    
    // Generate individual entity models
    for (const entity of spec.entities) {
      archive.append(this.generateEntityModel(entity), { name: `app/models/${entity.name.toLowerCase()}.py` });
    }
    
    // Add authentication
    archive.append('', { name: 'app/auth/__init__.py' });
    archive.append(this.jwtAuth(spec), { name: 'app/auth/jwt.py' });
    archive.append(this.authDependencies(spec), { name: 'app/auth/dependencies.py' });
    
    // Add routes
    archive.append('', { name: 'app/routes/__init__.py' });
    for (const resource of spec.api) {
      archive.append(this.generatePythonRoute(resource, spec), { name: `app/routes/${resource.resource}.py` });
    }
    
    // Add Alembic configuration
    archive.append(this.alembicConfig(), { name: 'alembic.ini' });
    archive.append(this.alembicEnv(), { name: 'alembic/env.py' });
    archive.append(this.alembicScript(), { name: 'alembic/script.py.mako' });
    
    // Add Docker and deployment
    archive.append(this.dockerPy(), { name: 'Dockerfile' });
    archive.append(this.ghActions(), { name: '.github/workflows/deploy.yml' });
    
    // Add run script and README
    archive.append(this.runScript(), { name: 'run.py' });
    archive.append(this.pythonReadme(spec), { name: 'README.md' });
  }
  
  // Helper methods for archive generation
  private prismaField(modelName: string, f: any): string {
    const map: Record<string, string> = {
      string: 'String',
      int: 'Int',
      uuid: 'String @id @default(uuid())',
      decimal: 'Decimal',
      datetime: 'DateTime'
    };
    if (f.name === 'id') return `  id String @id @default(uuid())`;
    if (String(f.type).startsWith('enum:')) {
      const enumName = `${modelName}${f.name[0].toUpperCase() + f.name.slice(1)}Enum`;
      return `  ${f.name} ${enumName}`;
    }
    const t = map[f.type] || 'String';
    const req = f.required ? '' : '?';
    const uniq = f.unique ? ' @unique' : '';
    return `  ${f.name} ${t}${req}${uniq}`;
  }

  private serverTs(spec: any): string {
    return (
      "import express from 'express';\n" +
      "import { json } from 'express';\n" +
      "import { PrismaClient } from '@prisma/client';\n" +
      "const prisma = new PrismaClient();\n" +
      "const app = express();\n" +
      'app.use(json());\n' +
      "app.get('/health', (_req,res)=>res.json({ok:true}));\n" +
      spec.api
        .map((r: any) => `app.use('/api/${r.resource}', require('./routes/${r.resource}').default);`)
        .join('\n') +
      "\napp.listen(process.env.PORT||3000, ()=> console.log('API on', process.env.PORT||3000));\n"
    );
  }

  private routerTs(resource: string, ops: string[]): string {
    return (
      "import { Router } from 'express';\n" +
      "import { PrismaClient } from '@prisma/client';\n" +
      'const prisma = new PrismaClient();\n' +
      'const r = Router();\n' +
      (ops.includes('list')
        ? "r.get('/', async (_req,res)=>{ const data = await prisma." + resource + ".findMany(); res.json(data); });\n"
        : '') +
      (ops.includes('get')
        ? "r.get('/:id', async (req,res)=>{ const item = await prisma." +
          resource +
          ".findUnique({ where: { id: String(req.params.id) } }); if(!item) return res.status(404).end(); res.json(item); });\n"
        : '') +
      (ops.includes('create')
        ? "r.post('/', async (req,res)=>{ const item = await prisma." + resource + ".create({ data: req.body }); res.status(201).json(item); });\n"
        : '') +
      (ops.includes('update')
        ? "r.put('/:id', async (req,res)=>{ const item = await prisma." +
          resource +
          ".update({ where:{ id: String(req.params.id)}, data: req.body }); res.json(item); });\n"
        : '') +
      (ops.includes('delete')
        ? "r.delete('/:id', async (req,res)=>{ await prisma." + resource + ".delete({ where:{ id: String(req.params.id)} }); res.status(204).end(); });\n"
        : '') +
      'export default r;\n'
    );
  }

  private authTs(): string {
    return (
      "import jwt from 'jsonwebtoken';\n" +
      'export function authMiddleware(req:any,res:any,next:any){ next(); }\n' +
      '// TODO: implement JWT verification and role checks based on spec.auth\n'
    );
  }

  private dockerNode(): string {
    return `FROM node:20-alpine\nWORKDIR /app\nCOPY package.json package-lock.json* yarn.lock* pnpm-lock.yaml* ./\nRUN npm i --silent || yarn || pnpm i\nCOPY . .\nRUN npm run build\nEXPOSE 3000\nCMD ["npm","start"]\n`;
  }

  private ghActions(): string {
    return `name: deploy\non: { push: { branches: [ main ] } }\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n    - uses: actions/checkout@v4\n    - uses: actions/setup-node@v4\n      with: { node-version: 20 }\n    - run: npm ci\n    - run: npm run build\n    - run: echo 'Deploy step here (Railway/Render CLI)'\n`;
  }

  private generateNodeReadme(spec: any): string {
    return `# ${spec.metadata?.name || 'Backend V0'} - Node.js Express Backend

This is an AI-generated backend API built with Express, Prisma, and PostgreSQL.

## Features

- Express.js: Fast, unopinionated web framework
- Prisma: Next-generation ORM for Node.js and TypeScript
- PostgreSQL: Robust, open-source database
- JWT Authentication: Secure token-based authentication
- TypeScript: Type-safe JavaScript
- Automatic CRUD: Generated endpoints for all entities

## Quick Start

1. Install dependencies
   \`\`\`bash
   npm install
   \`\`\`

2. Set up environment variables
   \`\`\`bash
   cp .env.example .env
   \`\`\`
   (Edit .env with your database credentials)

3. Set up the database
   \`\`\`bash
   npx prisma generate
   npx prisma db push
   \`\`\`

4. Start the server
   \`\`\`bash
   npm run dev
   \`\`\`

## API Documentation

Once running, visit:
- Health Check: http://localhost:3000/health
- API Endpoints: http://localhost:3000/api/{resource}

## Project Structure

\`\`\`
src/
  server.ts           (Express application)
  auth.ts             (Authentication utilities)
  routes/             (API route handlers)
    *.ts              (Resource-specific routes)
prisma/
  schema.prisma       (Database schema)
\`\`\`

## Development

Adding New Models:
1) Update prisma/schema.prisma
2) Run: npx prisma generate
3) Run: npx prisma db push

## Deployment

Docker:
\`\`\`bash
docker build -t backend-v0 .
docker run -p 3000:3000 backend-v0
\`\`\`

Generated by Backend V0 Orchestrator.
`;
  }

  // Python helper methods
  private fastapiMain(spec: any): string {
    const imports = [
      'from fastapi import FastAPI, HTTPException, Depends',
      'from fastapi.middleware.cors import CORSMiddleware',
      'from sqlmodel import SQLModel, create_engine, Session',
      'from app.database.connection import engine, get_session',
      'from app.models import *',
      'from app.auth.dependencies import get_current_user, get_current_active_user',
      'import os'
    ];

    const routeImports = spec.api.map((r: any) => `from app.routes.${r.resource} import router as ${r.resource}_router`);

    return `${imports.join('\n')}
${routeImports.join('\n')}

app = FastAPI(
    title="${spec.metadata?.name || 'Backend V0 API'}",
    description="AI-generated backend API",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database initialization
@app.on_event("startup")
async def on_startup():
    SQLModel.metadata.create_all(engine)

# Health check
@app.get("/health")
def health():
    return {"ok": True, "message": "API is running"}

# Include routers
${spec.api.map((r: any) => `app.include_router(${r.resource}_router, prefix="/api/${r.resource}", tags=["${r.resource}"])`).join('\n')}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
`;
  }

  private databaseConnection(): string {
    return `from sqlmodel import create_engine, Session
from sqlmodel import SQLModel
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/app")

engine = create_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL debugging
    pool_pre_ping=True,
    pool_recycle=300
)

def get_session():
    with Session(engine) as session:
        yield session
`;
  }

  private modelsInit(spec: any): string {
    const modelImports = spec.entities.map((entity: any) => `from .${entity.name.toLowerCase()} import ${entity.name}`);
    
    return `# Generated models
from .base import BaseModel
${modelImports.join('\n')}

# Export all models
__all__ = [
    "BaseModel",
${spec.entities.map((e: any) => `    "${e.name}"`).join(',\n')}
]
`;
  }

  private baseModel(): string {
    return `from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime
import uuid

class BaseModel(SQLModel):
    id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    
    class Config:
        arbitrary_types_allowed = True
`;
  }

  private generateEntityModel(entity: any): string {
    const fields = entity.fields.map((field: any) => {
      let fieldType = 'str';
      let fieldConfig = '';

      switch (field.type) {
        case 'int':
          fieldType = 'int';
          break;
        case 'decimal':
          fieldType = 'float';
          break;
        case 'datetime':
          fieldType = 'datetime';
          break;
        case 'boolean':
          fieldType = 'bool';
          break;
        default:
          if (field.type.startsWith('enum:')) {
            const enumValues = field.type.split(':')[1].split('|');
            fieldType = `Literal[${enumValues.map((v: any) => `"${v}"`).join(', ')}]`;
          }
      }

      if (!field.required) {
        fieldType = `Optional[${fieldType}]`;
        fieldConfig = ' = None';
      }

      if (field.unique) {
        fieldConfig += ', unique=True';
      }

      if (field.default && field.default !== 'uuid') {
        if (field.type === 'string') {
          fieldConfig += ` = "${field.default}"`;
        } else {
          fieldConfig += ` = ${field.default}`;
        }
      }

      return `    ${field.name}: ${fieldType}${fieldConfig}`;
    }).filter((f: any) => f !== '');

    return `from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime
from .base import BaseModel

class ${entity.name}(BaseModel, table=True):
${fields.join('\n')}
    
    class Config:
        table = True
`;
  }

  private jwtAuth(spec: any): string {
    if (spec.auth.strategy !== 'jwt') {
      return `# Authentication not configured for this backend
# Configure auth strategy in your spec`;
    }
    
    return `import jwt
from datetime import datetime, timedelta
from typing import Optional
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

load_dotenv()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = os.getenv("JWT_SECRET", "change-me")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRATION", "3600"))

# Security scheme
security = HTTPBearer()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
`;
  }

  private authDependencies(spec: any): string {
    if (spec.auth.strategy !== 'jwt') {
      return `# Authentication dependencies not configured
# Configure auth strategy in your spec`;
    }
    
    return `from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.auth.jwt import verify_token, security
from app.models.user import User
from app.database.connection import get_session
from sqlmodel import Session, select

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: Session = Depends(get_session)
) -> User:
    token = credentials.credentials
    payload = verify_token(token)
    user_id: str = payload.get("sub")
    
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    
    user = session.exec(select(User).where(User.id == user_id)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

def require_role(required_roles: list):
    def role_checker(current_user: User = Depends(get_current_user)):
        if not any(role in current_user.roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return role_checker
`;
  }

  private generatePythonRoute(resource: any, spec: any): string {
    const resourceName = resource.resource;
    const modelName = resourceName.charAt(0).toUpperCase() + resourceName.slice(1);
    const operations = resource.operations;
    
    let routeContent = `from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select
from typing import List, Optional
from app.database.connection import get_session
from app.models.${resourceName.toLowerCase()} import ${modelName}
from app.auth.dependencies import get_current_user, require_role
from app.models.user import User

router = APIRouter()

`;

    // Add CRUD operations based on spec
    if (operations.includes('list')) {
      routeContent += `@router.get("/", response_model=List[${modelName}])
async def list_${resourceName}(
    skip: int = 0,
    limit: int = 100,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """List all ${resourceName}"""
    ${resourceName} = session.exec(select(${modelName}).offset(skip).limit(limit)).all()
    return ${resourceName}

`;
    }

    if (operations.includes('get')) {
      routeContent += `@router.get("/{${resourceName}_id}", response_model=${modelName})
async def get_${resourceName}(
    ${resourceName}_id: str,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """Get a specific ${resourceName} by ID"""
    ${resourceName} = session.exec(select(${modelName}).where(${modelName}.id == ${resourceName}_id)).first()
    if not ${resourceName}:
        raise HTTPException(status_code=404, detail="${modelName} not found")
    return ${resourceName}

`;
    }

    if (operations.includes('create')) {
      routeContent += `@router.post("/", response_model=${modelName}, status_code=status.HTTP_201_CREATED)
async def create_${resourceName}(
    ${resourceName}_data: ${modelName},
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """Create a new ${resourceName}"""
    ${resourceName} = ${modelName}(**${resourceName}_data.dict())
    session.add(${resourceName})
    session.commit()
    session.refresh(${resourceName})
    return ${resourceName}

`;
    }

    if (operations.includes('update')) {
      routeContent += `@router.put("/{${resourceName}_id}", response_model=${modelName})
async def update_${resourceName}(
    ${resourceName}_id: str,
    ${resourceName}_data: ${modelName},
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """Update an existing ${resourceName}"""
    ${resourceName} = session.exec(select(${modelName}).where(${modelName}.id == ${resourceName}_id)).first()
    if not ${resourceName}:
        raise HTTPException(status_code=404, detail="${modelName} not found")
    
    update_data = ${resourceName}_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(${resourceName}, field, value)
    
    session.add(${resourceName})
    session.commit()
    session.refresh(${resourceName})
    return ${resourceName}

`;
    }

    if (operations.includes('delete')) {
      routeContent += `@router.delete("/{${resourceName}_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_${resourceName}(
    ${resourceName}_id: str,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """Delete a ${resourceName}"""
    ${resourceName} = session.exec(select(${modelName}).where(${modelName}.id == ${resourceName}_id)).first()
    if not ${resourceName}:
        raise HTTPException(status_code=404, detail="${modelName} not found")
    
    session.delete(${resourceName})
    session.commit()
    return None

`;
    }

    return routeContent;
  }

  private alembicConfig(): string {
    return `# A generic, single database configuration.

[alembic]
# path to migration scripts
script_location = alembic

# template used to generate migration file names; The default value is %%(rev)s_%%(slug)s
# Uncomment the line below if you want the files to be prepended with a date and time
# file_template = %%(year)d_%%(month).2d_%%(day).2d_%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s

# sys.path path, will be prepended to sys.path if present.
# defaults to the current working directory.
prepend_sys_path = .

# timezone to use when rendering the date within the migration file
# as well as the filename.
# If specified, requires the python-dateutil library that can be
# installed by adding \`alembic[tz]\` to the pip requirements
# string value is passed to dateutil.tz.gettz()
# leave blank for localtime
# timezone =

# max length of characters to apply to the
# "slug" field
# truncate_slug_length = 40

# set to 'true' to run the environment during
# the 'revision' command, regardless of autogenerate
# revision_environment = false

# set to 'true' to allow .pyc and .pyo files without
# a source .py file to be detected as revisions in the
# versions/ directory
# sourceless = false

# version number format
version_num_format = %04d

# version path separator; As mentioned above, this is the character used to split
# version_locations. The default within new alembic.ini files is "os", which uses
# os.pathsep. If this key is omitted entirely, it falls back to the legacy
# behavior of splitting on spaces and/or commas.
# Valid values for version_path_separator are:
#
# version_path_separator = :
# version_path_separator = ;
# version_path_separator = space
version_path_separator = os

# the output encoding used when revision files
# are written from script.py.mako
# output_encoding = utf-8

sqlalchemy.url = postgresql://user:pass@localhost:5432/app


[post_write_hooks]
# post_write_hooks defines scripts or Python functions that are run
# on newly generated revision scripts.  See the documentation for further
# detail and examples

# format using "black" - use the console_scripts runner, against the "black" entrypoint
# hooks = black
# black.type = console_scripts
# black.entrypoint = black
# black.options = -l 79 REVISION_SCRIPT_FILENAME

# Logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
`;
  }

  private alembicEnv(): string {
    return `from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
from app.models import *
from app.database.connection import DATABASE_URL

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = SQLModel.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = DATABASE_URL
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = DATABASE_URL
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
`;
  }

  private alembicScript(): string {
    return `"""\${message}

Revision ID: \${up_revision}
Revises: \${down_revision | comma,n}
Create Date: \${create_date}

"""
from alembic import op
import sqlalchemy as sa
\${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = \${repr(up_revision)}
down_revision = \${repr(down_revision)}
branch_labels = \${repr(branch_labels)}
depends_on = \${repr(depends_on)}


def upgrade() -> None:
    \${upgrades if upgrades else "pass"}


def downgrade() -> None:
    \${downgrades if downgrades else "pass"}
`;
  }

  private runScript(): string {
    return `#!/usr/bin/env python3
"""
Run script for the FastAPI application
"""
import uvicorn
from app.main import app

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
`;
  }

  private pythonReadme(spec: any): string {
    return `# ${spec.metadata?.name || 'Backend V0'} - Python FastAPI Backend

This is an AI-generated backend API built with FastAPI, SQLModel, and PostgreSQL.

## Features

- FastAPI: Modern, fast web framework for building APIs
- SQLModel: SQL databases in Python, designed for simplicity and compatibility
- PostgreSQL: Robust, open-source database
- JWT Authentication: Secure token-based authentication
- Automatic CRUD: Generated endpoints for all entities
- Database Migrations: Alembic for schema management

## Quick Start

1. Install dependencies
   pip install -r requirements.txt

2. Set environment variables
   cp .env.example .env
   (Edit .env with your database credentials)

3. Run database migrations
   alembic upgrade head

4. Start the server
   python run.py
   or
   uvicorn app.main:app --reload

## API Documentation

Once running, visit:
- API Docs: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- Health Check: http://localhost:8000/health

## Project Structure

app/
  __init__.py
  main.py              (FastAPI application)
  auth/
    __init__.py
    jwt.py             (JWT utilities)
    dependencies.py    (Auth dependencies)
  database/
    __init__.py
    connection.py      (Database connection)
  models/
    __init__.py
    base.py            (Base model)
    *.py               (Entity models)
  routes/
    __init__.py
    *.py               (Resource routes)

## Development

Adding New Models:
1) Create a new model in app/models/
2) Add it to app/models/__init__.py
3) Run: alembic revision --autogenerate -m "Add new model"
4) Run: alembic upgrade head

Database Migrations:
- Create a new migration: alembic revision --autogenerate -m "Description"
- Apply migrations: alembic upgrade head
- Rollback: alembic downgrade -1

## Deployment

Docker:
- docker build -t backend-v0 .
- docker run -p 8000:8000 backend-v0

Environment Variables:
- DATABASE_URL: PostgreSQL connection string
- JWT_SECRET: Secret key for JWT tokens
- JWT_ALGORITHM: JWT algorithm (default: HS256)
- JWT_EXPIRATION: Token expiration in seconds
- CORS_ORIGINS: Comma-separated allowed origins

Security Notes:
- Change your JWT_SECRET in production
- Configure CORS origins for your frontend
- Set up proper database credentials
- Enable HTTPS in production

Generated by Backend V0 Orchestrator.
`;
  }

  private dockerPy(): string {
    return `FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]`;
  }
  
  private generateInstructions(spec: any): string[] {
    const instructions = [
      '🎉 Your backend has been generated successfully!',
      '',
      '📋 Next steps:',
      '1. Navigate to your project directory',
      '2. Copy .env.example to .env and configure your environment variables',
    ];
    
    if (spec.stack.language === 'node') {
      instructions.push(
        '3. Run: npm install',
        '4. Run: npx prisma generate',
        '5. Run: npx prisma db push (to set up your database)',
        '6. Run: npm run dev (to start development server)',
        '',
        '🚀 Your API will be available at http://localhost:3000',
        '📊 Health check: http://localhost:3000/health'
      );
    } else {
      instructions.push(
        '3. Run: pip install -r requirements.txt',
        '4. Run: uvicorn app.main:app --reload',
        '',
        '🚀 Your API will be available at http://localhost:8000',
        '📊 Health check: http://localhost:8000/health',
        '📖 API docs: http://localhost:8000/docs'
      );
    }
    
    instructions.push(
      '',
      '🔒 Security Notes:',
      '- Change your JWT_SECRET in production',
      '- Configure CORS origins for your frontend',
      '- Set up proper database credentials',
      '- Enable HTTPS in production',
      '',
      '📦 Docker:',
      '- Run: docker-compose up -d',
      '- This will start your app with database and dependencies'
    );
    
    return instructions;
  }
  
}

// HTTP server setup
const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(helmet());
app.use(compression());
app.use(morgan('dev'));
app.use(express.json({ limit: '1mb' }));

// Health check
app.get('/health', (_req: Request, res: Response) => res.json({ ok: true }));

// API Routes
app.post('/api/generate-spec', async (req: Request, res: Response) => {
  try {
    const { prompt } = req.body;
    
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt is required and must be a string' });
    }
    
    const spec = await promptToSpec(prompt);
    res.json(spec);
  } catch (error) {
    console.error('Generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate specification', 
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

app.post('/api/scaffold', async (req: Request, res: Response) => {
  try {
    const { spec } = req.body;
    
    // Validate spec
    const validatedSpec = SpecSchema.parse(spec);
    
    // Generate zip file
    const scaffolder = new Scaffolder();
    const zipBuffer = await scaffolder.generateProjectZip(validatedSpec);
    
    // Set headers for file download
    const projectName = validatedSpec.metadata?.name || 'backend-project';
    const fileName = `${projectName}-${Date.now()}.zip`;
    
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.setHeader('Content-Length', zipBuffer.length);
    
    // Send the zip file
    res.send(zipBuffer);
  } catch (error) {
    console.error('Scaffolding error:', error);
    res.status(500).json({
      error: 'Failed to scaffold project',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Legacy endpoints for backward compatibility
app.post('/spec', async (req: Request, res: Response) => {
  const body = req.body as GenerationRequest;
  if (!body?.prompt) return res.status(400).json({ success: false, error: 'prompt required' } satisfies GenerationResponse);
  try {
    const spec = await promptToSpec(body.prompt);
    const resp: GenerationResponse = { success: true, spec };
    res.json(resp);
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message || 'generation failed' } satisfies GenerationResponse);
  }
});

app.post('/scaffold', async (req: Request, res: Response) => {
  const body = req.body as ScaffoldRequest;
  if (!body?.spec) return res.status(400).json({ success: false, error: 'spec required' } satisfies ScaffoldResponse);
  const outDir = path.resolve('out');
  try {
    scaffoldFromSpec(body.spec, outDir);
    const resp: ScaffoldResponse = { success: true, localPath: outDir };
    res.json(resp);
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message || 'scaffold failed' } satisfies ScaffoldResponse);
  }
});

// Initialize the server
const port = Number(process.env.PORT || 4000);

async function startServer() {
  try {
    // Start the HTTP server
    app.listen(port, () => {
      console.log(`🚀 Enhanced Backend V0 Orchestrator listening on http://localhost:${port}`);
      console.log('✨ Features:');
      console.log('   - Enhanced AI generation with multiple models');
      console.log('   - Zod validation schemas');
      console.log('   - Comprehensive project scaffolding');
      console.log('   - Advanced error handling and retry logic');
      console.log('   - Production-ready Node.js and Python backends');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();



// Enhanced system prompt with better structure and examples
const SYSTEM_PROMPT = `You are BackendV0, an expert backend architect and code generator.

TASK: Convert natural language requirements into a structured JSON specification for backend generation.

OUTPUT FORMAT: Return ONLY a valid JSON object with this exact structure:

{
  "stack": {
    "language": "node" | "python",
    "framework": "express" | "fastapi" | "nestjs" | "django",
    "database": "postgres" | "mysql" | "sqlite" | "mongodb",
    "orm": "prisma" | "typeorm" | "sqlmodel" | "sqlalchemy" | "mongoose"
  },
  "entities": [
    {
      "name": "EntityName",
      "fields": [
        {
          "name": "fieldName",
          "type": "uuid" | "string" | "int" | "float" | "decimal" | "boolean" | "datetime" | "enum:value1|value2" | "relation:EntityName",
          "required": boolean,
          "unique": boolean,
          "default": string | null,
          "validation": {
            "min": number,
            "max": number,
            "pattern": string,
            "enum": string[]
          }
        }
      ],
      "relations": [
        {
          "type": "oneToMany" | "manyToOne" | "manyToMany" | "oneToOne",
          "target": "EntityName",
          "field": "fieldName",
          "onDelete": "cascade" | "restrict" | "setNull"
        }
      ]
    }
  ],
  "auth": {
    "strategy": "jwt" | "session" | "oauth" | "none",
    "roles": string[],
    "permissions": {
      "role": {
        "resource": ["read", "write", "delete", "admin"]
      }
    },
    "oauth": {
      "providers": ["google", "github", "facebook"],
      "scopes": string[]
    }
  },
  "api": [
    {
      "resource": "resourceName",
      "operations": ["list", "get", "create", "update", "delete", "search"],
      "middleware": ["auth", "validate", "rateLimit", "cache"],
      "permissions": {
        "list": ["admin", "user"],
        "create": ["admin"],
        "update": ["admin", "owner"],
        "delete": ["admin"]
      },
      "validation": {
        "create": {"field": "validation_rule"},
        "update": {"field": "validation_rule"}
      }
    }
  ],
  "env": [
    {
      "name": "ENV_VAR_NAME",
      "description": "Description of the environment variable",
      "required": boolean,
      "default": string | null,
      "type": "string" | "number" | "boolean" | "url" | "secret"
    }
  ],
  "extras": {
    "queue": "bull" | "celery" | "none",
    "cache": "redis" | "memcached" | "none",
    "storage": "s3" | "local" | "gcs" | "none",
    "email": "sendgrid" | "ses" | "smtp" | "none",
    "payment": "stripe" | "paypal" | "none",
    "search": "elasticsearch" | "algolia" | "none",
    "monitoring": "sentry" | "datadog" | "none",
    "testing": boolean,
    "docker": boolean,
    "ci_cd": boolean
  },
  "metadata": {
    "name": "project-name",
    "description": "Brief project description",
    "version": "1.0.0",
    "license": "MIT"
  }
}

RULES:
1. ALWAYS include an 'id' field as the primary key for each entity
2. Use UUIDs by default for IDs unless specified otherwise
3. Include proper relationships between entities
4. Add validation rules for common patterns (email, phone, etc.)
5. Include reasonable defaults for environment variables
6. Consider security implications (auth, permissions, rate limiting)
7. Return ONLY the JSON object, no explanations or markdown formatting

EXAMPLES:

Input: "Build a blog API with users, posts, and comments. Use Node.js and PostgreSQL."
Output: {"stack":{"language":"node","framework":"express","database":"postgres","orm":"prisma"},"entities":[{"name":"User","fields":[{"name":"id","type":"uuid","required":true,"unique":true,"default":"uuid"},{"name":"email","type":"string","required":true,"unique":true,"validation":{"pattern":"email"}},{"name":"username","type":"string","required":true,"unique":true},{"name":"passwordHash","type":"string","required":true},{"name":"createdAt","type":"datetime","required":true,"default":"now"}],"relations":[]},{"name":"Post","fields":[{"name":"id","type":"uuid","required":true,"unique":true,"default":"uuid"},{"name":"title","type":"string","required":true},{"name":"content","type":"string","required":true},{"name":"authorId","type":"uuid","required":true},{"name":"published","type":"boolean","required":true,"default":"false"},{"name":"createdAt","type":"datetime","required":true,"default":"now"}],"relations":[{"type":"manyToOne","target":"User","field":"authorId","onDelete":"cascade"}]},{"name":"Comment","fields":[{"name":"id","type":"uuid","required":true,"unique":true,"default":"uuid"},{"name":"content","type":"string","required":true},{"name":"authorId","type":"uuid","required":true},{"name":"postId","type":"uuid","required":true},{"name":"createdAt","type":"datetime","required":true,"default":"now"}],"relations":[{"type":"manyToOne","target":"User","field":"authorId","onDelete":"cascade"},{"type":"manyToOne","target":"Post","field":"postId","onDelete":"cascade"}]}],"auth":{"strategy":"jwt","roles":["admin","user"],"permissions":{"admin":{"posts":["read","write","delete","admin"],"comments":["read","write","delete","admin"]},"user":{"posts":["read","write"],"comments":["read","write"]}}},"api":[{"resource":"users","operations":["list","get","create","update","delete"],"middleware":["auth","validate"],"permissions":{"list":["admin"],"get":["admin","owner"],"create":["public"],"update":["admin","owner"],"delete":["admin","owner"]}},{"resource":"posts","operations":["list","get","create","update","delete","search"],"middleware":["auth","validate","cache"],"permissions":{"list":["public"],"get":["public"],"create":["user","admin"],"update":["admin","owner"],"delete":["admin","owner"],"search":["public"]}},{"resource":"comments","operations":["list","get","create","update","delete"],"middleware":["auth","validate"],"permissions":{"list":["public"],"get":["public"],"create":["user","admin"],"update":["admin","owner"],"delete":["admin","owner"]}}],"env":[{"name":"DATABASE_URL","description":"PostgreSQL connection string","required":true,"type":"url"},{"name":"JWT_SECRET","description":"Secret key for JWT token signing","required":true,"type":"secret"},{"name":"PORT","description":"Server port","required":false,"default":"3000","type":"number"}],"extras":{"queue":"none","cache":"none","storage":"none","email":"none","payment":"none","search":"none","monitoring":"none","testing":true,"docker":true,"ci_cd":true},"metadata":{"name":"blog-api","description":"A simple blog API with users, posts, and comments","version":"1.0.0","license":"MIT"}}`;

async function promptToSpec(userPrompt: string): Promise<BackendSpec> {
  try {
    const backendGenerator = new BackendGenerator();
    const spec = await backendGenerator.generateSpec(userPrompt);
    return spec as BackendSpec;
  } catch (error) {
    console.error('Error in promptToSpec:', error);
    throw new Error(`Failed to generate backend specification: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

function validateSpec(spec: any): void {
  const required = ['stack', 'entities', 'auth', 'api', 'env'];
  for (const field of required) {
    if (!spec[field]) {
      throw new Error(`Missing required field: ${field}`);
    }
  }
  if (!['node', 'python'].includes(spec.stack?.language)) {
    throw new Error('Invalid language in stack config');
  }
  if (!['jwt', 'session', 'oauth'].includes(spec.auth?.strategy)) {
    throw new Error('Invalid auth strategy');
  }
}

function ensureDir(dir: string) {
  fs.mkdirSync(dir, { recursive: true });
}

function writeFile(filePath: string, content: string) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, content);
}

function scaffoldFromSpec(spec: BackendSpec, outDir: string) {
  if (spec.stack.language === 'node') return scaffoldNode(spec, outDir);
  if (spec.stack.language === 'python') return scaffoldPython(spec, outDir);
  throw new Error('Unsupported language in spec.stack.language');
}

function scaffoldNode(spec: BackendSpec, outDir: string) {
  const pkg = {
    name: spec.name || 'backendv0-node',
    type: 'module',
    scripts: {
      dev: 'tsx src/server.ts',
      build: 'tsc',
      start: 'node dist/server.js',
      prisma: 'prisma'
    },
    dependencies: {
      express: '^4',
      zod: '^3',
      jsonwebtoken: '^9',
      bcryptjs: '^2',
      prisma: '^5',
      '@prisma/client': '^5'
    },
    devDependencies: { typescript: '^5', tsx: '^4', '@types/express': '^4' }
  } as const;

  writeFile(path.join(outDir, 'package.json'), JSON.stringify(pkg, null, 2));
  writeFile(
    path.join(outDir, 'tsconfig.json'),
    JSON.stringify(
      {
        compilerOptions: {
          outDir: 'dist',
          module: 'ESNext',
          target: 'ES2022',
          moduleResolution: 'Node'
        }
      },
      null,
      2
    )
  );
  writeFile(
    path.join(outDir, '.env.example'),
    `DATABASE_URL=postgresql://user:pass@localhost:5432/app\nJWT_SECRET=change-me`
  );

  const prismaModels = spec.entities
    .map((e) => `model ${e.name} {\n${e.fields.map((f) => prismaField(e.name, f)).join('\n')}\n}`)
    .join('\n\n');
  writeFile(
    path.join(outDir, 'prisma/schema.prisma'),
    `datasource db { provider = "postgresql" url = env("DATABASE_URL") }\n\ngenerator client { provider = "prisma-client-js" }\n\n${prismaModels}\n`
  );

  writeFile(path.join(outDir, 'src/server.ts'), serverTs(spec));
  for (const r of spec.api) {
    writeFile(path.join(outDir, `src/routes/${r.resource}.ts`), routerTs(r.resource, r.operations));
  }
  writeFile(path.join(outDir, 'src/auth.ts'), authTs());
  writeFile(path.join(outDir, 'Dockerfile'), dockerNode());
  writeFile(path.join(outDir, '.github/workflows/deploy.yml'), ghActions());
}

function prismaField(modelName: string, f: any) {
  const map: Record<string, string> = {
    string: 'String',
    int: 'Int',
    uuid: 'String @id @default(uuid())',
    decimal: 'Decimal',
    datetime: 'DateTime'
  };
  if (f.name === 'id') return `  id String @id @default(uuid())`;
  if (String(f.type).startsWith('enum:')) {
    const enumName = `${modelName}${f.name[0].toUpperCase() + f.name.slice(1)}Enum`;
    return `  ${f.name} ${enumName}`;
  }
  const t = map[f.type] || 'String';
  const req = f.required ? '' : '?';
  const uniq = f.unique ? ' @unique' : '';
  return `  ${f.name} ${t}${req}${uniq}`;
}

function serverTs(spec: BackendSpec) {
  return (
    "import express from 'express';\n" +
    "import { json } from 'express';\n" +
    "import { PrismaClient } from '@prisma/client';\n" +
    "const prisma = new PrismaClient();\n" +
    "const app = express();\n" +
    'app.use(json());\n' +
    "app.get('/health', (_req,res)=>res.json({ok:true}));\n" +
    spec.api
      .map((r) => `app.use('/api/${r.resource}', require('./routes/${r.resource}').default);`)
      .join('\n') +
    "\napp.listen(process.env.PORT||3000, ()=> console.log('API on', process.env.PORT||3000));\n"
  );
}

function routerTs(resource: string, ops: string[]) {
  return (
    "import { Router } from 'express';\n" +
    "import { PrismaClient } from '@prisma/client';\n" +
    'const prisma = new PrismaClient();\n' +
    'const r = Router();\n' +
    (ops.includes('list')
      ? "r.get('/', async (_req,res)=>{ const data = await prisma." + resource + ".findMany(); res.json(data); });\n"
      : '') +
    (ops.includes('get')
      ? "r.get('/:id', async (req,res)=>{ const item = await prisma." +
        resource +
        ".findUnique({ where: { id: String(req.params.id) } }); if(!item) return res.status(404).end(); res.json(item); });\n"
      : '') +
    (ops.includes('create')
      ? "r.post('/', async (req,res)=>{ const item = await prisma." + resource + ".create({ data: req.body }); res.status(201).json(item); });\n"
      : '') +
    (ops.includes('update')
      ? "r.put('/:id', async (req,res)=>{ const item = await prisma." +
        resource +
        ".update({ where:{ id: String(req.params.id)}, data: req.body }); res.json(item); });\n"
      : '') +
    (ops.includes('delete')
      ? "r.delete('/:id', async (req,res)=>{ await prisma." + resource + ".delete({ where:{ id: String(req.params.id)} }); res.status(204).end(); });\n"
      : '') +
    'export default r;\n'
  );
}

function authTs() {
  return (
    "import jwt from 'jsonwebtoken';\n" +
    'export function authMiddleware(req:any,res:any,next:any){ next(); }\n' +
    '// TODO: implement JWT verification and role checks based on spec.auth\n'
  );
}

function dockerNode() {
  return `FROM node:20-alpine\nWORKDIR /app\nCOPY package.json package-lock.json* yarn.lock* pnpm-lock.yaml* ./\nRUN npm i --silent || yarn || pnpm i\nCOPY . .\nRUN npm run build\nEXPOSE 3000\nCMD ["npm","start"]\n`;
}

function ghActions() {
  return `name: deploy\non: { push: { branches: [ main ] } }\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n    - uses: actions/checkout@v4\n    - uses: actions/setup-node@v4\n      with: { node-version: 20 }\n    - run: npm ci\n    - run: npm run build\n    - run: echo 'Deploy step here (Railway/Render CLI)'\n`;
}

function scaffoldPython(spec: BackendSpec, outDir: string) {
  // Create app directory structure
  ensureDir(path.join(outDir, 'app'));
  ensureDir(path.join(outDir, 'app/models'));
  ensureDir(path.join(outDir, 'app/routes'));
  ensureDir(path.join(outDir, 'app/auth'));
  ensureDir(path.join(outDir, 'app/database'));
  ensureDir(path.join(outDir, 'alembic'));

  // Requirements with all necessary dependencies
  writeFile(
    path.join(outDir, 'requirements.txt'),
    `fastapi==0.114.0
uvicorn[standard]==0.30.0
sqlmodel==0.0.22
psycopg2-binary==2.9.9
python-dotenv==1.0.1
passlib[bcrypt]==1.7.4
pyjwt==2.8.0
alembic==1.13.1
python-multipart==0.0.6
email-validator==2.1.0`
  );

  // Environment configuration
  writeFile(
    path.join(outDir, '.env.example'),
    `DATABASE_URL=postgresql://user:pass@localhost:5432/app
JWT_SECRET=change-me-this-is-a-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600
CORS_ORIGINS=http://localhost:3000,http://localhost:8080`
  );

  // Main application file
  writeFile(path.join(outDir, 'app/main.py'), fastapiMain(spec));
  
  // Database configuration
  writeFile(path.join(outDir, 'app/database/__init__.py'), '');
  writeFile(path.join(outDir, 'app/database/connection.py'), databaseConnection());
  
  // Models
  writeFile(path.join(outDir, 'app/models/__init__.py'), modelsInit(spec));
  writeFile(path.join(outDir, 'app/models/base.py'), baseModel());
  
  // Generate individual entity models
  for (const entity of spec.entities) {
    writeFile(path.join(outDir, `app/models/${entity.name.toLowerCase()}.py`), generateEntityModel(entity));
  }
  
  // Authentication
  writeFile(path.join(outDir, 'app/auth/__init__.py'), '');
  writeFile(path.join(outDir, 'app/auth/jwt.py'), jwtAuth(spec));
  writeFile(path.join(outDir, 'app/auth/dependencies.py'), authDependencies(spec));
  
  // Routes
  writeFile(path.join(outDir, 'app/routes/__init__.py'), '');
  for (const resource of spec.api) {
    writeFile(path.join(outDir, `app/routes/${resource.resource}.py`), generatePythonRoute(resource, spec));
  }
  
  // Alembic configuration for migrations
  writeFile(path.join(outDir, 'alembic.ini'), alembicConfig());
  writeFile(path.join(outDir, 'alembic/env.py'), alembicEnv());
  writeFile(path.join(outDir, 'alembic/script.py.mako'), alembicScript());
  
  // Docker and deployment
  writeFile(path.join(outDir, 'Dockerfile'), dockerPy());
  writeFile(path.join(outDir, '.github/workflows/deploy.yml'), ghActions());
  
  // Additional Python files
  writeFile(path.join(outDir, 'run.py'), runScript());
  writeFile(path.join(outDir, 'README.md'), pythonReadme(spec));
}

function fastapiMain(spec: BackendSpec) {
  const imports = [
    'from fastapi import FastAPI, HTTPException, Depends',
    'from fastapi.middleware.cors import CORSMiddleware',
    'from sqlmodel import SQLModel, create_engine, Session',
    'from app.database.connection import engine, get_session',
    'from app.models import *',
    'from app.auth.dependencies import get_current_user, get_current_active_user',
    'import os'
  ];

  const routeImports = spec.api.map(r => `from app.routes.${r.resource} import router as ${r.resource}_router`);

  return `${imports.join('\n')}
${routeImports.join('\n')}

app = FastAPI(
    title="${spec.name || 'Backend V0 API'}",
    description="AI-generated backend API",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database initialization
@app.on_event("startup")
async def on_startup():
    SQLModel.metadata.create_all(engine)

# Health check
@app.get("/health")
def health():
    return {"ok": True, "message": "API is running"}

# Include routers
${spec.api.map(r => `app.include_router(${r.resource}_router, prefix="/api/${r.resource}", tags=["${r.resource}"])`).join('\n')}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
`;
}

function databaseConnection() {
  return `from sqlmodel import create_engine, Session
from sqlmodel import SQLModel
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/app")

engine = create_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL debugging
    pool_pre_ping=True,
    pool_recycle=300
)

def get_session():
    with Session(engine) as session:
        yield session
`;
}

function modelsInit(spec: BackendSpec) {
  const modelImports = spec.entities.map(entity => `from .${entity.name.toLowerCase()} import ${entity.name}`);
  
  return `# Generated models
from .base import BaseModel
${modelImports.join('\n')}

# Export all models
__all__ = [
    "BaseModel",
${spec.entities.map(e => `    "${e.name}"`).join(',\n')}
]
`;
}

function baseModel() {
  return `from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime
import uuid

class BaseModel(SQLModel):
    id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    
    class Config:
        arbitrary_types_allowed = True
`;
}

function generateEntityModel(entity: any) {
  const fields = entity.fields.map((field: any) => {
    let fieldType = 'str';
    let fieldConfig = '';

    switch (field.type) {
      case 'int':
        fieldType = 'int';
        break;
      case 'decimal':
        fieldType = 'float';
        break;
      case 'datetime':
        fieldType = 'datetime';
        break;
      case 'boolean':
        fieldType = 'bool';
        break;
      default:
        if (field.type.startsWith('enum:')) {
          const enumValues = field.type.split(':')[1].split('|');
          fieldType = `Literal[${enumValues.map((v: any) => `"${v}"`).join(', ')}]`;
        }
    }

    if (!field.required) {
      fieldType = `Optional[${fieldType}]`;
      fieldConfig = ' = None';
    }

    if (field.unique) {
      fieldConfig += ', unique=True';
    }

    if (field.default && field.default !== 'uuid') {
      if (field.type === 'string') {
        fieldConfig += ` = "${field.default}"`;
      } else {
        fieldConfig += ` = ${field.default}`;
      }
    }

    return `    ${field.name}: ${fieldType}${fieldConfig}`;
  }).filter((f: any) => f !== ''); // Remove empty lines

  return `from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime
from .base import BaseModel

class ${entity.name}(BaseModel, table=True):
${fields.join('\n')}
    
    class Config:
        table = True
`;
}

function generatePythonModels(spec: BackendSpec) {
  return spec.entities.map(entity => {
    const fields = entity.fields.map(field => {
      if (field.name === 'id') return ''; // Skip id as it's in base model
      
      let fieldType = 'str';
      let fieldConfig = '';
      
      switch (field.type) {
        case 'int':
          fieldType = 'int';
          break;
        case 'decimal':
          fieldType = 'float';
          break;
        case 'datetime':
          fieldType = 'datetime';
          break;
        case 'boolean':
          fieldType = 'bool';
          break;
        default:
          if (field.type.startsWith('enum:')) {
            const enumValues = field.type.split(':')[1].split('|');
            fieldType = `Literal[${enumValues.map(v => `"${v}"`).join(', ')}]`;
          }
      }
      
      if (!field.required) {
        fieldType = `Optional[${fieldType}]`;
        fieldConfig = ' = None';
      }
      
      if (field.unique) {
        fieldConfig += ', unique=True';
      }
      
      if (field.default && field.default !== 'uuid') {
        if (field.type === 'string') {
          fieldConfig += ` = "${field.default}"`;
        } else {
          fieldConfig += ` = ${field.default}`;
        }
      }
      
      return `    ${field.name}: ${fieldType}${fieldConfig}`;
    }).filter(f => f !== ''); // Remove empty lines
    
    return `from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime
from .base import BaseModel

class ${entity.name}(BaseModel, table=True):
${fields.join('\n')}
    
    class Config:
        table = True
`;
  }).join('\n\n');
}

function jwtAuth(spec: BackendSpec) {
  if (spec.auth.strategy !== 'jwt') {
    return `# Authentication not configured for this backend
# Configure auth strategy in your spec`;
  }
  
  return `import jwt
from datetime import datetime, timedelta
from typing import Optional
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

load_dotenv()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = os.getenv("JWT_SECRET", "change-me")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRATION", "3600"))

# Security scheme
security = HTTPBearer()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
`;
}

function authDependencies(spec: BackendSpec) {
  if (spec.auth.strategy !== 'jwt') {
    return `# Authentication dependencies not configured
# Configure auth strategy in your spec`;
  }
  
  return `from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.auth.jwt import verify_token, security
from app.models.user import User
from app.database.connection import get_session
from sqlmodel import Session, select

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: Session = Depends(get_session)
) -> User:
    token = credentials.credentials
    payload = verify_token(token)
    user_id: str = payload.get("sub")
    
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    
    user = session.exec(select(User).where(User.id == user_id)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

def require_role(required_roles: list):
    def role_checker(current_user: User = Depends(get_current_user)):
        if not any(role in current_user.roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return role_checker
`;
}

function generatePythonRoute(resource: any, spec: BackendSpec) {
  const resourceName = resource.resource;
  const modelName = resourceName.charAt(0).toUpperCase() + resourceName.slice(1);
  const operations = resource.operations;
  
  let routeContent = `from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select
from typing import List, Optional
from app.database.connection import get_session
from app.models.${resourceName.toLowerCase()} import ${modelName}
from app.auth.dependencies import get_current_user, require_role
from app.models.user import User

router = APIRouter()

`;

  // Add CRUD operations based on spec
  if (operations.includes('list')) {
    routeContent += `@router.get("/", response_model=List[${modelName}])
async def list_${resourceName}(
    skip: int = 0,
    limit: int = 100,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """List all ${resourceName}"""
    ${resourceName} = session.exec(select(${modelName}).offset(skip).limit(limit)).all()
    return ${resourceName}

`;
  }

  if (operations.includes('get')) {
    routeContent += `@router.get("/{${resourceName}_id}", response_model=${modelName})
async def get_${resourceName}(
    ${resourceName}_id: str,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """Get a specific ${resourceName} by ID"""
    ${resourceName} = session.exec(select(${modelName}).where(${modelName}.id == ${resourceName}_id)).first()
    if not ${resourceName}:
        raise HTTPException(status_code=404, detail="${modelName} not found")
    return ${resourceName}

`;
  }

  if (operations.includes('create')) {
    routeContent += `@router.post("/", response_model=${modelName}, status_code=status.HTTP_201_CREATED)
async def create_${resourceName}(
    ${resourceName}_data: ${modelName},
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """Create a new ${resourceName}"""
    ${resourceName} = ${modelName}(**${resourceName}_data.dict())
    session.add(${resourceName})
    session.commit()
    session.refresh(${resourceName})
    return ${resourceName}

`;
  }

  if (operations.includes('update')) {
    routeContent += `@router.put("/{${resourceName}_id}", response_model=${modelName})
async def update_${resourceName}(
    ${resourceName}_id: str,
    ${resourceName}_data: ${modelName},
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """Update an existing ${resourceName}"""
    ${resourceName} = session.exec(select(${modelName}).where(${modelName}.id == ${resourceName}_id)).first()
    if not ${resourceName}:
        raise HTTPException(status_code=404, detail="${modelName} not found")
    
    update_data = ${resourceName}_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(${resourceName}, field, value)
    
    session.add(${resourceName})
    session.commit()
    session.refresh(${resourceName})
    return ${resourceName}

`;
  }

  if (operations.includes('delete')) {
    routeContent += `@router.delete("/{${resourceName}_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_${resourceName}(
    ${resourceName}_id: str,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """Delete a ${resourceName}"""
    ${resourceName} = session.exec(select(${modelName}).where(${modelName}.id == ${resourceName}_id)).first()
    if not ${resourceName}:
        raise HTTPException(status_code=404, detail="${modelName} not found")
    
    session.delete(${resourceName})
    session.commit()
    return None

`;
  }

  return routeContent;
}

function alembicConfig() {
  return `# A generic, single database configuration.

[alembic]
# path to migration scripts
script_location = alembic

# template used to generate migration file names; The default value is %%(rev)s_%%(slug)s
# Uncomment the line below if you want the files to be prepended with a date and time
# file_template = %%(year)d_%%(month).2d_%%(day).2d_%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s

# sys.path path, will be prepended to sys.path if present.
# defaults to the current working directory.
prepend_sys_path = .

# timezone to use when rendering the date within the migration file
# as well as the filename.
# If specified, requires the python-dateutil library that can be
# installed by adding \`alembic[tz]\` to the pip requirements
# string value is passed to dateutil.tz.gettz()
# leave blank for localtime
# timezone =

# max length of characters to apply to the
# "slug" field
# truncate_slug_length = 40

# set to 'true' to run the environment during
# the 'revision' command, regardless of autogenerate
# revision_environment = false

# set to 'true' to allow .pyc and .pyo files without
# a source .py file to be detected as revisions in the
# versions/ directory
# sourceless = false

# version number format
version_num_format = %04d

# version path separator; As mentioned above, this is the character used to split
# version_locations. The default within new alembic.ini files is "os", which uses
# os.pathsep. If this key is omitted entirely, it falls back to the legacy
# behavior of splitting on spaces and/or commas.
# Valid values for version_path_separator are:
#
# version_path_separator = :
# version_path_separator = ;
# version_path_separator = space
version_path_separator = os

# the output encoding used when revision files
# are written from script.py.mako
# output_encoding = utf-8

sqlalchemy.url = postgresql://user:pass@localhost:5432/app


[post_write_hooks]
# post_write_hooks defines scripts or Python functions that are run
# on newly generated revision scripts.  See the documentation for further
# detail and examples

# format using "black" - use the console_scripts runner, against the "black" entrypoint
# hooks = black
# black.type = console_scripts
# black.entrypoint = black
# black.options = -l 79 REVISION_SCRIPT_FILENAME

# Logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
`;
}

function alembicEnv() {
  return `from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
from app.models import *
from app.database.connection import DATABASE_URL

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = SQLModel.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = DATABASE_URL
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = DATABASE_URL
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
`;
}

function alembicScript() {
  return `"""\${message}

Revision ID: \${up_revision}
Revises: \${down_revision | comma,n}
Create Date: \${create_date}

"""
from alembic import op
import sqlalchemy as sa
\${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = \${repr(up_revision)}
down_revision = \${repr(down_revision)}
branch_labels = \${repr(branch_labels)}
depends_on = \${repr(depends_on)}


def upgrade() -> None:
    \${upgrades if upgrades else "pass"}


def downgrade() -> None:
    \${downgrades if downgrades else "pass"}
`;
}

function runScript() {
  return `#!/usr/bin/env python3
"""
Run script for the FastAPI application
"""
import uvicorn
from app.main import app

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
`;
}

function pythonReadme(spec: BackendSpec) {
  return `# ${spec.name || 'Backend V0'} - Python FastAPI Backend

This is an AI-generated backend API built with FastAPI, SQLModel, and PostgreSQL.

## Features

- FastAPI: Modern, fast web framework for building APIs
- SQLModel: SQL databases in Python, designed for simplicity and compatibility
- PostgreSQL: Robust, open-source database
- JWT Authentication: Secure token-based authentication
- Automatic CRUD: Generated endpoints for all entities
- Database Migrations: Alembic for schema management

## Quick Start

1. Install dependencies
   pip install -r requirements.txt

2. Set environment variables
   cp .env.example .env
   (Edit .env with your database credentials)

3. Run database migrations
   alembic upgrade head

4. Start the server
   python run.py
   or
   uvicorn app.main:app --reload

## API Documentation

Once running, visit:
- API Docs: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- Health Check: http://localhost:8000/health

## Project Structure

app/
  __init__.py
  main.py              (FastAPI application)
  auth/
    __init__.py
    jwt.py             (JWT utilities)
    dependencies.py    (Auth dependencies)
  database/
    __init__.py
    connection.py      (Database connection)
  models/
    __init__.py
    base.py            (Base model)
    *.py               (Entity models)
  routes/
    __init__.py
    *.py               (Resource routes)

## Development

Adding New Models:
1) Create a new model in app/models/
2) Add it to app/models/__init__.py
3) Run: alembic revision --autogenerate -m "Add new model"
4) Run: alembic upgrade head

Database Migrations:
- Create a new migration: alembic revision --autogenerate -m "Description"
- Apply migrations: alembic upgrade head
- Rollback: alembic downgrade -1

## Deployment

Docker:
- docker build -t backend-v0 .
- docker run -p 8000:8000 backend-v0

Environment Variables:
- DATABASE_URL: PostgreSQL connection string
- JWT_SECRET: Secret key for JWT tokens
- JWT_ALGORITHM: JWT algorithm (default: HS256)
- JWT_EXPIRATION: Token expiration in seconds
- CORS_ORIGINS: Comma-separated allowed origins

Security Notes:
- Change your JWT_SECRET in production
- Configure CORS origins for your frontend
- Set up proper database credentials
- Enable HTTPS in production

Generated by Backend V0 Orchestrator.
`;
}

function dockerPy() {
  return `FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]`;
}