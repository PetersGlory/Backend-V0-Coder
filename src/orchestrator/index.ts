import 'dotenv/config';
import express from 'express';
import type { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import { pipeline } from "@huggingface/transformers";
import fs from 'fs';
import path from 'path';
import { BackendSpec, GenerationRequest, GenerationResponse, ScaffoldRequest, ScaffoldResponse } from '../types/index.js';

// Initialize the local transformer pipeline
let generator: any = null;

async function initializeGenerator() {
  try {
    console.log('Initializing local transformer pipeline...');
    generator = await pipeline('text-generation',
  'Xenova/Qwen1.5-0.5B-Chat');
    console.log('Local transformer pipeline initialized successfully');
  } catch (error) {
    console.error('Failed to initialize local transformer pipeline:', error);
    throw error;
  }
}

const systemPrompt = `You are BackendV0, an expert backend architect and code generator.
Given a natural-language request, produce a STRICT JSON spec describing:
- stack: {language: "node|python", framework, database, orm}
- entities: array of {name, fields: [{name, type, required, unique, default}]}
- auth: {strategy: "jwt|session|oauth", roles?: string[]}
- api: array of {resource, operations: ["list","get","create","update","delete"], relations?}
- env: array of required environment variables (UPPER_SNAKE_CASE) with descriptions
- extras?: {queue?, cache?, storage?, thirdParty?: string[]}
Return ONLY minified JSON. No prose.`;

async function promptToSpec(userPrompt: string): Promise<BackendSpec> {
  if (!generator) {
    throw new Error('Local transformer pipeline not initialized');
  }

  try {
    const fullPrompt = `${systemPrompt}\n\nUSER:\n${userPrompt}`;
    const output = await generator(fullPrompt, {
      max_new_tokens: 512,
      temperature: 0.1
    });
    
    const generatedText = output[0].generated_text;
    const match = generatedText.match(/\{[\s\S]*\}/);
    
    if (!match) {
      throw new Error('No valid JSON found in generated response');
    }
    
    const spec = JSON.parse(match[0].trim()) as BackendSpec;
    validateSpec(spec);
    return spec;
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
  writeFile(
    path.join(outDir, 'requirements.txt'),
    `fastapi==0.114.0\nuvicorn[standard]==0.30.0\nsqlmodel==0.0.22\npsycopg2-binary==2.9.9\npython-dotenv==1.0.1\npasslib[bcrypt]==1.7.4\npyjwt==2.8.0`
  );
  writeFile(
    path.join(outDir, '.env.example'),
    `DATABASE_URL=postgresql://user:pass@localhost:5432/app\nJWT_SECRET=change-me`
  );
  writeFile(path.join(outDir, 'app/main.py'), fastapiMain(spec));
  writeFile(path.join(outDir, 'Dockerfile'), dockerPy());
  writeFile(path.join(outDir, '.github/workflows/deploy.yml'), ghActions());
}

function fastapiMain(spec: BackendSpec) {
  return (
    "from fastapi import FastAPI, HTTPException\n" +
    'from sqlmodel import SQLModel, create_engine, Session, select\n' +
    'import os\n' +
    'app = FastAPI()\n' +
    "engine = create_engine(os.getenv('DATABASE_URL'))\n\n" +
    'class Health(SQLModel, table=False):\n' +
    '    ok: bool = True\n\n' +
    "@app.on_event('startup')\n" +
    'def on_startup():\n' +
    '    SQLModel.metadata.create_all(engine)\n\n' +
    "@app.get('/health')\n" +
    'def health():\n' +
    "    return { 'ok': True }\n\n" +
    '# TODO: generate models and CRUD from spec.entities and spec.api\n'
  );
}

function dockerPy() {
  return `FROM python:3.11-slim\nWORKDIR /app\nCOPY requirements.txt .\nRUN pip install --no-cache-dir -r requirements.txt\nCOPY . .\nEXPOSE 8000\nCMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]\n`;
}

// HTTP server
const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(helmet());
app.use(compression());
app.use(morgan('dev'));
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_req: Request, res: Response) => res.json({ ok: true }));

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
    // Initialize the local transformer pipeline first
    await initializeGenerator();
    
    // Start the HTTP server
    app.listen(port, () => {
      console.log(`Orchestrator listening on http://localhost:${port}`);
      console.log('Local transformer pipeline is ready for backend generation');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
