# Backend V0 — MVP Kit (Python + Node.js + Hugging Face)

A practical starter to build an AI-powered backend generator like Vercel’s V0, focused on **Node.js** and **Python** scaffolds, with **Hugging Face** models for code generation.

---

## 1) High-Level Architecture

```text
┌────────────────────────────┐
│  Web UI / CLI (Prompt)     │
└──────────────┬─────────────┘
               │ Prompt
               ▼
┌────────────────────────────┐
│  Orchestrator Service      │  (Node.js)
│  - System prompts          │
│  - Prompt → Plan → Files   │
│  - Safety/validation       │
└──────────────┬─────────────┘
               │ Inference
               ▼
┌────────────────────────────┐
│  HF Inference API / TGI    │  (StarCoder2/Mixtral/Code Llama)
└──────────────┬─────────────┘
               │ Spec/Code
               ▼
┌────────────────────────────┐
│  Scaffolding Engine        │
│  - Templates (Node/Python) │
│  - File writers            │
│  - Post-gen fixes (lint)   │
└──────────────┬─────────────┘
               │ Output repo
               ▼
┌────────────────────────────┐
│  CI/CD + Deploy            │ (Railway/Render/Fly/Vercel Functions)
└────────────────────────────┘
```

**MVP Scope:**

* Input → JSON “Backend Spec” → Scaffold files → Run formatter/tests → Zip/Push to GitHub → 1-click deploy.
* Generators: **Node (Express + Prisma + Postgres)**, **Python (FastAPI + SQLModel + Postgres)**.

---

## 2) Prompting Strategy

**System Prompt (Orchestrator → Model):**

```
You are BackendV0, an expert backend architect and code generator.
Given a natural-language request, produce a STRICT JSON spec describing:
- stack: {language: "node|python", framework, database, orm}
- entities: array of {name, fields: [{name, type, required, unique, default}]}
- auth: {strategy: "jwt|session|oauth", roles?: string[]}
- api: array of {resource, operations: ["list","get","create","update","delete"], relations?}
- env: array of required environment variables (UPPER_SNAKE_CASE) with descriptions
- extras?: {queue?, cache?, storage?, thirdParty?: string[]}
Return ONLY minified JSON. No prose.
```

**User Prompt (example):**

```
Build a thrift contribution backend with weekly rotation. Use Node.js (TypeScript), Express, Prisma, and PostgreSQL.
Entities: User, ThriftGroup, Contribution, Payout.
Auth: JWT roles (admin, member). Expose REST endpoints.
```

**Model Output (example, abbreviated):**

```json
{"stack":{"language":"node","framework":"express","database":"postgres","orm":"prisma"},
 "entities":[{"name":"User","fields":[{"name":"id","type":"uuid","required":true,"unique":true,"default":"uuid"},{"name":"email","type":"string","required":true,"unique":true},{"name":"passwordHash","type":"string","required":true},{"name":"role","type":"enum:admin|member","required":true,"default":"member"}]},
 {"name":"ThriftGroup","fields":[{"name":"id","type":"uuid","required":true,"unique":true,"default":"uuid"},{"name":"name","type":"string","required":true},{"name":"cycleWeeks","type":"int","required":true}]},
 {"name":"Contribution","fields":[{"name":"id","type":"uuid","required":true,"unique":true,"default":"uuid"},{"name":"userId","type":"uuid","required":true},{"name":"groupId","type":"uuid","required":true},{"name":"amount","type":"decimal","required":true},{"name":"week","type":"int","required":true}]},
 {"name":"Payout","fields":[{"name":"id","type":"uuid","required":true,"unique":true,"default":"uuid"},{"name":"groupId","type":"uuid","required":true},{"name":"userId","type":"uuid","required":true},{"name":"scheduledAt","type":"datetime","required":true}]}],
 "auth":{"strategy":"jwt","roles":["admin","member"]},
 "api":[{"resource":"users","operations":["list","get","create","update","delete"]},{"resource":"groups","operations":["list","get","create","update","delete"]},{"resource":"contributions","operations":["list","get","create","update","delete"]},{"resource":"payouts","operations":["list","get","create","update","delete"]}],
 "env":["DATABASE_URL","JWT_SECRET"],
 "extras":{"cache":"redis"}}
```

---

## 3) Orchestrator (Node.js) — minimal implementation

````ts
// orchestrator/index.ts
import axios from "axios";
import fs from "fs";
import path from "path";
import { execSync } from "child_process";

const HF_API_URL = "https://api-inference.huggingface.co/models/bigcode/starcoder2-15b"; // or TGI endpoint
const HF_TOKEN = process.env.HF_TOKEN!;

const system = `You are BackendV0, an expert backend architect and code generator... (same as above)`;

export async function promptToSpec(userPrompt: string) {
  const body = { inputs: `${system}\n\nUSER:\n${userPrompt}`, parameters: { max_new_tokens: 1024 } };
  const res = await axios.post(HF_API_URL, body, { headers: { Authorization: `Bearer ${HF_TOKEN}` } });
  const text = Array.isArray(res.data) ? res.data[0]?.generated_text ?? "" : String(res.data);
  const json = text.trim().replace(/^```json|```/g, "");
  return JSON.parse(json);
}

export function scaffoldFromSpec(spec: any, outDir: string) {
  if (spec.stack.language === "node") return scaffoldNode(spec, outDir);
  if (spec.stack.language === "python") return scaffoldPython(spec, outDir);
  throw new Error("Unsupported language");
}

function write(file: string, content: string) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

// --- Node template (Express + Prisma + Postgres) ---
function scaffoldNode(spec: any, outDir: string) {
  const pkg = {
    name: spec.name || "backendv0-node",
    type: "module",
    scripts: {
      dev: "tsx src/server.ts",
      build: "tsc",
      start: "node dist/server.js",
      prisma: "prisma"
    },
    dependencies: {
      express: "^4",
      zod: "^3",
      jsonwebtoken: "^9",
      bcryptjs: "^2",
      prisma: "^5",
      "@prisma/client": "^5"
    },
    devDependencies: { typescript: "^5", tsx: "^4", "@types/express": "^4" }
  };

  write(path.join(outDir, "package.json"), JSON.stringify(pkg, null, 2));
  write(path.join(outDir, "tsconfig.json"), JSON.stringify({ compilerOptions: { outDir: "dist", module: "ESNext", target: "ES2022", moduleResolution: "Node" } }, null, 2));
  write(path.join(outDir, ".env.example"), `DATABASE_URL=postgresql://user:pass@localhost:5432/app\nJWT_SECRET=change-me`);

  // Prisma schema from entities
  const prismaModels = spec.entities.map((e: any) => `model ${e.name} {\n${e.fields.map((f: any) => prismaField(e.name,f)).join("\n")}\n}`).join("\n\n");
  write(path.join(outDir, "prisma/schema.prisma"), `datasource db { provider = "postgresql" url = env("DATABASE_URL") }\n\ngenerator client { provider = "prisma-client-js" }\n\n${prismaModels}\n`);

  // Basic server
  write(path.join(outDir, "src/server.ts"), serverTs(spec));
  // Routers per resource
  for (const r of spec.api) {
    write(path.join(outDir, `src/routes/${r.resource}.ts`), routerTs(r.resource, r.operations));
  }
  // Auth
  write(path.join(outDir, "src/auth.ts"), authTs());

  // Docker & CI
  write(path.join(outDir, "Dockerfile"), dockerNode());
  write(path.join(outDir, ".github/workflows/deploy.yml"), ghActions());
}

function prismaField(modelName: string, f: any) {
  // Map types
  const map: Record<string,string> = { string: "String", int: "Int", uuid: "String @id @default(uuid())", decimal: "Decimal", datetime: "DateTime" };
  if (f.name === "id") return `  id String @id @default(uuid())`;
  if (f.type.startsWith("enum:")) {
    const enumName = `${modelName}${f.name[0].toUpperCase()+f.name.slice(1)}Enum`;
    return `  ${f.name} ${enumName}`;
  }
  const t = map[f.type] || "String";
  const req = f.required ? "" : "?";
  const uniq = f.unique ? " @unique" : "";
  return `  ${f.name} ${t}${req}${uniq}`;
}

function serverTs(spec: any) {
  return `import express from 'express';\nimport { json } from 'express';\nimport { authMiddleware } from './auth';\nimport { PrismaClient } from '@prisma/client';\nconst prisma = new PrismaClient();\nconst app = express();\napp.use(json());\napp.get('/health', (_req,res)=>res.json({ok:true}));\n${spec.api.map((r: any)=>`app.use('/api/${r.resource}', require('./routes/${r.resource}').default);`).join('\n')}\napp.listen(process.env.PORT||3000, ()=> console.log('API on', process.env.PORT||3000));\n`;
}

function routerTs(resource: string, ops: string[]) {
  return `import { Router } from 'express';\nimport { PrismaClient } from '@prisma/client';\nconst prisma = new PrismaClient();\nconst r = Router();\n${ops.includes("list") ? `r.get('/', async (_req,res)=>{ const data = await prisma.${resource}.findMany(); res.json(data); });` : ''}\n${ops.includes("get") ? `r.get('/:id', async (req,res)=>{ const item = await prisma.${resource}.findUnique({ where: { id: String(req.params.id) } }); if(!item) return res.status(404).end(); res.json(item); });` : ''}\n${ops.includes("create") ? `r.post('/', async (req,res)=>{ const item = await prisma.${resource}.create({ data: req.body }); res.status(201).json(item); });` : ''}\n${ops.includes("update") ? `r.put('/:id', async (req,res)=>{ const item = await prisma.${resource}.update({ where:{ id: String(req.params.id)}, data: req.body }); res.json(item); });` : ''}\n${ops.includes("delete") ? `r.delete('/:id', async (req,res)=>{ await prisma.${resource}.delete({ where:{ id: String(req.params.id)} }); res.status(204).end(); });` : ''}\nexport default r;\n`;
}

function authTs() {
  return `import jwt from 'jsonwebtoken';\nexport function authMiddleware(req:any,res:any,next:any){ next(); }\n// TODO: implement JWT verification and role checks based on spec.auth\n`;
}

function dockerNode() {
  return `FROM node:20-alpine\nWORKDIR /app\nCOPY package.json package-lock.json* yarn.lock* pnpm-lock.yaml* ./\nRUN npm i --silent || yarn || pnpm i\nCOPY . .\nRUN npm run build\nEXPOSE 3000\nCMD ["npm","start"]\n`;
}

function ghActions() {
  return `name: deploy\non: { push: { branches: [ main ] } }\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n    - uses: actions/checkout@v4\n    - uses: actions/setup-node@v4\n      with: { node-version: 20 }\n    - run: npm ci\n    - run: npm run build\n    - run: echo 'Deploy step here (Railway/Render CLI)'
`;
}

// --- Python template (FastAPI + SQLModel + Postgres) ---
function scaffoldPython(spec: any, outDir: string) {
  write(path.join(outDir, "requirements.txt"), `fastapi==0.114.0\nuvicorn[standard]==0.30.0\nsqlmodel==0.0.22\npsycopg2-binary==2.9.9\npython-dotenv==1.0.1\npasslib[bcrypt]==1.7.4\npyjwt==2.8.0`);
  write(path.join(outDir, ".env.example"), `DATABASE_URL=postgresql://user:pass@localhost:5432/app\nJWT_SECRET=change-me`);
  write(path.join(outDir, "app/main.py"), fastapiMain(spec));
  write(path.join(outDir, "Dockerfile"), dockerPy());
  write(path.join(outDir, ".github/workflows/deploy.yml"), ghActions());
}

function fastapiMain(spec: any) {
  return `from fastapi import FastAPI, HTTPException\nfrom sqlmodel import SQLModel, create_engine, Session, select\nimport os\napp = FastAPI()\nengine = create_engine(os.getenv('DATABASE_URL'))\n\nclass Health(SQLModel, table=False):\n    ok: bool = True\n\n@app.on_event('startup')\ndef on_startup():\n    SQLModel.metadata.create_all(engine)\n\n@app.get('/health')\ndef health():\n    return { 'ok': True }\n\n# TODO: generate models and CRUD from spec.entities and spec.api\n`;
}

function dockerPy() {
  return `FROM python:3.11-slim\nWORKDIR /app\nCOPY requirements.txt .\nRUN pip install --no-cache-dir -r requirements.txt\nCOPY . .\nEXPOSE 8000\nCMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]\n`;
}
````

---

## 4) CLI to Run the MVP

```bash
# 1) Orchestrate spec from a prompt
export HF_TOKEN=your_hf_token
node -e "import('./orchestrator/index.ts').then(async m=>{const spec=await m.promptToSpec(process.argv.slice(1).join(' ')); console.log(JSON.stringify(spec,null,2)); await m.scaffoldFromSpec(spec,'./out');})" "Build a FastAPI CRUD for Books and Authors with JWT auth and Postgres"

# 2) Install & run (Node scaffold example)
cd out
npm i
npx prisma generate
npm run dev
```

---

## 5) Post-Generation Validation (MVP)

* Run `eslint`/`prettier` (Node) and `ruff`/`black` (Python).
* Spin a container and run a quick `health` probe + `supertest`/`pytest` smoke.
* Ensure envs exist; generate `.env.example` from `spec.env`.

```bash
# Node quick checks
npm i -D eslint prettier @typescript-eslint/parser @typescript-eslint/eslint-plugin
npx eslint src --fix || true
npx prettier -w .
```

---

## 6) Security & Safety (Essentials)

* **Secrets**: never inline secrets in generated code; require envs.
* **Auth**: if `spec.auth.strategy === 'jwt'`, include middleware skeleton + role checks.
* **Validation**: generate DTO schemas (Zod / Pydantic) and validate `req.body`.
* **DB**: principle of least privilege; generate migrations; avoid `any` types.
* **Network**: CORS defaults locked to caller origin, configurable via env.

---

## 7) Deployment Options

* **Railway**: simplest DX; use Railway CLI in GH Actions.
* **Render**: Web Service (Docker) + Postgres.
* **Fly.io**: global Postgres, Machines for API.
* **Vercel Functions**: ok for light FastAPI via `vercel-python` or Node serverless adapters.

Provide a `deploy.yml` with a placeholder step; swap in the provider CLI.

---

## 8) Extending Beyond MVP

* **Spec dialect**: support OpenAPI import/export.
* **Generators**: NestJS, Django REST, GraphQL, WebSockets, Celery/BullMQ.
* **Integrations**: Stripe, SendGrid, Twilio, S3, Redis cache queue.
* **Self-hosted models**: TGI on A10/A100 for low-latency generation.
* **Fine-tuning**: curate a dataset of high-quality backends; RL from lint/test feedback.

---

## 9) Quick Notes on Hugging Face Setup

* Start with **StarCoder2-15B** or **Mixtral 8x7B Instruct** via Inference API.
* For production, deploy **Text Generation Inference (TGI)** behind your orchestrator.
* Add a retry/backoff and max tokens; force JSON via instructions and post-validate.

---

## 10) Next Actions

1. Implement the `orchestrator/index.ts` with real HTTP server (Express) and endpoints:

   * `POST /spec` → { prompt } → JSON spec
   * `POST /scaffold` → { spec } → zip file / repo URL
2. Add Node + Python file writers for models/CRUD from `entities` and `api`.
3. Wire a simple Web UI to submit prompts and download the generated repo.

> This doc is your working blueprint plus drop-in code you can start executing today. Replace placeholders as needed and iterate. ✅
