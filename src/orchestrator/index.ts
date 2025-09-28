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
import session from 'express-session';
import { History, syncDatabase } from '../models/index.js';
import authRoutes from '../routes/auth.js';
import historyRoutes from '../routes/history.js';
import pricingRoutes from '../routes/pricing.js';
import { optionalAuth } from '../middleware/auth.js';
import { enforceUsageLimit } from '../middleware/subscription.js';

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
      required: z.boolean().default(true),
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
        const spec = await this.callGemini(prompt, 8192);
        
        // Validate the generated spec
        const validated = SpecSchema.parse(spec);

        // Ensure comprehensive coverage for complex prompts
        if (!this.isSpecComprehensive(validated, prompt)) {
          const expansionPrompt = this.buildExpansionPrompt(prompt, validated);
          const expanded = await this.callGemini(expansionPrompt, 8192);
          const expandedValidated = SpecSchema.parse(expanded);
          return expandedValidated;
        }
        return validated;
      } catch (error) {
        console.error(`Attempt ${attempt + 1} failed:`, error);
        
        // If it's a JSON parsing error, try with a simpler prompt
        if (error instanceof Error && error.message.includes('JSON')) {
          console.log('JSON parsing error detected, trying with simplified prompt...');
          try {
            const simplePrompt = `Generate a simple but COMPLETE backend specification for: ${prompt}. Return only valid JSON. Include ALL entities, routes, and env keys mentioned.`;
            const spec = await this.callGemini(simplePrompt, 4096);
            const validated = SpecSchema.parse(spec);
            if (!this.isSpecComprehensive(validated, prompt)) {
              const expansionPrompt = this.buildExpansionPrompt(prompt, validated);
              const expanded = await this.callGemini(expansionPrompt, 8192);
              const expandedValidated = SpecSchema.parse(expanded);
              return expandedValidated;
            }
            return validated;
          } catch (simpleError) {
            console.error('Simple prompt also failed:', simpleError);
          }
        }
        
        if (attempt === retries - 1) {
          throw new Error('All attempts failed to generate valid specification');
        }
      }
    }
    
    throw new Error('All attempts failed to generate valid specification');
  }
  
  private async callGemini(prompt: string, maxTokens: number = 4096): Promise<any> {
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
          maxOutputTokens: Math.min(Math.max(1024, maxTokens), 8192),
        }
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Gemini API Error:', response.status, response.statusText);
      console.error('Error details:', errorText);
      throw new Error(`Gemini API Error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const generatedText = data.candidates?.[0]?.content?.parts?.[0]?.text;
    
    if (!generatedText) {
      console.error('Gemini API response:', JSON.stringify(data, null, 2));
      throw new Error('Gemini API returned no text');
    }

    console.log('Raw Gemini response:', generatedText.substring(0, 500) + '...');

    // Clean and parse the response
    const cleanedText = this.cleanJsonResponse(generatedText);
    console.log('Cleaned JSON:', cleanedText.substring(0, 500) + '...');
    
    try {
      return JSON.parse(cleanedText);
    } catch (parseError) {
      console.error('Final JSON parsing failed:', parseError);
      console.error('Cleaned text (first 1000 chars):', cleanedText.substring(0, 1000));
      
      // Return fallback spec if all else fails
      console.log('Using fallback specification due to parsing error');
      return this.createFallbackSpec();
    }
  }

  private isSpecComprehensive(spec: any, originalPrompt: string): boolean {
    // Heuristics: if prompt contains keywords, ensure corresponding entities/resources exist
    const requiredEntities: string[] = [];
    const lower = originalPrompt.toLowerCase();
    if (lower.includes('users')) requiredEntities.push('User');
    if (lower.includes('merchants')) requiredEntities.push('Merchant');
    if (lower.includes('kyc')) requiredEntities.push('KycDocument');
    if (lower.includes('directors')) requiredEntities.push('Director');
    if (lower.includes('transactions')) requiredEntities.push('Transaction');
    if (lower.includes('group split') || lower.includes('group_split')) requiredEntities.push('GroupSplitContributor');
    if (lower.includes('settlement')) { requiredEntities.push('Settlement'); requiredEntities.push('SettlementItem'); }
    if (lower.includes('qr')) requiredEntities.push('QrCode');
    if (lower.includes('admin')) requiredEntities.push('AdminLog');
    if (lower.includes('fraud')) requiredEntities.push('FraudFlag');

    const entityNames = new Set((spec.entities || []).map((e: any) => String(e.name).toLowerCase()));
    const missingEntities = requiredEntities.filter((e) => !entityNames.has(e.toLowerCase()));

    // Also require multiple API resources if prompt is complex
    const minEntities = lower.includes('dashboard') ? 8 : 3;
    const minApis = lower.includes('dashboard') ? 10 : 3;
    const hasEnoughEntities = (spec.entities || []).length >= minEntities;
    const hasEnoughApis = (spec.api || []).length >= minApis;

    return missingEntities.length === 0 && hasEnoughEntities && hasEnoughApis;
  }

  private buildExpansionPrompt(originalPrompt: string, partialSpec: any): string {
    const missingList = [
      'User','Merchant','KycDocument','Director','Transaction','GroupSplitContributor','Settlement','SettlementItem','QrCode','AdminLog','FraudFlag'
    ];
    const existing = new Set((partialSpec.entities || []).map((e: any) => String(e.name).toLowerCase()));
    const missing = missingList.filter((n) => !existing.has(n.toLowerCase()));

    return `You previously returned an incomplete JSON spec. Expand it to include ALL modules and tables required by the user's prompt.\n\n` +
      `STRICT REQUIREMENTS:\n- Include entities for: ${missing.join(', ')} (if applicable).\n` +
      `- Ensure API resources for auth, merchants, transactions, group-splits, settlements, qr-codes, admin (merchants, transactions, settlements, analytics, config, logs), webhooks, and health.\n` +
      `- Include Redis, S3, Email, and SMS env variables.\n` +
      `- Keep output as a SINGLE valid JSON object matching the required schema with required/unique flags on all fields.\n\n` +
      `Return ONLY JSON with no commentary.\n\nORIGINAL USER REQUEST:\n${originalPrompt}`;
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
    
    let cleanedText = text.slice(jsonStart, jsonEnd).trim();
    
    // More robust JSON cleaning
    try {
      // First, try to parse as-is to see if it's already valid
      const parsed = JSON.parse(cleanedText);
      
      // Post-process to add missing required fields
      if (parsed.entities && Array.isArray(parsed.entities)) {
        parsed.entities.forEach((entity: any) => {
          if (entity.fields && Array.isArray(entity.fields)) {
            entity.fields.forEach((field: any) => {
              // Add missing required field with default value
              if (field.required === undefined) {
                field.required = true;
              }
              // Add missing unique field
              if (field.unique === undefined) {
                field.unique = false;
              }
            });
          }
        });
      }
      
      return JSON.stringify(parsed);
    } catch (error) {
      // If parsing fails, try a simpler approach
      console.log('JSON parsing failed, attempting to clean...');
      
      // Simple cleaning - just fix obvious issues without complex regex
      cleanedText = cleanedText
        // Fix common newline issues
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t')
        // Fix unescaped quotes in string values (simple approach)
        .replace(/"([^"]*)"\s*:\s*"([^"]*)"([^,}\]]*)/g, (match, key, value, rest) => {
          // Only escape if the value contains unescaped quotes
          if (value.includes('"') && !value.includes('\\"')) {
            const escapedValue = value.replace(/"/g, '\\"');
            return `"${key}": "${escapedValue}"${rest}`;
          }
          return match;
        });
      
      // Try parsing again
      try {
        const parsed = JSON.parse(cleanedText);
        
        // Post-process to add missing required fields
        if (parsed.entities && Array.isArray(parsed.entities)) {
          parsed.entities.forEach((entity: any) => {
            if (entity.fields && Array.isArray(entity.fields)) {
              entity.fields.forEach((field: any) => {
                // Add missing required field with default value
                if (field.required === undefined) {
                  field.required = true;
                }
                // Add missing unique field
                if (field.unique === undefined) {
                  field.unique = false;
                }
              });
            }
          });
        }
        
        return JSON.stringify(parsed);
      } catch (secondError) {
        console.error('JSON cleaning failed:', secondError);
        console.error('Cleaned text (first 1000 chars):', cleanedText.substring(0, 1000));
        
        // Last resort: try to extract just the essential parts and rebuild
        try {
          const fallbackSpec = this.createFallbackSpec();
          console.log('Using fallback specification');
          return JSON.stringify(fallbackSpec);
        } catch (fallbackError) {
          throw new Error(`Failed to parse JSON after cleaning: ${secondError instanceof Error ? secondError.message : 'Unknown error'}`);
        }
      }
    }
  }

  private createFallbackSpec(): any {
    return {
      stack: {
        language: "node",
        framework: "express",
        database: "postgres",
        orm: "prisma"
      },
      entities: [
        {
          name: "User",
          fields: [
            { name: "id", type: "uuid", required: true, unique: true, default: "uuid" },
            { name: "email", type: "string", required: true, unique: true },
            { name: "passwordHash", type: "string", required: true, unique: false },
            { name: "createdAt", type: "datetime", required: true, unique: false, default: "now" }
          ],
          relations: []
        }
      ],
      auth: {
        strategy: "jwt",
        roles: ["user", "admin"],
        permissions: {
          user: { users: ["read", "write"] },
          admin: { users: ["read", "write", "delete", "admin"] }
        }
      },
      api: [
        {
          resource: "users",
          operations: ["list", "get", "create", "update", "delete"],
          middleware: ["auth", "validate"],
          permissions: {
            list: ["admin"],
            get: ["admin", "owner"],
            create: ["public"],
            update: ["admin", "owner"],
            delete: ["admin"]
          }
        }
      ],
      env: [
        { name: "DATABASE_URL", description: "PostgreSQL connection string", required: true, type: "url" },
        { name: "JWT_SECRET", description: "Secret key for JWT tokens", required: true, type: "secret" },
        { name: "PORT", description: "Server port", required: false, default: "3000", type: "number" }
      ],
      extras: {
        queue: "none",
        cache: "none",
        storage: "none",
        email: "none",
        payment: "none",
        search: "none",
        monitoring: "none",
        testing: true,
        docker: true,
        ci_cd: true
      },
      metadata: {
        name: "fallback-backend",
        description: "Fallback backend specification",
        version: "1.0.0",
        license: "MIT"
      }
    };
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
    
    // Enhanced package.json with better scripts and dependencies
    const pkg = {
      name: projectName,
      version: "1.0.0",
      type: 'module',
      scripts: {
        dev: 'tsx watch --clear-screen=false src/server.ts',
        build: 'tsc && tsc-alias',
        start: 'node dist/server.js',
        lint: 'eslint src/**/*.ts --fix',
        format: 'prettier --write src/**/*.ts',
        test: 'vitest',
        "test:watch": 'vitest --watch',
        "prisma:generate": 'prisma generate',
        "prisma:migrate": 'prisma migrate dev',
        "prisma:studio": 'prisma studio',
        "prisma:seed": 'tsx prisma/seed.ts'
      },
      dependencies: {
        express: '^4.18.2',
        cors: '^2.8.5',
        helmet: '^7.1.0',
        compression: '^1.7.4',
        'express-rate-limit': '^7.1.5',
        'express-validator': '^7.0.1',
        zod: '^3.22.4',
        jsonwebtoken: '^9.0.2',
        bcryptjs: '^2.4.3',
        prisma: '^5.6.0',
        '@prisma/client': '^5.6.0',
        dotenv: '^16.3.1',
        winston: '^3.11.0',
        'express-winston': '^4.2.0'
      },
      devDependencies: { 
        typescript: '^5.2.2', 
        tsx: '^4.1.4', 
        '@types/express': '^4.17.21',
        '@types/cors': '^2.8.17',
        '@types/compression': '^1.7.5',
        '@types/jsonwebtoken': '^9.0.5',
        '@types/bcryptjs': '^2.4.6',
        '@types/node': '^20.9.0',
        eslint: '^8.54.0',
        '@typescript-eslint/eslint-plugin': '^6.12.0',
        '@typescript-eslint/parser': '^6.12.0',
        prettier: '^3.1.0',
        vitest: '^0.34.6',
        'tsc-alias': '^1.8.8'
      }
    };

    archive.append(JSON.stringify(pkg, null, 2), { name: 'package.json' });
    
    // Enhanced tsconfig.json with path mapping
    const tsconfig = {
      compilerOptions: {
        target: 'ES2022',
        module: 'ESNext',
        moduleResolution: 'Node',
        allowSyntheticDefaultImports: true,
        esModuleInterop: true,
        allowJs: true,
        outDir: 'dist',
        rootDir: 'src',
        strict: true,
        skipLibCheck: true,
        forceConsistentCasingInFileNames: true,
        resolveJsonModule: true,
        isolatedModules: true,
        noEmit: false,
        baseUrl: '.',
        paths: {
          '@/*': ['src/*'],
          '@/config/*': ['src/config/*'],
          '@/controllers/*': ['src/controllers/*'],
          '@/middleware/*': ['src/middleware/*'],
          '@/routes/*': ['src/routes/*'],
          '@/services/*': ['src/services/*'],
          '@/utils/*': ['src/utils/*'],
          '@/types/*': ['src/types/*']
        }
      },
      include: ['src/**/*'],
      exclude: ['node_modules', 'dist']
    };
    archive.append(JSON.stringify(tsconfig, null, 2), { name: 'tsconfig.json' });

    // Professional .env.example
    const envExample = `# Database
DATABASE_URL=postgresql://username:password@localhost:5432/database_name

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here
JWT_EXPIRES_IN=7d
JWT_REFRESH_EXPIRES_IN=30d

# Server Configuration
NODE_ENV=development
PORT=3000
API_PREFIX=/api/v1

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS Configuration
CORS_ORIGIN=http://localhost:3000,http://localhost:8080

# Logging
LOG_LEVEL=info

# Email Configuration (Optional)
EMAIL_FROM=noreply@yourapp.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password`;

    archive.append(envExample, { name: '.env.example' });

    // Add professional project structure files
    archive.append(this.generateNodeServerTs(spec), { name: 'src/server.ts' });
    archive.append(this.generateAppTs(spec), { name: 'src/app.ts' });
    archive.append(this.generateConfigIndex(spec), { name: 'src/config/index.ts' });
    archive.append(this.generateDatabaseConfig(), { name: 'src/config/database.ts' });
    archive.append(this.generateLoggerConfig(), { name: 'src/config/logger.ts' });
    
    // Middleware
    archive.append(this.generateAuthMiddleware(spec), { name: 'src/middleware/auth.ts' });
    archive.append(this.generateErrorMiddleware(), { name: 'src/middleware/error.ts' });
    archive.append(this.generateValidationMiddleware(), { name: 'src/middleware/validation.ts' });
    
    // Controllers
    for (const resource of spec.api) {
      archive.append(this.generateController(resource, spec), { name: `src/controllers/${resource.resource}.controller.ts` });
    }
    
    // Services
    for (const resource of spec.api) {
      archive.append(this.generateService(resource, spec), { name: `src/services/${resource.resource}.service.ts` });
    }
    
    // Routes with versioning
    archive.append(this.generateRouteIndex(spec), { name: 'src/routes/index.ts' });
    for (const resource of spec.api) {
      archive.append(this.generateProfessionalRoute(resource, spec), { name: `src/routes/${resource.resource}.routes.ts` });
    }
    
    // Utils
    archive.append(this.generateResponseUtil(), { name: 'src/utils/response.ts' });
    archive.append(this.generateValidationUtil(), { name: 'src/utils/validation.ts' });
    
    // Types
    archive.append(this.generateTypesIndex(spec), { name: 'src/types/index.ts' });
    
    // Enhanced Prisma schema
    archive.append(this.generateEnhancedPrismaSchema(spec), { name: 'prisma/schema.prisma' });
    archive.append(this.generatePrismaSeed(spec), { name: 'prisma/seed.ts' });
    
    // Configuration files
    archive.append(this.generateEslintConfig(), { name: '.eslintrc.json' });
    archive.append(this.generatePrettierConfig(), { name: '.prettierrc' });
    archive.append(this.generateGitignore(), { name: '.gitignore' });
    
    // Docker
    archive.append(this.generateProfessionalDockerfile(), { name: 'Dockerfile' });
    archive.append(this.generateDockerCompose(spec), { name: 'docker-compose.yml' });
    
    // Enhanced README
    archive.append(this.generateProfessionalNodeReadme(spec), { name: 'README.md' });
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

  private generateNodeServerTs(spec: any): string {
    return `import app from './app.js';
import config from './config/index.js';
import logger from './config/logger.js';

const { port } = config;

const server = app.listen(port, () => {
  logger.info(\`🚀 Server running on port \${port}\`);
  logger.info(\`📚 API Documentation: http://localhost:\${port}/api/v1/docs\`);
  logger.info(\`🏥 Health Check: http://localhost:\${port}/api/v1/health\`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    logger.info('Process terminated');
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    logger.info('Process terminated');
  });
});

export default server;`;
  }

  private generateAppTs(spec: any): string {
    return `import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import expressWinston from 'express-winston';

import config from './config/index.js';
import logger from './config/logger.js';
import routes from './routes/index.js';
import { errorHandler } from './middleware/error.js';
import { ApiResponse } from './utils/response.js';

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: config.corsOrigin,
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: config.rateLimitMaxRequests,
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(compression());

// Request logging
app.use(expressWinston.logger({
  winstonInstance: logger,
  meta: false,
  msg: 'HTTP {{req.method}} {{req.url}}',
  expressFormat: true,
  colorize: false
}));

// Health check endpoint
app.get('/api/v1/health', (req, res) => {
  ApiResponse.success(res, { status: 'OK', timestamp: new Date().toISOString() }, 'Service is healthy');
});

// API routes
app.use('/api/v1', routes);

// Handle 404
app.use('*', (req, res) => {
  ApiResponse.notFound(res, 'Route not found');
});

// Error handling middleware
app.use(errorHandler);

export default app;`;
  }

  private generateConfigIndex(spec: any): string {
    return `import dotenv from 'dotenv';

dotenv.config();

const config = {
  // Server
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  apiPrefix: process.env.API_PREFIX || '/api/v1',

  // Database
  databaseUrl: process.env.DATABASE_URL || '',

  // JWT
  jwtSecret: process.env.JWT_SECRET || 'fallback-secret-key',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '7d',
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d',

  // Rate limiting
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),

  // CORS
  corsOrigin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],

  // Logging
  logLevel: process.env.LOG_LEVEL || 'info',

  // Email
  email: {
    from: process.env.EMAIL_FROM || 'noreply@example.com',
    smtp: {
      host: process.env.SMTP_HOST || '',
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      user: process.env.SMTP_USER || '',
      pass: process.env.SMTP_PASS || ''
    }
  }
};

export default config;`;
  }

  private generateErrorMiddleware(): string {
    return `import { Request, Response, NextFunction } from 'express';
import { Prisma } from '@prisma/client';
import logger from '../config/logger.js';
import { ApiResponse } from '../utils/response.js';

export class AppError extends Error {
  statusCode: number;
  isOperational: boolean;

  constructor(message: string, statusCode: number = 500, isOperational: boolean = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;

    Error.captureStackTrace(this, this.constructor);
  }
}

export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  let statusCode = 500;
  let message = 'Internal server error';

  // Log error
  logger.error(\`Error: \${error.message}\`, { stack: error.stack });

  // Handle different error types
  if (error instanceof AppError) {
    statusCode = error.statusCode;
    message = error.message;
  } else if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === 'P2002') {
      statusCode = 409;
      message = 'Resource already exists';
    } else if (error.code === 'P2025') {
      statusCode = 404;
      message = 'Resource not found';
    }
  } else if (error instanceof Prisma.PrismaClientValidationError) {
    statusCode = 400;
    message = 'Invalid data provided';
  }

  ApiResponse.error(res, message, statusCode);
};

export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};`;
  }

  private generateResponseUtil(): string {
    return `import { Response } from 'express';

export interface ApiResponseData<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  timestamp: string;
}

export class ApiResponse {
  static success<T>(res: Response, data?: T, message: string = 'Success', statusCode: number = 200) {
    return res.status(statusCode).json({
      success: true,
      message,
      data,
      timestamp: new Date().toISOString()
    } as ApiResponseData<T>);
  }

  static error(res: Response, message: string = 'Error', statusCode: number = 500, error?: string) {
    return res.status(statusCode).json({
      success: false,
      message,
      error,
      timestamp: new Date().toISOString()
    } as ApiResponseData);
  }

  static notFound(res: Response, message: string = 'Resource not found') {
    return this.error(res, message, 404);
  }

  static badRequest(res: Response, message: string = 'Bad request') {
    return this.error(res, message, 400);
  }

  static unauthorized(res: Response, message: string = 'Unauthorized') {
    return this.error(res, message, 401);
  }

  static forbidden(res: Response, message: string = 'Forbidden') {
    return this.error(res, message, 403);
  }
}`;
  }

  private generateController(resource: any, spec: any): string {
    const resourceName = resource.resource;
    const modelName = resourceName.charAt(0).toUpperCase() + resourceName.slice(1);
    
    return `import { Request, Response } from 'express';
import { ${modelName}Service } from '../services/${resourceName}.service.js';
import { ApiResponse } from '../utils/response.js';
import { asyncHandler } from '../middleware/error.js';

export class ${modelName}Controller {
  private ${resourceName}Service: ${modelName}Service;

  constructor() {
    this.${resourceName}Service = new ${modelName}Service();
  }

  ${resource.operations.includes('list') ? `
  getAll = asyncHandler(async (req: Request, res: Response) => {
    const { page = 1, limit = 10, ...filters } = req.query;
    const result = await this.${resourceName}Service.findMany({
      page: Number(page),
      limit: Number(limit),
      filters
    });
    
    ApiResponse.success(res, result, '${modelName}s retrieved successfully');
  });` : ''}

  ${resource.operations.includes('get') ? `
  getById = asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const ${resourceName} = await this.${resourceName}Service.findById(id);
    
    ApiResponse.success(res, ${resourceName}, '${modelName} retrieved successfully');
  });` : ''}

  ${resource.operations.includes('create') ? `
  create = asyncHandler(async (req: Request, res: Response) => {
    const ${resourceName} = await this.${resourceName}Service.create(req.body);
    
    ApiResponse.success(res, ${resourceName}, '${modelName} created successfully', 201);
  });` : ''}

  ${resource.operations.includes('update') ? `
  update = asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const ${resourceName} = await this.${resourceName}Service.update(id, req.body);
    
    ApiResponse.success(res, ${resourceName}, '${modelName} updated successfully');
  });` : ''}

  ${resource.operations.includes('delete') ? `
  delete = asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    await this.${resourceName}Service.delete(id);
    
    ApiResponse.success(res, null, '${modelName} deleted successfully', 204);
  });` : ''}
}`;
  }

  private generateService(resource: any, spec: any): string {
    const resourceName = resource.resource;
    const modelName = resourceName.charAt(0).toUpperCase() + resourceName.slice(1);
    
    return `import { PrismaClient } from '@prisma/client';
import { AppError } from '../middleware/error.js';

const prisma = new PrismaClient();

export class ${modelName}Service {
  async findMany(options: { page: number; limit: number; filters: any }) {
    const { page, limit, filters } = options;
    const skip = (page - 1) * limit;
    
    const [items, total] = await Promise.all([
      prisma.${resourceName}.findMany({
        skip,
        take: limit,
        where: filters,
        orderBy: { createdAt: 'desc' }
      }),
      prisma.${resourceName}.count({ where: filters })
    ]);

    return {
      items,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    };
  }

  async findById(id: string) {
    const ${resourceName} = await prisma.${resourceName}.findUnique({
      where: { id }
    });

    if (!${resourceName}) {
      throw new AppError('${modelName} not found', 404);
    }

    return ${resourceName};
  }

  async create(data: any) {
    return prisma.${resourceName}.create({ data });
  }

  async update(id: string, data: any) {
    const existing = await this.findById(id);
    
    return prisma.${resourceName}.update({
      where: { id },
      data
    });
  }

  async delete(id: string) {
    const existing = await this.findById(id);
    
    return prisma.${resourceName}.delete({
      where: { id }
    });
  }
}`;
  }

  // Placeholder methods for enhanced Node.js project generation
  private generateDatabaseConfig(): string {
    return `import { PrismaClient } from '@prisma/client';
import config from './index.js';

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: config.databaseUrl
    }
  }
});

export default prisma;`;
  }

  private generateLoggerConfig(): string {
    return `import winston from 'winston';
import config from './index.js';

const logger = winston.createLogger({
  level: config.logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'backend-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (config.nodeEnv !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

export default logger;`;
  }

  private generateAuthMiddleware(spec: any): string {
    return `import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import config from '../config/index.js';

interface AuthRequest extends Request {
  user?: any;
}

export const authenticateToken = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, config.jwtSecret, (err: any, user: any) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
    req.user = user;
    next();
  });
};`;
  }

  private generateValidationMiddleware(): string {
    return `import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';

export const handleValidationErrors = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }
  next();
};`;
  }

  private generateRouteIndex(spec: any): string {
    const routeImports = spec.api.map((r: any) => 
      `import ${r.resource}Routes from './${r.resource}.routes.js';`
    ).join('\n');
    
    const routeRegistrations = spec.api.map((r: any) => 
      `router.use('/${r.resource}', ${r.resource}Routes);`
    ).join('\n');

    return `import { Router } from 'express';
${routeImports}

const router = Router();

${routeRegistrations}

export default router;`;
  }

  private generateProfessionalRoute(resource: any, spec: any): string {
    const resourceName = resource.resource;
    const modelName = resourceName.charAt(0).toUpperCase() + resourceName.slice(1);
    
    return `import { Router } from 'express';
import { ${modelName}Controller } from '../controllers/${resourceName}.controller.js';
import { authenticateToken } from '../middleware/auth.js';

const router = Router();
const ${resourceName}Controller = new ${modelName}Controller();

// Apply authentication to all routes
router.use(authenticateToken);

${resource.operations.includes('list') ? `router.get('/', ${resourceName}Controller.getAll);` : ''}
${resource.operations.includes('get') ? `router.get('/:id', ${resourceName}Controller.getById);` : ''}
${resource.operations.includes('create') ? `router.post('/', ${resourceName}Controller.create);` : ''}
${resource.operations.includes('update') ? `router.put('/:id', ${resourceName}Controller.update);` : ''}
${resource.operations.includes('delete') ? `router.delete('/:id', ${resourceName}Controller.delete);` : ''}

export default router;`;
  }

  private generateValidationUtil(): string {
    return `import { z } from 'zod';

export const validateRequest = (schema: z.ZodSchema) => {
  return (req: any, res: any, next: any) => {
    try {
      schema.parse(req.body);
      next();
    } catch (error) {
      res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: error instanceof z.ZodError ? error.errors : []
      });
    }
  };
};`;
  }

  private generateTypesIndex(spec: any): string {
    return `export interface User {
  id: string;
  email: string;
  username: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  timestamp: string;
}`;
  }

  private generateEnhancedPrismaSchema(spec: any): string {
    const prismaModels = spec.entities
      .map((e: any) => `model ${e.name} {\n${e.fields.map((f: any) => this.prismaField(e.name, f)).join('\n')}\n}`)
      .join('\n\n');
    
    return `generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

${prismaModels}`;
  }

  private generatePrismaSeed(spec: any): string {
    return `import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  // Add seed data here
  console.log('Seeding database...');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });`;
  }

  private generateEslintConfig(): string {
    return `{
  "env": {
    "es2021": true,
    "node": true
  },
  "extends": [
    "eslint:recommended",
    "@typescript-eslint/recommended"
  ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": "latest",
    "sourceType": "module"
  },
  "plugins": ["@typescript-eslint"],
  "rules": {
    "indent": ["error", 2],
    "linebreak-style": ["error", "unix"],
    "quotes": ["error", "single"],
    "semi": ["error", "always"]
  }
}`;
  }

  private generatePrettierConfig(): string {
    return `{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 80,
  "tabWidth": 2
}`;
  }

  private generateGitignore(): string {
    return `node_modules/
dist/
.env
.env.local
.env.development.local
.env.test.local
.env.production.local
logs/
*.log
.DS_Store
.vscode/
.idea/`;
  }

  private generateProfessionalDockerfile(): string {
    return `FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine AS runner
WORKDIR /app

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nodejs

COPY --from=builder /app/node_modules ./node_modules
COPY . .

USER nodejs

EXPOSE 3000

CMD ["npm", "start"]`;
  }

  private generateDockerCompose(spec: any): string {
    return `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://postgres:password@db:5432/backend_db
    depends_on:
      - db

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=backend_db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:`;
  }

  private generateProfessionalNodeReadme(spec: any): string {
    return `# ${spec.metadata?.name || 'Backend V0'} - Professional Node.js API

A production-ready Node.js API built with Express, TypeScript, Prisma, and PostgreSQL.

## 🚀 Features

- **Express.js** - Fast, unopinionated web framework
- **TypeScript** - Type-safe JavaScript with modern features
- **Prisma** - Next-generation ORM with type safety
- **PostgreSQL** - Robust, open-source database
- **JWT Authentication** - Secure token-based authentication
- **Winston Logging** - Professional logging with multiple transports
- **Rate Limiting** - Built-in protection against abuse
- **CORS** - Cross-origin resource sharing support
- **Helmet** - Security headers middleware
- **Compression** - Response compression for better performance
- **Validation** - Request validation with express-validator
- **Error Handling** - Comprehensive error handling middleware
- **Docker** - Containerized deployment ready

## 📁 Project Structure

\`\`\`
src/
├── config/           # Configuration files
├── controllers/      # Route controllers
├── middleware/       # Custom middleware
├── routes/          # API routes
├── services/        # Business logic
├── utils/           # Utility functions
├── types/           # TypeScript type definitions
├── app.ts           # Express app configuration
└── server.ts        # Server entry point
\`\`\`

## 🛠️ Development

### Prerequisites

- Node.js 20+
- PostgreSQL 15+
- npm or yarn

### Installation

1. Clone the repository
2. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`

3. Set up environment variables:
   \`\`\`bash
   cp .env.example .env
   \`\`\`

4. Set up the database:
   \`\`\`bash
   npm run prisma:generate
   npm run prisma:migrate
   \`\`\`

5. Start the development server:
   \`\`\`bash
   npm run dev
   \`\`\`

## 📚 API Documentation

- **Health Check**: \`GET /api/v1/health\`
- **API Endpoints**: \`/api/v1/{resource}\`

## 🐳 Docker Deployment

\`\`\`bash
# Build and run with Docker Compose
docker-compose up -d

# Or build and run individually
docker build -t backend-api .
docker run -p 3000:3000 backend-api
\`\`\`

## 🔧 Scripts

- \`npm run dev\` - Start development server with hot reload
- \`npm run build\` - Build for production
- \`npm run start\` - Start production server
- \`npm run lint\` - Run ESLint
- \`npm run format\` - Format code with Prettier
- \`npm run test\` - Run tests
- \`npm run prisma:studio\` - Open Prisma Studio

## 🔒 Security

- JWT-based authentication
- Rate limiting
- CORS protection
- Security headers with Helmet
- Input validation
- SQL injection protection with Prisma

## 📝 License

MIT License - see LICENSE file for details

Generated by EaseArch Backend Generator.`;
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
  private generateProfessionalFastapiMain(spec: any): string {
    return `from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import time
import uvicorn

from app.core.config import settings
from app.core.database import init_db
from app.core.exceptions import AppException
from app.api.v1.router import api_router
from app.core.logging import logger

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 Starting up...")
    await init_db()
    yield
    # Shutdown
    logger.info("🛑 Shutting down...")

app = FastAPI(
    title="${spec.metadata?.name || 'Backend V0 API'}",
    description="Professional AI-generated backend API",
    version="1.0.0",
    docs_url="/api/v1/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/api/v1/redoc" if settings.ENVIRONMENT != "production" else None,
    lifespan=lifespan
)

# Security middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

# Exception handlers
@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.message,
            "error_code": exc.error_code
        }
    )

# Health check
@app.get("/api/v1/health")
async def health_check():
    return {
        "success": True,
        "message": "Service is healthy",
        "timestamp": time.time()
    }

# Include API router
app.include_router(api_router, prefix="/api/v1")

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )`;
  }

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

// ==========================
// Enhanced (v2) Node.js generator (Professional)
// ==========================

// Enhanced validation schemas to match professional generator
const EnhancedFieldSchema = z.object({
  name: z.string(),
  type: z.enum(['string', 'number', 'boolean', 'date', 'uuid', 'array', 'object', 'decimal', 'text', 'json']),
  required: z.boolean().default(true),
  unique: z.boolean().default(false),
  default: z.any().optional(),
  validation: z.object({
    min: z.number().optional(),
    max: z.number().optional(),
    minLength: z.number().optional(),
    maxLength: z.number().optional(),
    pattern: z.string().optional(),
    enum: z.array(z.string()).optional(),
    email: z.boolean().optional(),
    phone: z.boolean().optional()
  }).optional()
});

const EnhancedEntitySchema = z.object({
  name: z.string(),
  fields: z.array(EnhancedFieldSchema),
  relations: z.array(z.object({
    type: z.enum(['oneToMany', 'manyToOne', 'manyToMany', 'oneToOne']),
    target: z.string(),
    field: z.string(),
    onDelete: z.enum(['cascade', 'restrict', 'setNull']).optional()
  })).optional(),
  indexes: z.array(z.object({
    fields: z.array(z.string()),
    unique: z.boolean().optional()
  })).optional()
});

const EnhancedSpecSchema = z.object({
  stack: z.object({
    language: z.enum(['node', 'python']),
    framework: z.string(),
    database: z.string(),
    orm: z.string(),
    typescript: z.boolean().default(true)
  }),
  entities: z.array(EnhancedEntitySchema),
  auth: z.object({
    strategy: z.enum(['jwt', 'session', 'oauth', 'none']),
    providers: z.array(z.string()).optional(),
    roles: z.array(z.string()).optional(),
    permissions: z.record(z.string(), z.unknown()).optional(),
    middleware: z.array(z.string()).optional()
  }).optional(),
  api: z.array(z.object({
    resource: z.string(),
    operations: z.array(z.string()),
    middleware: z.array(z.string()).optional(),
    permissions: z.record(z.string(), z.unknown()).optional(),
    validation: z.record(z.string(), z.unknown()).optional(),
    customEndpoints: z.array(z.object({
      method: z.string(),
      path: z.string(),
      description: z.string()
    })).optional()
  })),
  features: z.object({
    wallet: z.boolean().optional(),
    trading: z.boolean().optional(),
    notifications: z.boolean().optional(),
    fileUpload: z.boolean().optional(),
    email: z.boolean().optional(),
    sms: z.boolean().optional(),
    payments: z.boolean().optional(),
    analytics: z.boolean().optional(),
    realtime: z.boolean().optional()
  }).optional(),
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
    ci_cd: z.boolean().optional(),
    swagger: z.boolean().optional()
  }).optional(),
  metadata: z.object({
    name: z.string(),
    description: z.string(),
    version: z.string().default('1.0.0'),
    license: z.string().default('MIT')
  })
});

type EnhancedSpec = z.infer<typeof EnhancedSpecSchema>;

class ProfessionalBackendGenerator {
  private geminiApiKey = process.env.GEMINI_API_KEY!;
  private geminiApiUrl = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent';

  async generateSpec(prompt: string): Promise<EnhancedSpec> {
    const systemPrompt = `You are an expert backend architect specializing in complex domain applications. Generate a comprehensive, production-ready backend specification.

CRITICAL REQUIREMENTS:
1. Analyze the user's prompt carefully and identify ALL entities, relationships, and business logic
2. For betting/gambling apps: Include User, Match, Odds, Bet, Transaction, Wallet entities
3. For e-commerce: Include User, Product, Order, Cart, Payment, Category entities  
4. For social apps: Include User, Post, Comment, Like, Follow, Message entities
5. For any app: Always include User management with authentication
6. Generate ALL entities mentioned in the prompt with proper relationships
7. Use modern Node.js/TypeScript stack with Express and Sequelize
8. Include comprehensive authentication with JWT and bcrypt
9. Add proper error handling, validation, and security middleware
10. Generate clean, modular architecture (controllers, services, middleware, routes)
11. Include environment configuration and professional project structure
12. Add features like rate limiting, CORS, compression, logging
13. Generate proper TypeScript types and interfaces
14. Include database migrations and seed files
15. Add Docker support and deployment configuration
16. Generate professional README and documentation

ENTITY GENERATION RULES:
- Always generate a complete set of entities based on the domain
- Include proper relationships between entities (oneToMany, manyToOne, manyToMany)
- Add appropriate fields for each entity (id, timestamps, domain-specific fields)
- Include validation rules for each field
- Generate API endpoints for all entities with full CRUD operations
- Add proper authentication and authorization middleware

EXAMPLE FOR BETTING APP:
- User: id, email, password, firstName, lastName, balance, role, isActive
- Match: id, homeTeam, awayTeam, startTime, status, result, createdAt
- Odds: id, matchId, marketType, oddsValue, isActive
- Bet: id, userId, matchId, oddsId, amount, potentialWin, status, createdAt
- Transaction: id, userId, type, amount, balance, description, createdAt

Return ONLY a valid JSON object matching the EnhancedSpecSchema.`;

    try {
      console.log('🤖 Calling Gemini API for enhanced spec generation...');
      const response = await fetch(`${this.geminiApiUrl}?key=${this.geminiApiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: `${systemPrompt}\n\nUser Request: ${prompt}` }] }],
          generationConfig: { temperature: 0.2, topK: 40, topP: 0.95, maxOutputTokens: 16384 }
        })
      });

      if (!response.ok) {
        console.error(`Gemini API Error: ${response.status} ${response.statusText}`);
        throw new Error(`Gemini API Error: ${response.status}`);
      }
      
      const data = await response.json();
      const generatedText = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!generatedText) {
        console.error('No text generated from Gemini API');
        throw new Error('No text generated');
      }

      console.log('📝 Raw Gemini response length:', generatedText.length);
      const cleaned = this.cleanJsonResponse(generatedText);
      console.log('🧹 Cleaned JSON length:', cleaned.length);
      
      const parsed = JSON.parse(cleaned);
      console.log('✅ Parsed JSON successfully, entities count:', parsed.entities?.length || 0);
      
      const validated = EnhancedSpecSchema.parse(parsed);
      console.log('✅ Validated spec successfully');
      return this.enhance(validated);
    } catch (err) {
      console.error('❌ Professional generation failed:', err);
      console.log('🔄 Using intelligent fallback based on prompt analysis...');
      return this.generateIntelligentFallback(prompt);
    }
  }

  private enhance(spec: EnhancedSpec): EnhancedSpec {
    return {
      ...spec,
      stack: { ...spec.stack, typescript: true, framework: 'express', database: 'mysql', orm: 'sequelize' },
      extras: { testing: true, docker: true, swagger: true, monitoring: 'sentry', ...(spec.extras || {}) }
    } as EnhancedSpec;
  }

  private generateIntelligentFallback(prompt: string): EnhancedSpec {
    const lowerPrompt = prompt.toLowerCase();
    console.log('🔍 Analyzing prompt for intelligent fallback...');
    
    // Extract key concepts and entities from the prompt
    const extractedEntities = this.extractEntitiesFromPrompt(prompt);
    const detectedFeatures = this.detectFeaturesFromPrompt(lowerPrompt);
    const businessDomain = this.detectBusinessDomain(lowerPrompt);
    
    console.log(`🎯 Detected domain: ${businessDomain}`);
    console.log(`📊 Extracted entities: ${extractedEntities.join(', ')}`);
    console.log(`⚡ Features: ${Object.keys(detectedFeatures).join(', ')}`);
    
    // Generate comprehensive entity set
    const entities = this.generateComprehensiveEntities(extractedEntities, businessDomain, lowerPrompt);
    const api = this.generateAPIEndpoints(entities);
    
    console.log(`✅ Generated ${entities.length} entities:`, entities.map(e => e.name));
    
    return {
      stack: { language: 'node', framework: 'express', database: 'mysql', orm: 'sequelize', typescript: true },
      entities,
      auth: { strategy: 'jwt', roles: ['user', 'admin'] },
      api,
      features: detectedFeatures,
      env: [
        { name: 'DATABASE_URL', description: 'Database connection string', required: true, type: 'url' },
        { name: 'JWT_SECRET', description: 'JWT secret key', required: true, type: 'secret' },
        { name: 'PORT', description: 'Server port', required: false, type: 'number', default: 3000 }
      ],
      metadata: { 
        name: 'professional-backend', 
        description: `Professional backend API for ${businessDomain}`, 
        version: '1.0.0', 
        license: 'MIT' 
      }
    };
  }

  private extractEntitiesFromPrompt(prompt: string): string[] {
    const entities = new Set<string>();
    
    // Common entity patterns
    const entityPatterns = [
      // User management
      { pattern: /\b(user|users|customer|customers|client|clients|member|members|account|accounts)\b/gi, entity: 'User' },
      
      // Content management
      { pattern: /\b(post|posts|article|articles|blog|blogs|content|contents|story|stories)\b/gi, entity: 'Post' },
      { pattern: /\b(comment|comments|review|reviews|feedback|feedbacks)\b/gi, entity: 'Comment' },
      { pattern: /\b(category|categories|tag|tags|label|labels|topic|topics)\b/gi, entity: 'Category' },
      
      // E-commerce
      { pattern: /\b(product|products|item|items|inventory|inventories|catalog|catalogs)\b/gi, entity: 'Product' },
      { pattern: /\b(order|orders|purchase|purchases|transaction|transactions|payment|payments)\b/gi, entity: 'Order' },
      { pattern: /\b(cart|carts|basket|baskets|wishlist|wishlists)\b/gi, entity: 'Cart' },
      
      // Betting/Gaming
      { pattern: /\b(match|matches|game|games|event|events|fixture|fixtures)\b/gi, entity: 'Match' },
      { pattern: /\b(bet|bets|wager|wagers|stake|stakes)\b/gi, entity: 'Bet' },
      { pattern: /\b(odd|odds|rate|rates|price|prices)\b/gi, entity: 'Odds' },
      
      // Financial
      { pattern: /\b(wallet|wallets|balance|balances|account|accounts|fund|funds)\b/gi, entity: 'Wallet' },
      { pattern: /\b(transaction|transactions|payment|payments|deposit|deposits|withdrawal|withdrawals)\b/gi, entity: 'Transaction' },
      
      // Communication
      { pattern: /\b(message|messages|chat|chats|conversation|conversations)\b/gi, entity: 'Message' },
      { pattern: /\b(notification|notifications|alert|alerts|reminder|reminders)\b/gi, entity: 'Notification' },
      
      // Learning/Education
      { pattern: /\b(course|courses|lesson|lessons|class|classes|module|modules)\b/gi, entity: 'Course' },
      { pattern: /\b(quiz|quizzes|exam|exams|test|tests|assignment|assignments)\b/gi, entity: 'Quiz' },
      
      // Healthcare
      { pattern: /\b(patient|patients|appointment|appointments|visit|visits)\b/gi, entity: 'Patient' },
      { pattern: /\b(doctor|doctors|physician|physicians|practitioner|practitioners)\b/gi, entity: 'Doctor' },
      
      // Real Estate
      { pattern: /\b(property|properties|listing|listings|house|houses|apartment|apartments)\b/gi, entity: 'Property' },
      { pattern: /\b(booking|bookings|reservation|reservations|rental|rentals)\b/gi, entity: 'Booking' },
      
      // Project Management
      { pattern: /\b(project|projects|task|tasks|milestone|milestones)\b/gi, entity: 'Project' },
      { pattern: /\b(team|teams|group|groups|organization|organizations)\b/gi, entity: 'Team' },
      
      // Media/Entertainment
      { pattern: /\b(video|videos|movie|movies|show|shows|episode|episodes)\b/gi, entity: 'Video' },
      { pattern: /\b(playlist|playlists|album|albums|track|tracks)\b/gi, entity: 'Playlist' },
      
      // Events
      { pattern: /\b(event|events|conference|conferences|meeting|meetings)\b/gi, entity: 'Event' },
      { pattern: /\b(ticket|tickets|registration|registrations)\b/gi, entity: 'Ticket' }
    ];
    
    // Extract entities using patterns
    entityPatterns.forEach(({ pattern, entity }) => {
      if (pattern.test(prompt)) {
        entities.add(entity);
      }
    });
    
    // Always include User if not already present
    if (!entities.has('User')) {
      entities.add('User');
    }
    
    return Array.from(entities);
  }

  private detectFeaturesFromPrompt(lowerPrompt: string): any {
    const features: any = {};
    
    // Authentication & Security
    if (lowerPrompt.includes('auth') || lowerPrompt.includes('login') || lowerPrompt.includes('register') || lowerPrompt.includes('user')) {
      features.authentication = true;
    }
    
    // Payment & Financial
    if (lowerPrompt.includes('payment') || lowerPrompt.includes('money') || lowerPrompt.includes('price') || lowerPrompt.includes('cost') || 
        lowerPrompt.includes('wallet') || lowerPrompt.includes('balance') || lowerPrompt.includes('transaction') || lowerPrompt.includes('bet')) {
      features.payments = true;
      features.wallet = true;
    }
    
    // File Management
    if (lowerPrompt.includes('upload') || lowerPrompt.includes('file') || lowerPrompt.includes('image') || lowerPrompt.includes('photo') || 
        lowerPrompt.includes('document') || lowerPrompt.includes('media')) {
      features.fileUpload = true;
    }
    
    // Notifications
    if (lowerPrompt.includes('notification') || lowerPrompt.includes('alert') || lowerPrompt.includes('email') || lowerPrompt.includes('sms') || 
        lowerPrompt.includes('push') || lowerPrompt.includes('reminder')) {
      features.notifications = true;
      features.email = true;
    }
    
    // Real-time features
    if (lowerPrompt.includes('real-time') || lowerPrompt.includes('live') || lowerPrompt.includes('chat') || lowerPrompt.includes('message') || 
        lowerPrompt.includes('stream') || lowerPrompt.includes('websocket')) {
      features.realtime = true;
    }
    
    // Analytics
    if (lowerPrompt.includes('analytics') || lowerPrompt.includes('report') || lowerPrompt.includes('statistic') || lowerPrompt.includes('dashboard') || 
        lowerPrompt.includes('metric') || lowerPrompt.includes('tracking')) {
      features.analytics = true;
    }
    
    // Trading/Gaming
    if (lowerPrompt.includes('bet') || lowerPrompt.includes('trade') || lowerPrompt.includes('gamble') || lowerPrompt.includes('game') || 
        lowerPrompt.includes('odds') || lowerPrompt.includes('match')) {
      features.trading = true;
      features.wallet = true;
    }
    
    return features;
  }

  private detectBusinessDomain(lowerPrompt: string): string {
    if (lowerPrompt.includes('betting') || lowerPrompt.includes('gambling') || lowerPrompt.includes('bet') || lowerPrompt.includes('odds')) {
      return 'Betting Platform';
    }
    if (lowerPrompt.includes('ecommerce') || lowerPrompt.includes('e-commerce') || lowerPrompt.includes('shop') || lowerPrompt.includes('store')) {
      return 'E-commerce Platform';
    }
    if (lowerPrompt.includes('social') || lowerPrompt.includes('community') || lowerPrompt.includes('network')) {
      return 'Social Platform';
    }
    if (lowerPrompt.includes('learning') || lowerPrompt.includes('education') || lowerPrompt.includes('course') || lowerPrompt.includes('school')) {
      return 'Learning Management System';
    }
    if (lowerPrompt.includes('healthcare') || lowerPrompt.includes('medical') || lowerPrompt.includes('patient') || lowerPrompt.includes('doctor')) {
      return 'Healthcare Platform';
    }
    if (lowerPrompt.includes('real estate') || lowerPrompt.includes('property') || lowerPrompt.includes('rental')) {
      return 'Real Estate Platform';
    }
    if (lowerPrompt.includes('project') || lowerPrompt.includes('management') || lowerPrompt.includes('task') || lowerPrompt.includes('team')) {
      return 'Project Management System';
    }
    if (lowerPrompt.includes('media') || lowerPrompt.includes('video') || lowerPrompt.includes('streaming') || lowerPrompt.includes('entertainment')) {
      return 'Media Platform';
    }
    if (lowerPrompt.includes('event') || lowerPrompt.includes('conference') || lowerPrompt.includes('meeting') || lowerPrompt.includes('booking')) {
      return 'Event Management System';
    }
    return 'Business Application';
  }

  private generateComprehensiveEntities(extractedEntities: string[], businessDomain: string, lowerPrompt: string): any[] {
    const entities: any[] = [];
    
    // Always start with User entity
    entities.push(this.createUserEntity(lowerPrompt));
    
    // Generate entities based on extracted concepts
    extractedEntities.forEach(entityName => {
      if (entityName !== 'User') {
        const entity = this.createEntityByType(entityName, lowerPrompt, businessDomain);
        if (entity) {
          entities.push(entity);
        }
      }
    });
    
    // Add common supporting entities based on domain
    this.addSupportingEntities(entities, businessDomain, lowerPrompt);
    
    return entities;
  }

  private createUserEntity(lowerPrompt: string): any {
    const fields = [
      { name: 'id', type: 'uuid', required: true, unique: true },
      { name: 'email', type: 'string', required: true, unique: true, validation: { email: true } },
      { name: 'password', type: 'string', required: true },
      { name: 'firstName', type: 'string', required: true },
      { name: 'lastName', type: 'string', required: true },
      { name: 'role', type: 'string', required: false, default: 'user' },
      { name: 'isActive', type: 'boolean', required: false, default: true },
      { name: 'createdAt', type: 'date', required: true },
      { name: 'updatedAt', type: 'date', required: true }
    ];
    
    // Add domain-specific fields
    if (lowerPrompt.includes('balance') || lowerPrompt.includes('wallet') || lowerPrompt.includes('money')) {
      fields.push({ name: 'balance', type: 'decimal', required: false, default: false });
    }
    if (lowerPrompt.includes('phone') || lowerPrompt.includes('mobile')) {
      fields.push({ name: 'phone', type: 'string', required: false });
    }
    if (lowerPrompt.includes('address') || lowerPrompt.includes('location')) {
      fields.push({ name: 'address', type: 'text', required: false });
    }
    
    return { name: 'User', fields };
  }

  private createEntityByType(entityName: string, lowerPrompt: string, businessDomain: string): any {
    const entityTemplates: { [key: string]: () => any } = {
      'Post': () => ({
        name: 'Post',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'userId', type: 'uuid', required: true },
          { name: 'title', type: 'string', required: true },
          { name: 'content', type: 'text', required: true },
          { name: 'imageUrl', type: 'string', required: false },
          { name: 'likesCount', type: 'number', required: false, default: 0 },
          { name: 'commentsCount', type: 'number', required: false, default: 0 },
          { name: 'isPublished', type: 'boolean', required: false, default: true },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      }),
      
      'Product': () => ({
        name: 'Product',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'name', type: 'string', required: true },
          { name: 'description', type: 'text', required: false },
          { name: 'price', type: 'decimal', required: true },
          { name: 'stock', type: 'number', required: true },
          { name: 'categoryId', type: 'uuid', required: true },
          { name: 'imageUrl', type: 'string', required: false },
          { name: 'isActive', type: 'boolean', required: true, default: true },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      }),
      
      'Match': () => ({
        name: 'Match',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'homeTeam', type: 'string', required: true },
          { name: 'awayTeam', type: 'string', required: true },
          { name: 'startTime', type: 'date', required: true },
          { name: 'status', type: 'string', required: true, default: 'upcoming' },
          { name: 'result', type: 'string', required: false },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      }),
      
      'Bet': () => ({
        name: 'Bet',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'userId', type: 'uuid', required: true },
          { name: 'matchId', type: 'uuid', required: true },
          { name: 'oddsId', type: 'uuid', required: true },
          { name: 'amount', type: 'decimal', required: true },
          { name: 'potentialWin', type: 'decimal', required: true },
          { name: 'status', type: 'string', required: true, default: 'pending' },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      }),
      
      'Transaction': () => ({
        name: 'Transaction',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'userId', type: 'uuid', required: true },
          { name: 'type', type: 'string', required: true },
          { name: 'amount', type: 'decimal', required: true },
          { name: 'balance', type: 'decimal', required: true },
          { name: 'description', type: 'text', required: false },
          { name: 'status', type: 'string', required: true, default: 'completed' },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      }),
      
      'Order': () => ({
        name: 'Order',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'userId', type: 'uuid', required: true },
          { name: 'total', type: 'decimal', required: true },
          { name: 'status', type: 'string', required: true, default: 'pending' },
          { name: 'shippingAddress', type: 'text', required: true },
          { name: 'paymentMethod', type: 'string', required: false },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      }),
      
      'Category': () => ({
        name: 'Category',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'name', type: 'string', required: true },
          { name: 'description', type: 'text', required: false },
          { name: 'isActive', type: 'boolean', required: true, default: true },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      }),
      
      'Comment': () => ({
        name: 'Comment',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'userId', type: 'uuid', required: true },
          { name: 'postId', type: 'uuid', required: true },
          { name: 'content', type: 'text', required: true },
          { name: 'isApproved', type: 'boolean', required: false, default: true },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      }),
      
      'Message': () => ({
        name: 'Message',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'senderId', type: 'uuid', required: true },
          { name: 'receiverId', type: 'uuid', required: true },
          { name: 'content', type: 'text', required: true },
          { name: 'isRead', type: 'boolean', required: false, default: false },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      }),
      
      'Notification': () => ({
        name: 'Notification',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'userId', type: 'uuid', required: true },
          { name: 'title', type: 'string', required: true },
          { name: 'message', type: 'text', required: true },
          { name: 'type', type: 'string', required: true },
          { name: 'isRead', type: 'boolean', required: false, default: false },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      })
    };
    
    return entityTemplates[entityName]?.() || null;
  }

  private addSupportingEntities(entities: any[], businessDomain: string, lowerPrompt: string): void {
    const entityNames = entities.map(e => e.name);
    
    // Add common supporting entities based on domain and existing entities
    if (businessDomain === 'Betting Platform' && !entityNames.includes('Odds')) {
      entities.push({
        name: 'Odds',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'matchId', type: 'uuid', required: true },
          { name: 'marketType', type: 'string', required: true },
          { name: 'oddsValue', type: 'decimal', required: true },
          { name: 'isActive', type: 'boolean', required: true, default: true },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      });
    }
    
    if (businessDomain === 'E-commerce Platform' && !entityNames.includes('Cart')) {
      entities.push({
        name: 'Cart',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'userId', type: 'uuid', required: true },
          { name: 'productId', type: 'uuid', required: true },
          { name: 'quantity', type: 'number', required: true },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      });
    }
    
    // Add Category if we have content entities but no category
    if ((entityNames.includes('Post') || entityNames.includes('Product')) && !entityNames.includes('Category')) {
      entities.push({
        name: 'Category',
        fields: [
          { name: 'id', type: 'uuid', required: true, unique: true },
          { name: 'name', type: 'string', required: true },
          { name: 'description', type: 'text', required: false },
          { name: 'isActive', type: 'boolean', required: true, default: true },
          { name: 'createdAt', type: 'date', required: true },
          { name: 'updatedAt', type: 'date', required: true }
        ]
      });
    }
  }

  private generateAPIEndpoints(entities: any[]): any[] {
    return entities.map(entity => ({
      resource: entity.name.toLowerCase() + 's',
      operations: ['list', 'get', 'create', 'update', 'delete'],
      middleware: ['auth', 'validate']
    }));
  }

  private fallbackSpec(): EnhancedSpec {
    return this.generateIntelligentFallback('basic backend application');
  }

  private cleanJsonResponse(text: string): string {
    const cleaned = text.replace(/```json\n?/g, '').replace(/```\n?/g, '');
    const s = cleaned.indexOf('{');
    const e = cleaned.lastIndexOf('}') + 1;
    if (s === -1 || e === 0) throw new Error('No JSON object found');
    return cleaned.slice(s, e).trim();
  }
}

class ProfessionalCodeGenerator {
  async generateProject(spec: EnhancedSpec): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const archive = archiver('zip', { zlib: { level: 9 } });
      const chunks: Buffer[] = [];
      archive.on('data', (c) => chunks.push(c));
      archive.on('end', () => resolve(Buffer.concat(chunks)));
      archive.on('error', reject);

      this.generateProjectFiles(archive, spec);
      archive.finalize();
    });
  }

  private generateProjectFiles(archive: archiver.Archiver, spec: EnhancedSpec) {
    // package.json
    const pkg = {
      name: spec.metadata.name.toLowerCase().replace(/\s+/g, '-'),
      version: spec.metadata.version,
      description: spec.metadata.description,
      main: 'dist/server.js',
      type: 'module',
      scripts: {
        dev: 'nodemon src/server.ts',
        build: 'tsc',
        start: 'node dist/server.js',
        test: 'jest',
        'test:watch': 'jest --watch',
        lint: 'eslint src/**/*.ts --fix',
        format: 'prettier --write src/**/*.ts',
        'db:migrate': 'sequelize-cli db:migrate',
        'db:seed': 'sequelize-cli db:seed:all',
        'db:reset': 'sequelize-cli db:migrate:undo:all && npm run db:migrate && npm run db:seed'
      },
      dependencies: {
        express: '^4.18.2', cors: '^2.8.5', helmet: '^7.1.0', compression: '^1.7.4', morgan: '^1.10.0',
        bcryptjs: '^2.4.3', jsonwebtoken: '^9.0.2', joi: '^17.11.0', sequelize: '^6.35.0', mysql2: '^3.6.5',
        dotenv: '^16.3.1', winston: '^3.11.0', 'express-rate-limit': '^7.1.5', 'express-validator': '^7.0.1',
        multer: '^1.4.5-lts.1', nodemailer: '^6.9.7', uuid: '^9.0.1'
      },
      devDependencies: {
        '@types/express': '^4.17.21', '@types/cors': '^2.8.17', '@types/bcryptjs': '^2.4.6', '@types/jsonwebtoken': '^9.0.5',
        '@types/morgan': '^1.9.9', '@types/compression': '^1.7.5', '@types/multer': '^1.4.11', '@types/nodemailer': '^6.4.14',
        '@types/uuid': '^9.0.7', '@types/node': '^20.9.0', '@types/jest': '^29.5.8', typescript: '^5.2.2', nodemon: '^3.0.1',
        'ts-node': '^10.9.1', jest: '^29.7.0', 'ts-jest': '^29.1.1', eslint: '^8.54.0', '@typescript-eslint/parser': '^6.12.0',
        '@typescript-eslint/eslint-plugin': '^6.12.0', prettier: '^3.1.0', 'sequelize-cli': '^6.6.2'
      }
    };
    archive.append(JSON.stringify(pkg, null, 2), { name: 'package.json' });

    // tsconfig.json
    const tsconfig = {
      compilerOptions: {
        target: 'ES2022', module: 'ESNext', moduleResolution: 'Node', allowSyntheticDefaultImports: true,
        esModuleInterop: true, allowJs: true, outDir: 'dist', rootDir: 'src', strict: true, skipLibCheck: true,
        forceConsistentCasingInFileNames: true, resolveJsonModule: true, declaration: true, sourceMap: true,
        baseUrl: './src', paths: { '@/*': ['./*'], '@/config/*': ['./config/*'], '@/controllers/*': ['./controllers/*'], '@/models/*': ['./models/*'], '@/middleware/*': ['./middleware/*'], '@/routes/*': ['./routes/*'], '@/services/*': ['./services/*'], '@/utils/*': ['./utils/*'], '@/types/*': ['./types/*'] }
      },
      include: ['src/**/*'], exclude: ['node_modules', 'dist', '**/*.test.ts']
    };
    archive.append(JSON.stringify(tsconfig, null, 2), { name: 'tsconfig.json' });

    // env example
    archive.append(this.generateEnvFile(spec), { name: '.env.example' });

    // Configs
    archive.append(this.generateDatabaseConfig(), { name: 'src/config/database.ts' });

    // App/server
    archive.append(this.generateServerFile(spec), { name: 'src/server.ts' });
    archive.append(this.generateAppFile(), { name: 'src/app.ts' });

    // Models
    archive.append(this.generateModelsIndex(spec), { name: 'src/models/index.ts' });
    for (const entity of spec.entities) {
      archive.append(this.generateSequelizeModel(entity, spec), { name: `src/models/${entity.name}.ts` });
    }

    // Controllers & Services
    for (const resource of spec.api) {
      archive.append(this.generateProfessionalController(resource, spec), { name: `src/controllers/${resource.resource}Controller.ts` });
      archive.append(this.generateService(resource, spec), { name: `src/services/${resource.resource}Service.ts` });
    }

    // Middleware
    archive.append(this.generateAuthMiddleware(spec), { name: 'src/middleware/auth.ts' });
    archive.append(this.generateValidationMiddleware(), { name: 'src/middleware/validation.ts' });
    archive.append(this.generateErrorMiddleware(), { name: 'src/middleware/errorHandler.ts' });

    // Routes
    archive.append(this.generateRoutesIndex(spec), { name: 'src/routes/index.ts' });
    for (const resource of spec.api) {
      archive.append(this.generateProfessionalRoute(resource, spec), { name: `src/routes/${resource.resource}Routes.ts` });
    }

    // Utils & Types
    archive.append(this.generateAppError(), { name: 'src/utils/AppError.ts' });
    archive.append(this.generateCatchAsync(), { name: 'src/utils/catchAsync.ts' });
    archive.append(this.generateResponseUtils(), { name: 'src/utils/response.ts' });
    archive.append(this.generateValidationRules(spec), { name: 'src/utils/validationRules.ts' });
    archive.append(this.generateTypes(spec), { name: 'src/types/index.ts' });

    // Lint/format/git
    archive.append(this.generateEslintConfig(), { name: '.eslintrc.json' });
    archive.append(this.generatePrettierConfig(), { name: '.prettierrc' });
    archive.append(this.generateGitignore(), { name: '.gitignore' });

    // Docker
    archive.append(this.generateDockerfile(), { name: 'Dockerfile' });
    archive.append(this.generateDockerCompose(spec), { name: 'docker-compose.yml' });

    // Docs
    archive.append(this.generateProfessionalReadme(spec), { name: 'README.md' });
    archive.append(this.generateAPIDocumentation(spec), { name: 'docs/API.md' });

    // Sequelize migrations & seeds
    const now = new Date();
    const ts = `${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2,'0')}${now.getDate().toString().padStart(2,'0')}${now.getHours().toString().padStart(2,'0')}${now.getMinutes().toString().padStart(2,'0')}${now.getSeconds().toString().padStart(2,'0')}`;
    archive.append(this.generateMigration(spec), { name: `src/database/migrations/${ts}-create-tables.js` });
    archive.append(this.generateSeeder(spec), { name: `src/database/seeders/${ts}-demo-data.js` });

    // Sequelize CLI config
    archive.append(this.generateSequelizeConfig(), { name: '.sequelizerc' });
  }

  // ========== Utility generators (strings) ==========
 
  private generateAppError(): string {
    return `export class AppError extends Error {
  public readonly statusCode: number;
  public readonly status: string;
  public readonly isOperational: boolean;
  public readonly errors?: any[];

  constructor(message: string, statusCode: number = 500, errors?: any[]) {
    super(message);
    this.statusCode = statusCode;
    this.status = \`\${statusCode}\`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    this.errors = errors;
    Error.captureStackTrace(this, this.constructor);
  }
}
`;
  }

  private generateCatchAsync(): string { return `import { Request, Response, NextFunction } from 'express';

type AsyncFunction = (req: Request, res: Response, next: NextFunction) => Promise<any>;

export const catchAsync = (fn: AsyncFunction) => {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(next);
  };
};
`; }

  private generateResponseUtils(): string { return `import { Response } from 'express';

interface ApiResponse<T = any> { success: boolean; message: string; data?: T; error?: string; errors?: any[]; timestamp: string; }
interface PaginationInfo { page: number; limit: number; total: number; totalPages: number; hasNextPage: boolean; hasPreviousPage: boolean; }
interface PaginatedResponse<T = any> extends ApiResponse<T[]> { pagination: PaginationInfo; }

export const successResponse = <T>(res: Response, data?: T, message: string = 'Success', statusCode: number = 200): Response => {
  return res.status(statusCode).json({ success: true, message, data, timestamp: new Date().toISOString() } as ApiResponse<T>);
};

export const errorResponse = (res: Response, message: string = 'Error', statusCode: number = 500, errors?: any[]): Response => {
  return res.status(statusCode).json({ success: false, message, errors, timestamp: new Date().toISOString() } as ApiResponse);
};

export const paginatedResponse = <T>(res: Response, result: { items: T[]; pagination: PaginationInfo }, message: string = 'Success', statusCode: number = 200): Response => {
  return res.status(statusCode).json({ success: true, message, data: result.items, pagination: result.pagination, timestamp: new Date().toISOString() } as PaginatedResponse<T>);
};

export const createdResponse = <T>(res: Response, data: T, message: string = 'Created successfully'): Response => successResponse(res, data, message, 201);
export const noContentResponse = (res: Response): Response => res.status(204).send();
export const notFoundResponse = (res: Response, message: string = 'Resource not found'): Response => errorResponse(res, message, 404);
export const validationErrorResponse = (res: Response, errors: any[], message: string = 'Validation failed'): Response => errorResponse(res, message, 400, errors);
export const unauthorizedResponse = (res: Response, message: string = 'Unauthorized'): Response => errorResponse(res, message, 401);
export const forbiddenResponse = (res: Response, message: string = 'Forbidden'): Response => errorResponse(res, message, 403);
`; }

  private generateValidationRules(spec: EnhancedSpec): string {
    let out = 'import { body, param, query } from \'express-validator\';\n\n';
    for (const entity of spec.entities) {
      const createVal = entity.fields.filter(f => f.name !== 'id').map(f => {
        let v = `body('${f.name}')`;
        switch (f.type) {
          case 'string': case 'text': v += '.isString()'; if ((f as any).validation?.minLength) v += `.isLength({ min: ${(f as any).validation.minLength} })`; if ((f as any).validation?.maxLength) v += `.isLength({ max: ${(f as any).validation.maxLength} })`; if ((f as any).validation?.email) v += '.isEmail()'; break;
          case 'number': case 'decimal': v += '.isNumeric()'; if ((f as any).validation?.min) v += `.isFloat({ min: ${(f as any).validation.min} })`; if ((f as any).validation?.max) v += `.isFloat({ max: ${(f as any).validation.max} })`; break;
          case 'boolean': v += '.isBoolean()'; break;
          case 'date': v += '.isISO8601()'; break;
          case 'uuid': v += '.isUUID()'; break;
        }
        v += f.required ? '.notEmpty()' : '.optional()';
        v += `.withMessage('${f.name} validation failed')`;
        return `  ${v}`;
      }).join(',\n');

      const updateVal = entity.fields.filter(f => f.name !== 'id').map(f => {
        let v = `body('${f.name}').optional()`;
        switch (f.type) {
          case 'string': case 'text': v += '.isString()'; if ((f as any).validation?.minLength) v += `.isLength({ min: ${(f as any).validation.minLength} })`; if ((f as any).validation?.maxLength) v += `.isLength({ max: ${(f as any).validation.maxLength} })`; if ((f as any).validation?.email) v += '.isEmail()'; break;
          case 'number': case 'decimal': v += '.isNumeric()'; break;
          case 'boolean': v += '.isBoolean()'; break;
          case 'date': v += '.isISO8601()'; break;
          case 'uuid': v += '.isUUID()'; break;
        }
        v += `.withMessage('${f.name} validation failed')`;
        return `  ${v}`;
      }).join(',\n');

      out += `// ${entity.name} validation rules\nexport const ${entity.name.toLowerCase()}ValidationRules = {\n  create: [\n${createVal}\n  ],\n  \n  update: [\n    param('id').isUUID().withMessage('Invalid ID format'),\n${updateVal}\n  ],\n\n  get: [\n    param('id').isUUID().withMessage('Invalid ID format')\n  ]\n};\n\n`;
    }
    out += `// Common validation rules\nexport const commonValidationRules = {\n  pagination: [\n    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),\n    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),\n    query('sortBy').optional().isString().withMessage('SortBy must be a string'),\n    query('sortOrder').optional().isIn(['ASC', 'DESC']).withMessage('SortOrder must be ASC or DESC')\n  ],\n\n  search: [\n    query('search').optional().isString().isLength({ min: 1, max: 100 }).withMessage('Search query must be 1-100 characters')\n  ],\n\n  bulkOperation: [\n    body('ids').isArray({ min: 1 }).withMessage('IDs array is required'),\n    body('ids.*').isUUID().withMessage('Each ID must be a valid UUID')\n  ]\n};\n`;
    return out;
  }

  private generateRoutesIndex(spec: EnhancedSpec): string {
    const routeImports = spec.api.map(r => `import ${r.resource}Routes from './${r.resource}Routes.js';`).join('\n');
    const regs = spec.api.map(r => `router.use('/${r.resource}', ${r.resource}Routes);`).join('\n');
    return `import { Router } from 'express';\n${routeImports}\n\nconst router = Router();\n\n// Health check\nrouter.get('/health', (req, res) => {\n  res.status(200).json({\n    success: true,\n    message: 'API is healthy',\n    timestamp: new Date().toISOString(),\n    environment: process.env.NODE_ENV,\n    version: process.env.npm_package_version || '1.0.0'\n  });\n});\n\n// API routes\n${regs}\n\n// Catch-all route for undefined endpoints\nrouter.use('*', (req, res) => {\n  res.status(404).json({\n    success: false,\n    message: \`Route \${req.originalUrl} not found\`,\n    timestamp: new Date().toISOString()\n  });\n});\n\nexport default router;\n`;
  }

  private generateProfessionalRoute(resource: any, spec: EnhancedSpec): string {
    const resourceName = resource.resource;
    const modelName = resourceName.charAt(0).toUpperCase() + resourceName.slice(1);
    const controllerName = `${modelName}Controller`;
    const fields = (spec.entities.find(e => e.name.toLowerCase() === resourceName)?.fields || []).filter(f => f.name !== 'id').map(f => f.name).join("', '");
    return `import { Router } from 'express';\nimport { ${controllerName} } from '../controllers/${resourceName}Controller.js';\nimport { authenticate, authorize, optionalAuth, requirePermission } from '../middleware/auth.js';\nimport { validate, validatePagination, sanitizeBody } from '../middleware/validation.js';\nimport { ${resource.resource}ValidationRules, commonValidationRules } from '../utils/validationRules.js';\n\nconst router = Router();\nconst ${resource.resource}Controller = new ${controllerName}();\n\n// Public routes (if any)\n${resource.operations.includes('list') && !(resource.middleware||[]).includes('auth') ? `router.get('/',\n  validatePagination,\n  validate(commonValidationRules.pagination),\n  validate(commonValidationRules.search),\n  ${resource.resource}Controller.getAll\n);` : ''}\n\n${resource.operations.includes('get') && !(resource.middleware||[]).includes('auth') ? `router.get('/:id',\n  validate(${resource.resource}ValidationRules.get),\n  ${resource.resource}Controller.getById\n);` : ''}\n\n// Apply authentication to protected routes\nrouter.use(authenticate);\n\n${resource.operations.includes('list') && (resource.middleware||[]).includes('auth') ? `router.get('/',\n  authorize('user','admin'),\n  validatePagination,\n  validate(commonValidationRules.pagination),\n  validate(commonValidationRules.search),\n  ${resource.resource}Controller.getAll\n);` : ''}\n\n${resource.operations.includes('get') && (resource.middleware||[]).includes('auth') ? `router.get('/:id',\n  validate(${resource.resource}ValidationRules.get),\n  requirePermission('${resourceName}', 'read'),\n  ${resource.resource}Controller.getById\n);` : ''}\n\n${resource.operations.includes('create') ? `router.post('/',\n  authorize('user','admin'),\n  sanitizeBody(['${fields}'].filter(Boolean)),\n  validate(${resource.resource}ValidationRules.create),\n  requirePermission('${resourceName}', 'create'),\n  ${resource.resource}Controller.create\n);` : ''}\n\n${resource.operations.includes('update') ? `router.put('/:id',\n  authorize('user','admin'),\n  sanitizeBody(['${fields}'].filter(Boolean)),\n  validate(${resource.resource}ValidationRules.update),\n  requirePermission('${resourceName}', 'update'),\n  ${resource.resource}Controller.update\n);` : ''}\n\n${resource.operations.includes('delete') ? `router.delete('/:id',\n  authorize('admin'),\n  validate(${resource.resource}ValidationRules.get),\n  requirePermission('${resourceName}', 'delete'),\n  ${resource.resource}Controller.delete\n);` : ''}\n\n${resource.operations.includes('search') ? `router.post('/search',\n  authorize('user','admin'),\n  validate(commonValidationRules.search),\n  ${resource.resource}Controller.search\n);` : ''}\n\n// Bulk operations (admin only)\nrouter.post('/bulk/create', authorize('admin'), validate(commonValidationRules.bulkOperation), ${resource.resource}Controller.bulkCreate);\nrouter.patch('/bulk/update', authorize('admin'), validate(commonValidationRules.bulkOperation), ${resource.resource}Controller.bulkUpdate);\nrouter.delete('/bulk/delete', authorize('admin'), validate(commonValidationRules.bulkOperation), ${resource.resource}Controller.bulkDelete);\n\nexport default router;\n`;
  }

  private getTypeScriptType(fieldType: string): string {
    switch (fieldType) {
      case 'uuid': case 'string': case 'text': return 'string';
      case 'number': case 'decimal': return 'number';
      case 'boolean': return 'boolean';
      case 'date': return 'Date';
      case 'array': return 'any[]';
      case 'object': case 'json': return 'object';
      default: return 'string';
    }
  }

  private generateTypes(spec: EnhancedSpec): string {
    let out = '// Global type definitions\n\n';
    for (const entity of spec.entities) {
      out += `export interface ${entity.name} {\n${entity.fields.map(f => `  ${f.name}: ${this.getTypeScriptType(f.type)};`).join('\n')}\n  readonly createdAt: Date;\n  readonly updatedAt: Date;\n  readonly deletedAt?: Date;\n}\n\nexport interface ${entity.name}CreateInput {\n${entity.fields.filter(f=>f.name!=='id').map(f => `  ${f.name}${f.required ? '' : '?'}: ${this.getTypeScriptType(f.type)};`).join('\n')}\n}\n\nexport interface ${entity.name}UpdateInput {\n${entity.fields.filter(f=>f.name!=='id').map(f => `  ${f.name}?: ${this.getTypeScriptType(f.type)};`).join('\n')}\n}\n\n`;
    }
    out += `export interface ApiResponse<T = any> { success: boolean; message: string; data?: T; error?: string; errors?: ValidationError[]; timestamp: string; }\nexport interface PaginatedResponse<T = any> extends ApiResponse<T[]> { pagination: PaginationInfo; }\nexport interface PaginationInfo { page: number; limit: number; total: number; totalPages: number; hasNextPage: boolean; hasPreviousPage: boolean; }\nexport interface ValidationError { field: string; message: string; value?: any; }\nexport interface SearchOptions { query: string; filters?: Record<string, any>; sortBy?: string; sortOrder?: 'ASC' | 'DESC'; }\nexport interface BulkOperation { ids: string[]; updates?: Record<string, any>; }\nexport interface AuthUser { id: string; email: string; firstName: string; lastName: string; role: string; roles?: string[]; isActive: boolean; }\nexport interface LoginRequest { email: string; password: string; }\nexport interface RegisterRequest extends LoginRequest { firstName: string; lastName: string; phone?: string; }\nexport interface TokenResponse { accessToken: string; refreshToken: string; expiresIn: number; user: AuthUser; }\n\ndeclare global { namespace Express { interface Request { user?: AuthUser; token?: string; } } }\n`;
    return out;
  }

  private generateEslintConfig(): string { return `{
  "env": { "es2022": true, "node": true },
  "extends": [ "eslint:recommended", "@typescript-eslint/recommended", "@typescript-eslint/recommended-requiring-type-checking" ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": { "ecmaVersion": "latest", "sourceType": "module", "project": "./tsconfig.json" },
  "plugins": ["@typescript-eslint"],
  "rules": { "indent": ["error", 2], "linebreak-style": ["error", "unix"], "quotes": ["error", "single"], "semi": ["error", "always"], "@typescript-eslint/no-unused-vars": "error", "@typescript-eslint/explicit-function-return-type": "warn", "@typescript-eslint/no-explicit-any": "warn", "@typescript-eslint/no-unsafe-assignment": "off", "@typescript-eslint/no-unsafe-member-access": "off", "@typescript-eslint/no-unsafe-call": "off" },
  "ignorePatterns": ["dist/", "node_modules/", "*.js"]
}`; }

  private generatePrettierConfig(): string { return `{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false,
  "bracketSpacing": true,
  "arrowParens": "avoid"
}`; }

  private generateGitignore(): string { return `node_modules/\n npm-debug.log*\n yarn-debug.log*\n yarn-error.log*\n pids\n *.pid\n *.seed\n *.pid.lock\n lib-cov\n coverage/\n *.lcov\n .nyc_output\n .grunt\n bower_components\n .lock-wscript\n build/Release\n jspm_packages/\n *.tsbuildinfo\n .npm\n .eslintcache\n *.tgz\n .yarn-integrity\n .env\n .env.test\n .env.production\n .env.local\n .cache\n .parcel-cache\n .next\n .nuxt\n .vuepress/dist\n .serverless/\n .fusebox/\n .dynamodb/\n .tern-port\n dist/\n build/\n logs/\n *.log\n *.sqlite\n *.sqlite3\n .vscode/\n .idea/\n *.swp\n *.swo\n .DS_Store\n Thumbs.db\n uploads/\n temp/\n *.backup\n *.bak\n`; }

  private generateDockerfile(): string { return `FROM node:20-alpine AS builder\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --only=production && npm cache clean --force\nCOPY . .\nRUN npm run build\n\nFROM node:20-alpine AS production\nWORKDIR /app\nRUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001\nCOPY --from=builder /app/dist ./dist\nCOPY --from=builder /app/node_modules ./node_modules\nCOPY --from=builder /app/package*.json ./\nRUN chown -R nodejs:nodejs /app\nUSER nodejs\nEXPOSE 3000\nHEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\ \n  CMD node -e "const http = require('http'); \\n    const req = http.request('http://localhost:3000/api/health', res => { \\\n      process.exit(res.statusCode === 200 ? 0 : 1); \\n    }); \\n    req.on('error', () => process.exit(1)); \\n    req.end();"\nCMD ["node", "dist/server.js"]\n`; }

  private generateDockerCompose(spec: EnhancedSpec): string {
    const dbName = spec.metadata.name.toLowerCase().replace(/\s+/g, '_');
    return `version: '3.8'\n\nservices:\n  app:\n    build: .\n    ports:\n      - "3000:3000"\n    environment:\n      - NODE_ENV=production\n      - DB_HOST=db\n      - DB_PORT=3306\n      - DB_NAME=${dbName}_db\n      - DB_USER=root\n      - DB_PASSWORD=rootpassword\n      - JWT_SECRET=your-super-secret-jwt-key\n      - CORS_ORIGIN=http://localhost:3000\n    depends_on:\n      db:\n        condition: service_healthy\n    volumes:\n      - ./uploads:/app/uploads\n    restart: unless-stopped\n    networks:\n      - app-network\n\n  db:\n    image: mysql:8.0\n    environment:\n      - MYSQL_ROOT_PASSWORD=rootpassword\n      - MYSQL_DATABASE=${dbName}_db\n      - MYSQL_USER=appuser\n      - MYSQL_PASSWORD=apppassword\n    volumes:\n      - mysql_data:/var/lib/mysql\n    ports:\n      - "3306:3306"\n    restart: unless-stopped\n    healthcheck:\n      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]\n      timeout: 20s\n      retries: 10\n    networks:\n      - app-network\n\n  redis:\n    image: redis:7-alpine\n    ports:\n      - "6379:6379"\n    volumes:\n      - redis_data:/data\n    restart: unless-stopped\n    networks:\n      - app-network\n\nvolumes:\n  mysql_data:\n  redis_data:\n\nnetworks:\n  app-network:\n    driver: bridge\n`;
  }

  private generateSequelizeConfig(): string { return `const path = require('path');\n\nmodule.exports = {\n  'config': path.resolve('./src/config/database.js'),\n  'models-path': path.resolve('./src/models'),\n  'seeders-path': path.resolve('./src/database/seeders'),\n  'migrations-path': path.resolve('./src/database/migrations')\n};\n`; }

  private generateMigration(spec: EnhancedSpec): string {
    const tables = spec.entities.map((entity) => {
      const fields = entity.fields.map((field) => {
        let t = 'Sequelize.STRING';
        const opts: string[] = [];
        switch (field.type) {
          case 'uuid': t = 'Sequelize.UUID'; if (field.name === 'id') { opts.push('primaryKey: true'); opts.push('defaultValue: Sequelize.UUIDV4'); } break;
          case 'string': t = 'Sequelize.STRING'; break;
          case 'text': t = 'Sequelize.TEXT'; break;
          case 'number': t = 'Sequelize.INTEGER'; break;
          case 'decimal': t = 'Sequelize.DECIMAL(10, 2)'; break;
          case 'boolean': t = 'Sequelize.BOOLEAN'; break;
          case 'date': t = 'Sequelize.DATE'; break;
          case 'json': case 'array': case 'object': t = 'Sequelize.JSON'; break;
        }
        if (!field.required && field.name !== 'id') opts.push('allowNull: true');
        else if (field.name !== 'id') opts.push('allowNull: false');
        if (field.unique && field.name !== 'id') opts.push('unique: true');
        const optStr = opts.length ? `, { ${opts.join(', ')} }` : '';
        return `        ${field.name}: {\n          type: ${t}${optStr}\n        }`;
      }).join(',\n');
      return `      await queryInterface.createTable('${entity.name.toLowerCase()}s', {\n${fields},\n        created_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },\n        updated_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },\n        deleted_at: { type: Sequelize.DATE, allowNull: true }\n      });`;
    }).join('\n\n');

    return `'use strict';\n\nmodule.exports = {\n  async up(queryInterface, Sequelize) {\n${tables}\n\n    // Add indexes for better performance\n${spec.entities.map((entity) => {
      // placeholder indexes
      return `    // Add custom indexes for ${entity.name.toLowerCase()}s if needed`;
    }).join('\n')}\n  },\n\n  async down(queryInterface, Sequelize) {\n${[...spec.entities].reverse().map((entity) => `    await queryInterface.dropTable('${entity.name.toLowerCase()}s');`).join('\n')}\n  }\n};\n`;
  }

  private generateSeeder(spec: EnhancedSpec): string {
    return `'use strict';\n\nmodule.exports = {\n  async up(queryInterface, Sequelize) {\n    // TODO: seed initial data\n  },\n  async down(queryInterface, Sequelize) {\n${spec.entities.map((e) => `    await queryInterface.bulkDelete('${e.name.toLowerCase()}s', null, {});`).join('\n')}\n  }\n};\n`;
  }

  private generateProfessionalReadme(spec: EnhancedSpec): string { return `# ${spec.metadata.name} - Professional Backend API\n\n${spec.metadata.description}\n\nA production-ready Node.js backend built with Express.js, TypeScript, Sequelize, and MySQL.\n`; }

  private generateAPIDocumentation(spec: EnhancedSpec): string { return `# API Documentation - ${spec.metadata.name}\n`; }

  private generateEnvFile(spec: EnhancedSpec): string {
    let env = `DB_HOST=localhost\nDB_PORT=3306\nDB_NAME=${spec.metadata.name.toLowerCase().replace(/\s+/g,'_')}_db\nDB_USER=root\nDB_PASSWORD=\nDB_DIALECT=mysql\n\nJWT_SECRET=your-super-secret-jwt-key-change-in-production\nJWT_EXPIRES_IN=7d\nJWT_REFRESH_EXPIRES_IN=30d\n\nNODE_ENV=development\nPORT=3000\n\nCORS_ORIGIN=http://localhost:3000,http://localhost:3001\n\nRATE_LIMIT_WINDOW_MS=900000\nRATE_LIMIT_MAX_REQUESTS=100\n\nSMTP_HOST=smtp.gmail.com\nSMTP_PORT=587\nSMTP_USER=your-email@gmail.com\nSMTP_PASS=your-app-password\nEMAIL_FROM=noreply@${spec.metadata.name.toLowerCase()}.com\n\nUPLOAD_MAX_SIZE=10485760\nUPLOAD_PATH=uploads/\n\nLOG_LEVEL=info\n`;
    for (const v of spec.env) {
      if (!env.includes(`\n${v.name}=`)) env += `\n# ${v.description}\n${v.name}=${(v as any).default || ''}\n`;
    }
    return env;
  }

  private generateDatabaseConfig(): string { return `import { Sequelize } from 'sequelize';\nimport dotenv from 'dotenv';\ndotenv.config();\n\nconst { DB_HOST = 'localhost', DB_PORT = '3306', DB_NAME, DB_USER = 'root', DB_PASSWORD = '', DB_DIALECT = 'mysql', NODE_ENV = 'development' } = process.env as Record<string,string>;\n\nif (!DB_NAME) { throw new Error('DB_NAME environment variable is required'); }\n\nconst sequelize = new Sequelize({\n  host: DB_HOST,\n  port: parseInt(DB_PORT, 10),\n  database: DB_NAME,\n  username: DB_USER,\n  password: DB_PASSWORD,\n  dialect: DB_DIALECT as any,\n  logging: NODE_ENV === 'development' ? console.log : false,\n  pool: { max: 5, min: 0, acquire: 30000, idle: 10000 },\n  define: { timestamps: true, underscored: true, paranoid: true },\n});\n\nexport { sequelize };\n\nexport const connectDatabase = async (): Promise<void> => {\n  try {\n    await sequelize.authenticate();\n    console.log('✅ Database connection established successfully.');\n    if (NODE_ENV === 'development') {\n      await sequelize.sync({ alter: true });\n      console.log('📊 Database models synchronized.');\n    }\n  } catch (error) {\n    console.error('❌ Unable to connect to the database:', error);\n    throw error;\n  }\n};\n`; }

  private generateServerFile(spec: EnhancedSpec): string { return `import app from './app.js';\nimport { connectDatabase } from './config/database.js';\n\nconst PORT = process.env.PORT || 3000;\n\nconst startServer = async (): Promise<void> => {\n  try {\n    await connectDatabase();\n    const server = app.listen(PORT, () => {\n      console.log(\`🚀 ${spec.metadata.name} server running on port \${PORT}\`);\n      console.log(\`🔗 API Base URL: http://localhost:\${PORT}/api\`);\n    });\n    process.on('SIGTERM', () => { console.log('SIGTERM received'); server.close(() => process.exit(0)); });\n    process.on('SIGINT', () => { console.log('SIGINT received'); server.close(() => process.exit(0)); });\n  } catch (error) { console.error('Failed to start server:', error); process.exit(1); }\n};\n\nprocess.on('unhandledRejection', (err: any) => { console.error('Unhandled Rejection:', err); process.exit(1); });\nprocess.on('uncaughtException', (err: Error) => { console.error('Uncaught Exception:', err); process.exit(1); });\n\nstartServer();\n`; }

  private generateAppFile(): string { return `import express from 'express';\nimport cors from 'cors';\nimport helmet from 'helmet';\nimport compression from 'compression';\nimport morgan from 'morgan';\nimport rateLimit from 'express-rate-limit';\n\nimport routes from './routes/index.js';\nimport { errorHandler, notFound } from './middleware/errorHandler.js';\n\nconst app = express();\n\napp.use(helmet());\napp.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'], credentials: true }));\nconst limiter = rateLimit({ windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10) });\napp.use('/api', limiter);\napp.use(express.json({ limit: '10mb' }));\napp.use(express.urlencoded({ extended: true, limit: '10mb' }));\napp.use(compression());\napp.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));\napp.set('trust proxy', 1);\n\napp.use('/api', routes);\napp.get('/health', (_req, res) => res.status(200).json({ success: true, message: 'Service is healthy', timestamp: new Date().toISOString() }));\napp.use(notFound);\napp.use(errorHandler);\n\nexport default app;\n`; }

  private generateModelsIndex(spec: EnhancedSpec): string {
    const imports = spec.entities.map((e) => `import { ${e.name} } from './${e.name}.js';`).join('\n');
    const exports = spec.entities.map((e) => e.name).join(',\n  ');
    const assoc = spec.entities.map((e) => `  ${e.name}.associate({ ${spec.entities.map(s => s.name).join(', ')} });`).join('\n');
    return `import { sequelize } from '../config/database.js';\n${imports}\n\nconst initializeAssociations = (): void => {\n${assoc}\n};\n\nexport {\n  sequelize,\n  ${exports}\n};\n\nexport { initializeAssociations };\n\nexport const syncDatabase = async (): Promise<void> => {\n  try {\n    await sequelize.authenticate();\n    initializeAssociations();\n  } catch (error) {\n    console.error('Unable to connect to the database:', error);\n    throw error;\n  }\n};\n`;
  }

  private generateProfessionalController(resource: any, spec: EnhancedSpec): string {
    const resourceName = resource.resource;
    const modelName = resourceName.charAt(0).toUpperCase() + resourceName.slice(1);
    const serviceName = `${modelName}Service`;
    return `import { Request, Response } from 'express';\nimport { ${serviceName} } from '../services/${resourceName}Service.js';\nimport { catchAsync } from '../utils/catchAsync.js';\nimport { AppError } from '../utils/AppError.js';\nimport { successResponse, paginatedResponse } from '../utils/response.js';\n\nexport class ${modelName}Controller {\n  private ${resourceName}Service: ${serviceName};\n  constructor() { this.${resourceName}Service = new ${serviceName}(); }\n  ${resource.operations.includes('list') ? `getAll = catchAsync(async (req: Request, res: Response) => {\n    const page = parseInt(req.query.page as string) || 1;\n    const limit = parseInt(req.query.limit as string) || 10;\n    const sortBy = (req.query.sortBy as string) || 'createdAt';\n    const sortOrder = ((req.query.sortOrder as string) || 'DESC').toUpperCase() as 'ASC' | 'DESC';\n    const search = (req.query.search as string) || '';\n    const filters: any = { ...req.query }; delete filters.page; delete filters.limit; delete filters.sortBy; delete filters.sortOrder; delete filters.search;\n    const result = await this.${resourceName}Service.findAll({ page, limit, sortBy, sortOrder, search, filters });\n    paginatedResponse(res, result, '${modelName}s retrieved successfully');\n  });` : ''}\n  ${resource.operations.includes('get') ? `getById = catchAsync(async (req: Request, res: Response) => {\n    const { id } = req.params;\n    const ${resourceName} = await this.${resourceName}Service.findById(id);\n    if (!${resourceName}) throw new AppError('${modelName} not found', 404);\n    successResponse(res, ${resourceName}, '${modelName} retrieved successfully');\n  });` : ''}\n  ${resource.operations.includes('create') ? `create = catchAsync(async (req: Request, res: Response) => {\n    if (req.user?.id) req.body.createdBy = req.user.id;\n    const ${resourceName} = await this.${resourceName}Service.create(req.body);\n    successResponse(res, ${resourceName}, '${modelName} created successfully', 201);\n  });` : ''}\n  ${resource.operations.includes('update') ? `update = catchAsync(async (req: Request, res: Response) => {\n    const { id } = req.params;\n    if (req.user?.id) req.body.updatedBy = req.user.id;\n    const ${resourceName} = await this.${resourceName}Service.update(id, req.body);\n    successResponse(res, ${resourceName}, '${modelName} updated successfully');\n  });` : ''}\n  ${resource.operations.includes('delete') ? `delete = catchAsync(async (req: Request, res: Response) => {\n    const { id } = req.params;\n    await this.${resourceName}Service.delete(id);\n    successResponse(res, null, '${modelName} deleted successfully');\n  });` : ''}\n  ${resource.operations.includes('search') ? `search = catchAsync(async (req: Request, res: Response) => {\n    const { query, filters } = req.body;\n    const result = await this.${resourceName}Service.search(query, filters);\n    successResponse(res, result, 'Search completed successfully');\n  });` : ''}\n  bulkCreate = catchAsync(async (req: Request, res: Response) => { const { items } = req.body; const result = await this.${resourceName}Service.bulkCreate(items); successResponse(res, result, '${modelName}s created successfully', 201); });\n  bulkUpdate = catchAsync(async (req: Request, res: Response) => { const { ids, updates } = req.body; const result = await this.${resourceName}Service.bulkUpdate(ids, updates); successResponse(res, result, '${modelName}s updated successfully'); });\n  bulkDelete = catchAsync(async (req: Request, res: Response) => { const { ids } = req.body; await this.${resourceName}Service.bulkDelete(ids); successResponse(res, null, '${modelName}s deleted successfully'); });\n}\n`;
  }

  private generateService(resource: any, spec: EnhancedSpec): string {
    const resourceName = resource.resource;
    const modelName = resourceName.charAt(0).toUpperCase() + resourceName.slice(1);
    return `import { Op, FindOptions, WhereOptions } from 'sequelize';\nimport { ${modelName} } from '../models/${modelName}.js';\nimport { AppError } from '../utils/AppError.js';\n\ninterface PaginationOptions { page: number; limit: number; sortBy?: string; sortOrder?: 'ASC' | 'DESC'; search?: string; filters?: Record<string, any>; }\ninterface PaginatedResult<T> { items: T[]; pagination: { page: number; limit: number; total: number; totalPages: number; hasNextPage: boolean; hasPreviousPage: boolean; }; }\n\nexport class ${modelName}Service {\n  async findAll(options: PaginationOptions): Promise<PaginatedResult<${modelName}>> {\n    const { page, limit, sortBy = 'createdAt', sortOrder = 'DESC', search, filters = {} } = options;\n    const offset = (page - 1) * limit;\n    const where: WhereOptions = { ...filters };\n    if (search) { const searchFields = ['name','title','description']; where[Op.or] = searchFields.map(f => ({ [f]: { [Op.like]: \`%\${search}%\` } })); }\n    const findOptions: FindOptions = { where, limit, offset, order: [[sortBy as string, sortOrder]] };\n    const { count, rows } = await ${modelName}.findAndCountAll(findOptions);\n    return { items: rows, pagination: { page, limit, total: count, totalPages: Math.ceil(count/limit), hasNextPage: page < Math.ceil(count/limit), hasPreviousPage: page > 1 } };\n  }\n  async findById(id: string): Promise<${modelName} | null> { return ${modelName}.findByPk(id); }\n  async findOne(conditions: WhereOptions): Promise<${modelName} | null> { return ${modelName}.findOne({ where: conditions }); }\n  async create(data: any): Promise<${modelName}> { if (!data) throw new AppError('Data is required', 400); return ${modelName}.create(data); }\n  async update(id: string, data: any): Promise<${modelName}> { const item = await this.findById(id); if (!item) throw new AppError('${modelName} not found', 404); await item.update(data); await item.reload(); return item; }\n  async delete(id: string): Promise<void> { const item = await this.findById(id); if (!item) throw new AppError('${modelName} not found', 404); await item.destroy(); }\n  async bulkCreate(items: any[]): Promise<${modelName}[]> { return ${modelName}.bulkCreate(items); }\n  async bulkUpdate(ids: string[], updates: any): Promise<number> { const [affected] = await ${modelName}.update(updates, { where: { id: { [Op.in]: ids } } }); return affected; }\n  async bulkDelete(ids: string[]): Promise<number> { return ${modelName}.destroy({ where: { id: { [Op.in]: ids } } }); }\n  async search(query: string, filters: Record<string, any> = {}): Promise<${modelName}[]> { return ${modelName}.findAll({ where: { ...filters, [Op.or]: [ { name: { [Op.like]: \`%\${query}%\` } }, { description: { [Op.like]: \`%\${query}%\` } } ] }, limit: 50 }); }\n}\n`;
  }

  private generateAuthMiddleware(spec: EnhancedSpec): string {
    return `import { Request, Response, NextFunction } from 'express';\nimport jwt from 'jsonwebtoken';\nimport { AppError } from '../utils/AppError.js';\n\ndeclare global { namespace Express { interface Request { user?: any; token?: string; } } }\n\nexport const authenticate = async (req: Request, res: Response, next: NextFunction) => {\n  const authHeader = req.headers.authorization;\n  let token: string | undefined;\n  if (authHeader && authHeader.startsWith('Bearer ')) token = authHeader.substring(7);\n  if (!token) return next(new AppError('Access denied. No token provided.', 401));\n  try {\n    const secret = process.env.JWT_SECRET;\n    if (!secret) return next(new AppError('JWT secret not configured', 500));\n    const decoded = jwt.verify(token, secret) as { userId: string; iat: number; exp: number };\n    (req as any).user = { id: decoded.userId, role: 'user', isActive: true };\n    req.token = token;\n    next();\n  } catch (e: any) { if (e.name === 'TokenExpiredError') next(new AppError('Token has expired', 401)); else next(new AppError('Invalid token', 401)); }\n};\n\nexport const optionalAuth = async (req: Request, res: Response, next: NextFunction) => {\n  const authHeader = req.headers.authorization;\n  if (authHeader?.startsWith('Bearer ')) { try { const token = authHeader.substring(7); const secret = process.env.JWT_SECRET; if (secret) { const decoded = jwt.verify(token, secret) as any; (req as any).user = { id: decoded.userId, role: 'user', isActive: true }; req.token = token; } } catch {} }\n  next();\n};\n\nexport const authorize = (...roles: string[]) => { return (req: Request, _res: Response, next: NextFunction) => { if (!req.user) return next(new AppError('Authentication required.', 401)); const userRoles = Array.isArray((req.user as any).roles) ? (req.user as any).roles : [(req.user as any).role || 'user']; const has = roles.some(r => userRoles.includes(r)); if (!has) return next(new AppError('Access denied. Insufficient permissions.', 403)); next(); }; };\n\nexport const requirePermission = (_resource: string, _action: string) => { return (req: Request, _res: Response, next: NextFunction) => { if (!req.user) return next(new AppError('Authentication required.', 401)); next(); }; };\n`;
  }

  private generateValidationMiddleware(): string { return `import { Request, Response, NextFunction } from 'express';\nimport { validationResult, ValidationChain } from 'express-validator';\nimport { AppError } from '../utils/AppError.js';\n\nexport const handleValidationErrors = (req: Request, _res: Response, _next: NextFunction) => {\n  const errors = validationResult(req);\n  if (!errors.isEmpty()) { const msgs = errors.array().map(e => ({ field: e.param, message: e.msg, value: e.value })); throw new AppError('Validation failed', 400, msgs); }\n  _next();\n};\n\nexport const validate = (validations: ValidationChain[]) => { return async (req: Request, res: Response, next: NextFunction) => { await Promise.all(validations.map(v => v.run(req))); handleValidationErrors(req, res, next); }; };\n\nexport const sanitizeBody = (allowed: string[]) => { return (req: Request, _res: Response, next: NextFunction) => { if (req.body && typeof req.body === 'object') { const b: any = {}; allowed.forEach(f => { if (Object.prototype.hasOwnProperty.call(req.body, f)) b[f] = req.body[f]; }); req.body = b; } next(); }; };\n\nexport const validatePagination = (req: Request, _res: Response, next: NextFunction) => { const page = parseInt(req.query.page as string) || 1; const limit = parseInt(req.query.limit as string) || 10; if (page < 1) throw new AppError('Page must be greater than 0', 400); if (limit < 1 || limit > 100) throw new AppError('Limit must be between 1 and 100', 400); req.query.page = page.toString(); req.query.limit = limit.toString(); next(); };\n`; }

  private generateErrorMiddleware(): string {
    return `import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/AppError.js';

export class CustomError extends Error {
  statusCode: number;
  status: string;
  isOperational: boolean;
  errors?: any[];

  constructor(message: string, statusCode: number = 500, errors?: any[]) {
    super(message);
    this.statusCode = statusCode;
    this.status = \`\${statusCode}\`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    this.errors = errors;
    Error.captureStackTrace(this, this.constructor);
  }
}

const sendErrorDev = (err: CustomError, res: Response) => {
  res.status(err.statusCode).json({
    success: false,
    error: err,
    message: err.message,
    stack: err.stack,
    errors: err.errors
  });
};

const sendErrorProd = (err: CustomError, res: Response) => {
  if (err.isOperational) {
    res.status(err.statusCode).json({
      success: false,
      message: err.message,
      errors: err.errors
    });
  } else {
    console.error('ERROR 💥', err);
    res.status(500).json({
      success: false,
      message: 'Something went wrong!'
    });
  }
};

export const errorHandler = (
  err: any,
  _req: Request,
  res: Response,
  _next: NextFunction
): void => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else {
    sendErrorProd(err, res);
  }
};

export const notFound = (
  req: Request,
  _res: Response,
  next: NextFunction
): void => {
  next(new CustomError(\`Route \${req.originalUrl} not found\`, 404));
};

export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};
`;
  }

  private generateSequelizeModel(entity: any, spec: EnhancedSpec): string {
    const fieldLines = entity.fields.map((f: any) => {
      let t = 'DataTypes.STRING';
      const opts: string[] = [];
      switch (f.type) {
        case 'uuid': t = 'DataTypes.UUID'; if (f.name === 'id') { opts.push('primaryKey: true'); opts.push('defaultValue: DataTypes.UUIDV4'); } break;
        case 'string': t = f.validation?.maxLength ? `DataTypes.STRING(${f.validation.maxLength})` : 'DataTypes.STRING'; break;
        case 'text': t = 'DataTypes.TEXT'; break;
        case 'number': t = 'DataTypes.INTEGER'; break;
        case 'decimal': t = 'DataTypes.DECIMAL(10, 2)'; break;
        case 'boolean': t = 'DataTypes.BOOLEAN'; break;
        case 'date': t = 'DataTypes.DATE'; break;
        case 'array': case 'object': case 'json': t = 'DataTypes.JSON'; break;
      }
      if (!f.required && f.name !== 'id') opts.push('allowNull: true'); else if (f.name !== 'id') opts.push('allowNull: false');
      if (f.unique) opts.push('unique: true');
      const vals: string[] = [];
      if (f.validation?.email) vals.push('isEmail: true');
      if (f.validation?.min && f.type === 'number') vals.push(`min: ${f.validation.min}`);
      if (f.validation?.max && f.type === 'number') vals.push(`max: ${f.validation.max}`);
      if (vals.length) opts.push(`validate: { ${vals.join(', ')} }`);
      const optStr = opts.length ? `,\n      { ${opts.join(', ')} }` : '';
      return `    ${f.name}: {\n      type: ${t}${optStr}\n    }`;
    }).join(',\n');

    const indexes = (entity.indexes && entity.indexes.length)
      ? entity.indexes.map((idx: any) => `      { fields: [${idx.fields.map((f: string) => `'${f}'`).join(', ')}]${idx.unique ? ',\n        unique: true' : ''} }`).join(',\n')
      : '      // Add custom indexes here';

    return `import { DataTypes, Model, Optional } from 'sequelize';\nimport { sequelize } from '../config/database.js';\n\nexport interface ${entity.name}Attributes {\n${entity.fields.map((f: any) => `  ${f.name}: ${this.getTypeScriptType(f.type)};`).join('\n')}\n  readonly createdAt: Date;\n  readonly updatedAt: Date;\n  readonly deletedAt?: Date;\n}\n\nexport interface ${entity.name}CreationAttributes extends Optional<${entity.name}Attributes, 'id' | 'createdAt' | 'updatedAt' | 'deletedAt'> {}\n\nclass ${entity.name} extends Model<${entity.name}Attributes, ${entity.name}CreationAttributes> implements ${entity.name}Attributes {\n${entity.fields.map((f: any) => `  public ${f.name}!: ${this.getTypeScriptType(f.type)};`).join('\n')}\n  public readonly createdAt!: Date; public readonly updatedAt!: Date; public readonly deletedAt!: Date;\n  public static associate(models: any): void { /* define associations here */ }\n}\n\n${entity.name}.init({\n${fieldLines}\n  }, {\n    sequelize,\n    modelName: '${entity.name}',\n    tableName: '${entity.name.toLowerCase()}s',\n    timestamps: true, paranoid: true, underscored: true,\n    indexes: [\n${indexes}\n    ],\n  });\n\nexport { ${entity.name} };\nexport default ${entity.name};\n`;
  }
}

// HTTP server setup
const app = express();
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = (process.env.CORS_ORIGIN || '').split(',').map(o => o.trim()).filter(Boolean);
    if (allowedOrigins.length === 0 || allowedOrigins.includes('*')) {
      callback(null, true);
    } else if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
app.use(helmet());
app.use(compression());
app.use(morgan('dev'));
app.use(express.json({ limit: '1mb' }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

// Health check
app.get('/health', (_req: Request, res: Response) => res.json({ ok: true }));

// API Routes
// Authentication routes
app.use('/api/auth', authRoutes);

// History routes
app.use('/api/history', historyRoutes);
// Pricing/subscriptions
app.use('/api/billing', pricingRoutes);
app.post('/api/generate-spec', optionalAuth, enforceUsageLimit, async (req: any, res: Response) => {
  try {
    const { prompt } = req.body;
    
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt is required and must be a string' });
    }
    
    const spec = await promptToSpec(prompt);
    
    // Save to history if user is authenticated
    if (req.user) {
      try {
        await History.create({
          user_id: req.user.id,
          prompt,
          spec,
          project_name: (spec as any).metadata?.name || `backend-${spec.stack.language}-${Date.now()}`,
          stack_language: spec.stack.language,
          stack_framework: spec.stack.framework,
          entities_count: spec.entities?.length || 0,
        });
      } catch (historyError) {
        console.error('Failed to save to history:', historyError);
        // Don't fail the request if history saving fails
      }
    }

    // Increment usage if subscription is present
    if (req.subscription) {
      try {
        await req.subscription.increment('used_requests');
      } catch (incErr) {
        console.error('Failed to increment usage:', incErr);
      }
    }
    
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

// Enhanced v2 endpoints using ProfessionalBackendGenerator
app.post('/api/v2/generate-spec', optionalAuth, enforceUsageLimit, async (req: any, res: Response) => {
  try {
    const { prompt } = req.body;
    
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ 
        success: false, 
        error: 'Prompt is required and must be a string' 
      });
    }

    const generator = new ProfessionalBackendGenerator();
    const spec = await generator.generateSpec(prompt);
    
    // Save to history if user is authenticated
    if (req.user) {
      try {
        await History.create({
          user_id: req.user.id,
          prompt,
          spec,
          project_name: spec.metadata?.name || `backend-${spec.stack.language}-${Date.now()}`,
          stack_language: spec.stack.language,
          stack_framework: spec.stack.framework,
          entities_count: spec.entities?.length || 0,
        });
      } catch (historyError) {
        console.error('Failed to save to history:', historyError);
        // Don't fail the request if history saving fails
      }
    }

    // Increment usage if subscription is present
    if (req.subscription) {
      try {
        await req.subscription.increment('used_requests');
      } catch (incErr) {
        console.error('Failed to increment usage:', incErr);
      }
    }
    
    res.json({
      success: true,
      spec,
      message: 'Professional backend specification generated successfully'
    });
  } catch (error) {
    console.error('Enhanced generation error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to generate specification', 
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

app.post('/api/v2/scaffold', async (req: Request, res: Response) => {
  try {
    const { spec } = req.body;
    
    // Validate the spec using enhanced schema
    const validatedSpec = EnhancedSpecSchema.parse(spec);
    
    // Generate the project using professional generator
    const codeGenerator = new ProfessionalCodeGenerator();
    const zipBuffer = await codeGenerator.generateProject(validatedSpec);
    
    // Set headers for download
    const projectName = validatedSpec.metadata.name.toLowerCase().replace(/\s+/g, '-');
    const fileName = `${projectName}-backend-${Date.now()}.zip`;
    
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.setHeader('Content-Length', zipBuffer.length);
    
    res.send(zipBuffer);
  } catch (error) {
    console.error('Enhanced scaffolding error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate project',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Legacy endpoints for backward compatibility
app.post('/spec', optionalAuth, enforceUsageLimit, async (req: any, res: Response) => {
  const body = req.body as GenerationRequest;
  if (!body?.prompt) return res.status(400).json({ success: false, error: 'prompt required' } satisfies GenerationResponse);
  try {
    const spec = await promptToSpec(body.prompt);
    const resp: GenerationResponse = { success: true, spec };
    // Save to history if user is authenticated
    if (req.user) {
      try {
        await History.create({
          user_id: req.user.id,
          prompt: body.prompt,
          spec,
          project_name: (spec as any).metadata?.name || `backend-${spec.stack.language}-${Date.now()}`,
          stack_language: spec.stack.language,
          stack_framework: spec.stack.framework,
          entities_count: spec.entities?.length || 0,
        });
      } catch (historyError) {
        console.error('Failed to save to history:', historyError);
        // Don't fail the request if history saving fails
      }
    }

    // Increment usage if subscription is present
    if (req.subscription) {
      try {
        await req.subscription.increment('used_requests');
      } catch (incErr) {
        console.error('Failed to increment usage:', incErr);
      }
    }
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
    // Initialize database
    await syncDatabase();
    
    // Start the HTTP server
    app.listen(port, () => {
      console.log(`🚀 EaseArch Backend Generator listening on http://localhost:${port}`);
      console.log('✨ Features:');
      console.log('   - AI-powered backend generation with Gemini');
      console.log('   - Professional v2 endpoints with enhanced architecture');
      console.log('   - User authentication and profile management');
      console.log('   - History tracking and download management');
      console.log('   - MySQL database with Sequelize ORM');
      console.log('   - Zod validation schemas');
      console.log('   - Comprehensive project scaffolding');
      console.log('   - Production-ready Node.js and Python backends');
      console.log('   - Automatic ZIP file downloads');
      console.log('');
      console.log('🔗 API Endpoints:');
      console.log('   - /api/v2/generate-spec - Enhanced specification generation');
      console.log('   - /api/v2/scaffold - Professional project scaffolding');
      console.log('   - /api/generate-spec - Legacy specification generation');
      console.log('   - /api/scaffold - Legacy project scaffolding');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();



// Enhanced system prompt with better structure and examples
const SYSTEM_PROMPT = `You are EaseArch, an expert backend architect and code generator.

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
8. Generate Powerful backend code
9. CRITICAL: Ensure all string values are properly escaped for JSON
10. Do not include any text before or after the JSON object
11. CRITICAL: Every field in entities.fields MUST have a "required" property (boolean) - this is mandatory
12. CRITICAL: Every field in entities.fields MUST have a "unique" property (boolean) - this is mandatory
13. If a field is not explicitly marked as unique, set "unique": false
14. If a field is not explicitly marked as required, set "required": true
15. CRITICAL: Do NOT use any special characters in string values that could break JSON parsing
16. CRITICAL: Use simple, clean string values without complex patterns or special characters
17. CRITICAL: Test your JSON output to ensure it's valid before returning
18. For complex dashboards or admin/merchant systems, include ALL modules mentioned: users, merchants, kyc_documents, directors, transactions, group_split_contributors, settlements, settlement_items, qr_codes, admin_logs, fraud_flags; and API groups for auth, merchants, transactions, group-splits, settlements, qr-codes, admin (merchants, transactions, settlements, analytics, config, logs), webhooks, health.

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
    name: spec.name || 'EaseArch-node',
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