export interface BackendSpec {
  stack: StackConfig;
  entities: Entity[];
  auth: AuthConfig;
  api: ApiResource[];
  env: string[];
  extras?: ExtrasConfig;
  name?: string;
}

export interface StackConfig {
  language: 'node' | 'python';
  framework: string;
  database: string;
  orm: string;
}

export interface Entity {
  name: string;
  fields: EntityField[];
}

export interface EntityField {
  name: string;
  type: string;
  required: boolean;
  unique: boolean;
  default?: string;
}

export interface AuthConfig {
  strategy: 'jwt' | 'session' | 'oauth';
  roles?: string[];
}

export interface ApiResource {
  resource: string;
  operations: ('list' | 'get' | 'create' | 'update' | 'delete')[];
  relations?: string[];
}

export interface ExtrasConfig {
  queue?: string;
  cache?: string;
  storage?: string;
  thirdParty?: string[];
}

export interface GenerationRequest {
  prompt: string;
  options?: {
    language?: 'node' | 'python';
    framework?: string;
    database?: string;
  };
}

export interface GenerationResponse {
  success: boolean;
  spec?: BackendSpec;
  error?: string;
  message?: string;
}

export interface ScaffoldRequest {
  spec: BackendSpec;
  outputFormat?: 'zip' | 'github' | 'local';
}

export interface ScaffoldResponse {
  success: boolean;
  downloadUrl?: string;
  repoUrl?: string;
  localPath?: string;
  error?: string;
}
