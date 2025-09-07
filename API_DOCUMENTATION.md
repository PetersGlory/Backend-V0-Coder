# EaseArch Backend Generator - API Documentation

## Overview
EaseArch is an AI-powered backend generator that creates production-ready Node.js and Python backends from natural language descriptions. The system includes user authentication, history tracking, and automatic project scaffolding.

## Features
- 🤖 AI-powered backend generation using Google Gemini
- 👤 User authentication and profile management
- 📚 History tracking and download management
- 🗄️ MySQL database with Sequelize ORM
- 📦 Automatic ZIP file generation and download
- 💳 Pricing plans and subscriptions (Free, Pro, Team)
- 🔒 JWT-based authentication
- ✅ Zod validation schemas

## API Endpoints

### Authentication Routes (`/api/auth`)

#### POST `/api/auth/register`
Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "password123",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": 1,
      "email": "user@example.com",
      "username": "johndoe",
      "first_name": "John",
      "last_name": "Doe",
      "is_active": true,
      "email_verified": false,
      "created_at": "2024-01-01T00:00:00.000Z"
    },
    "token": "jwt_token_here"
  }
}
```

#### POST `/api/auth/login`
Login with email and password.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": { /* user object */ },
    "token": "jwt_token_here"
  }
}
```

#### GET `/api/auth/profile`
Get current user profile (requires authentication).

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": { /* user object */ }
  }
}
```

#### PUT `/api/auth/profile`
Update user profile (requires authentication).

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "first_name": "John",
  "last_name": "Smith",
  "username": "johnsmith",
  "avatar_url": "https://example.com/avatar.jpg"
}
```

### History Routes (`/api/history`)

#### GET `/api/history`
Get user's generation history (requires authentication).

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 10)
- `favorite_only` (optional): Show only favorites (default: false)

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "histories": [
      {
        "id": 1,
        "prompt": "Create a blog API with users and posts",
        "project_name": "blog-api",
        "stack_language": "node",
        "stack_framework": "express",
        "entities_count": 3,
        "download_count": 2,
        "is_favorite": false,
        "created_at": "2024-01-01T00:00:00.000Z"
      }
    ],
    "pagination": {
      "current_page": 1,
      "total_pages": 5,
      "total_items": 50,
      "items_per_page": 10
    }
  }
}
```

#### POST `/api/history`
Create a new history entry (optional authentication).

**Request Body:**
```json
{
  "prompt": "Create a blog API with users and posts",
  "spec": { /* generated backend specification */ },
  "project_name": "blog-api"
}
```

#### GET `/api/history/:id`
Get specific history entry (requires authentication).

#### PUT `/api/history/:id`
Update history entry (e.g., mark as favorite) (requires authentication).

#### DELETE `/api/history/:id`
Delete history entry (requires authentication).

#### POST `/api/history/:id/download`
Increment download count for history entry (requires authentication).

### Generation Routes

#### POST `/api/generate-spec`
Generate backend specification from natural language prompt.

**Request Body:**
```json
{
  "prompt": "Create a blog API with users, posts, and comments. Use Node.js and PostgreSQL."
}
```

**Response:**
```json
{
  "stack": {
    "language": "node",
    "framework": "express",
    "database": "postgres",
    "orm": "prisma"
  },
  "entities": [
    {
      "name": "User",
      "fields": [
        {
          "name": "id",
          "type": "uuid",
          "required": true,
          "unique": true,
          "default": "uuid"
        },
        {
          "name": "email",
          "type": "string",
          "required": true,
          "unique": true,
          "validation": {
            "pattern": "email"
          }
        }
      ]
    }
  ],
  "auth": {
    "strategy": "jwt",
    "roles": ["admin", "user"]
  },
  "api": [
    {
      "resource": "users",
      "operations": ["list", "get", "create", "update", "delete"]
    }
  ],
  "env": [
    {
      "name": "DATABASE_URL",
      "description": "PostgreSQL connection string",
      "required": true,
      "type": "url"
    }
  ],
  "metadata": {
    "name": "blog-api",
    "description": "A simple blog API",
    "version": "1.0.0",
    "license": "MIT"
  }
}
```

#### POST `/api/scaffold`
Generate and download project files as ZIP.

**Request Body:**
```json
{
  "spec": { /* backend specification object */ }
}
```

**Response:** ZIP file download

### Billing Routes (`/api/billing`)

#### GET `/api/billing/plans`
List available pricing plans.

**Response:**
```json
{
  "success": true,
  "data": {
    "plans": [
      {
        "code": "free",
        "name": "Free",
        "price_cents": 0,
        "interval": "monthly",
        "request_limit": 10,
        "priority_support": false
      }
    ]
  }
}
```

#### POST `/api/billing/subscribe` (auth required)
Subscribe current user to a plan.

**Request Body:**
```json
{ "plan_code": "pro" }
```

#### GET `/api/billing/me` (auth required)
Get the current user's subscription details.

#### POST `/api/billing/cancel` (auth required)
Set the current subscription to not renew after the period ends.

## Environment Variables

Create a `.env` file with the following variables:

```env
# Server Configuration
PORT=4000
NODE_ENV=development

# CORS Configuration
CORS_ORIGIN=http://localhost:3000

# AI Model Configuration
GEMINI_API_KEY=your_gemini_api_key_here

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=easearch_db
DB_USER=root
DB_PASSWORD=your_mysql_password
DATABASE_URL=mysql://root:your_mysql_password@localhost:3306/easearch_db

# Authentication
JWT_SECRET=your_jwt_secret_key_here
SESSION_SECRET=your_session_secret_key_here

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

## Database Setup

1. Install MySQL server
2. Create database: `CREATE DATABASE easearch_db;`
3. Update `.env` with your MySQL credentials
4. The application will automatically create tables on startup

## Getting Started

1. Install dependencies: `npm install`
2. Set up environment variables in `.env`
3. Start the server: `npm run dev`
4. The API will be available at `http://localhost:4000`

## Authentication

The API uses JWT tokens for authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

Tokens expire after 7 days by default.

## Error Handling

All API responses follow this format:

**Success:**
```json
{
  "success": true,
  "data": { /* response data */ },
  "message": "Optional success message"
}
```

**Error:**
```json
{
  "success": false,
  "error": "Error message",
  "details": "Optional error details"
}
```

## Rate Limiting

- 100 requests per 15 minutes per IP (configurable)
- Subscription usage limits per billing period are enforced on `/api/generate-spec`
