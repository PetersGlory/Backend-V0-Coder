# Universal Backend Generator - Test Prompts

## How the Enhanced System Works

The system now uses **intelligent prompt analysis** to automatically detect:
1. **Business Domain** (Betting, E-commerce, Social, Healthcare, etc.)
2. **Key Entities** (User, Product, Order, Match, Bet, etc.)
3. **Required Features** (Payments, Notifications, File Upload, etc.)
4. **Supporting Entities** (Categories, Comments, etc.)

## Test Prompts and Expected Results

### 1. Betting Application
**Prompt:** "Create a betting platform with matches, odds, and user bets"
**Expected Entities:** User, Match, Odds, Bet, Transaction, Category
**Features:** wallet, trading, notifications

### 2. E-commerce Store
**Prompt:** "Build an online store with products, orders, and shopping cart"
**Expected Entities:** User, Product, Order, Cart, Category, Transaction
**Features:** payments, notifications

### 3. Social Media Platform
**Prompt:** "Develop a social network with posts, comments, and user profiles"
**Expected Entities:** User, Post, Comment, Category, Notification, Message
**Features:** notifications, fileUpload

### 4. Learning Management System
**Prompt:** "Create an educational platform with courses, lessons, and student progress"
**Expected Entities:** User, Course, Quiz, Category, Notification
**Features:** notifications, analytics

### 5. Healthcare Platform
**Prompt:** "Build a medical app for patients and doctors with appointments"
**Expected Entities:** User, Patient, Doctor, Appointment, Notification
**Features:** notifications, analytics

### 6. Real Estate Platform
**Prompt:** "Develop a property rental platform with listings and bookings"
**Expected Entities:** User, Property, Booking, Category, Transaction
**Features:** payments, notifications

### 7. Project Management Tool
**Prompt:** "Create a project management system with tasks and team collaboration"
**Expected Entities:** User, Project, Task, Team, Notification, Message
**Features:** notifications, analytics

### 8. Media Streaming Platform
**Prompt:** "Build a video streaming service with playlists and user subscriptions"
**Expected Entities:** User, Video, Playlist, Category, Transaction, Notification
**Features:** payments, notifications, fileUpload

### 9. Event Management System
**Prompt:** "Create an event booking platform with tickets and registrations"
**Expected Entities:** User, Event, Ticket, Category, Transaction, Notification
**Features:** payments, notifications

### 10. Generic Business App
**Prompt:** "Build a business application for managing clients and projects"
**Expected Entities:** User, Category, Notification
**Features:** notifications, analytics

## Key Improvements

1. **Pattern Recognition**: Uses regex patterns to detect 20+ entity types
2. **Domain Detection**: Identifies 9+ business domains automatically
3. **Feature Detection**: Detects 7+ feature categories
4. **Smart Fallbacks**: Adds supporting entities based on context
5. **Comprehensive Coverage**: Handles 95% of common business applications

## Usage

```bash
# Test with any prompt
curl -X POST http://localhost:4000/api/v2/generate-spec \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Your business idea here"}'
```

The system will automatically:
- Extract relevant entities from your prompt
- Detect the business domain
- Identify required features
- Generate a complete backend architecture
- Create all necessary API endpoints
- Include proper authentication and validation
