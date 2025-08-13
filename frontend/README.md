# Communication_LTD Ticket System API Documentation

A comprehensive cybersecurity-focused customer support ticket system with authentication, CSRF protection, and vulnerability testing capabilities.

## 🔐 Security Features

- **CSRF Protection**: All mutating operations require `X-CSRF-Token` header
- **Rate Limiting**: Protects against abuse with configurable limits per endpoint type
- **Audit Logging**: Comprehensive logging of all operations with security context
- **Vulnerability Mode**: Toggle security features for testing and demonstration

## 🌐 Environment Configuration

- `NEXT_PUBLIC_API_BASE`: Base URL for API endpoints
- `NEXT_PUBLIC_VULN_MODE`: Set to "true" to disable security features for testing

## 📋 API Endpoints

### Authentication Endpoints

#### `POST /auth/register`
**Purpose**: Register a new user account  
**Security**: Requires CSRF token  
**Request Body**:
\`\`\`json
{
  "username": "john_doe",
  "email": "john.doe@example.com", 
  "password": "SecureP@ssw0rd123",
  "role": "customer"
}
\`\`\`
**Response**: Returns created user object with ID, timestamps, and account status  
**Rate Limit**: 10 requests/minute per IP

#### `POST /auth/login`
**Purpose**: Authenticate user and receive access token  
**Security**: Requires CSRF token, sets auth cookies  
**Request Body**:
\`\`\`json
{
  "username_or_email": "john.doe@example.com",
  "password": "SecureP@ssw0rd123"
}
\`\`\`
**Response**: JWT access token with expiration time  
**Rate Limit**: 10 requests/minute per IP

#### `POST /auth/password-reset`
**Purpose**: Request password reset email  
**Security**: Requires CSRF token, always returns success for security  
**Request Body**:
\`\`\`json
{
  "email": "john.doe@example.com"
}
\`\`\`
**Response**: Generic success message regardless of email validity

#### `POST /auth/password-reset/confirm`
**Purpose**: Complete password reset with token from email  
**Security**: Requires CSRF token and valid reset token  
**Request Body**:
\`\`\`json
{
  "token": "reset-token-123456",
  "new_password": "NewSecureP@ssw0rd123"
}
\`\`\`
**Response**: Success confirmation message

#### `GET /auth/me`
**Purpose**: Get current authenticated user information  
**Security**: Requires valid JWT token  
**Response**: Complete user profile including role and account status

### Customer Management

#### `GET /customers`
**Purpose**: List all customers with pagination and search  
**Security**: Requires authentication, admin/support roles only  
**Query Parameters**:
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 10)  
- `search`: Search term for filtering
**Response**: Paginated list of customers with metadata

#### `POST /customers`
**Purpose**: Create new customer profile  
**Security**: Requires CSRF token and authentication  
**Request Body**:
\`\`\`json
{
  "first_name": "John",
  "last_name": "Doe", 
  "phone_number": "+1-555-123-4567",
  "address": "123 Main St",
  "city": "Springfield",
  "postal_code": "12345",
  "country": "USA"
}
\`\`\`
**Response**: Created customer object with generated ID

#### `GET /customers/{customer_id}`
**Purpose**: Get specific customer details  
**Security**: Requires authentication, role-based access control  
**Response**: Complete customer profile information

#### `PUT /customers/{customer_id}`
**Purpose**: Update customer information  
**Security**: Requires CSRF token, authentication, and appropriate permissions  
**Request Body**: Same as POST /customers  
**Response**: Updated customer object

#### `DELETE /customers/{customer_id}`
**Purpose**: Remove customer from system  
**Security**: Requires CSRF token, admin role only  
**Response**: 204 No Content on success

#### `GET /customers/{customer_id}/packages`
**Purpose**: Get all packages assigned to specific customer  
**Security**: Requires authentication  
**Response**: Array of customer package assignments with status

#### `POST /customers/{customer_id}/packages`
**Purpose**: Assign package to customer  
**Security**: Requires CSRF token and authentication  
**Request Body**:
\`\`\`json
{
  "package_id": 1,
  "start_date": "2025-08-01",
  "end_date": "2026-08-01",
  "status": "active"
}
\`\`\`
**Response**: Created customer package assignment

### Package Management

#### `GET /packages`
**Purpose**: List all available service packages  
**Security**: Requires authentication  
**Query Parameters**:
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 10)
**Response**: Paginated list of packages with pricing and features

#### `POST /packages`
**Purpose**: Create new service package  
**Security**: Requires CSRF token, admin role only  
**Request Body**:
\`\`\`json
{
  "name": "Basic Internet",
  "description": "Basic internet package for home use",
  "price": 29.99,
  "features": [
    "50Mbps download speed",
    "10Mbps upload speed", 
    "Unlimited data"
  ]
}
\`\`\`
**Response**: Created package object with ID and timestamps

#### `GET /packages/{package_id}`
**Purpose**: Get specific package details  
**Security**: Requires authentication  
**Response**: Complete package information including features

#### `PUT /packages/{package_id}`
**Purpose**: Update package information  
**Security**: Requires CSRF token, admin role only  
**Request Body**: Same as POST /packages  
**Response**: Updated package object

#### `DELETE /packages/{package_id}`
**Purpose**: Remove package from system  
**Security**: Requires CSRF token, admin role only  
**Response**: 204 No Content on success

### Ticket System

#### `GET /tickets`
**Purpose**: List support tickets with filtering and pagination  
**Security**: Requires authentication, filtered by user role  
**Query Parameters**:
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 10)
- `status`: Filter by status (new, in_progress, on_hold, resolved, closed)
- `priority`: Filter by priority (low, medium, high, urgent)
- `category`: Filter by category (billing, technical, account, other)
- `customer_id`: Filter by customer ID
- `assigned_to`: Filter by assigned user ID
**Response**: Paginated list of tickets with full details

#### `POST /tickets`
**Purpose**: Create new support ticket  
**Security**: Requires CSRF token and authentication  
**Request Body**:
\`\`\`json
{
  "subject": "Internet connection issue",
  "description": "My internet connection has been unstable for the past 2 days.",
  "priority": "high",
  "category": "technical"
}
\`\`\`
**Response**: Created ticket with auto-assigned ID and timestamps

#### `GET /tickets/{ticket_id}`
**Purpose**: Get specific ticket details  
**Security**: Requires authentication, role-based access control  
**Response**: Complete ticket information including assignment and status

#### `PATCH /tickets/{ticket_id}`
**Purpose**: Update ticket status, assignment, or priority  
**Security**: Requires CSRF token, support/admin roles only  
**Request Body**:
\`\`\`json
{
  "assigned_to": 2,
  "status": "in_progress", 
  "priority": "high"
}
\`\`\`
**Response**: Updated ticket object

#### `DELETE /tickets/{ticket_id}`
**Purpose**: Remove ticket from system  
**Security**: Requires CSRF token, admin role only  
**Response**: 204 No Content on success

#### `GET /tickets/{ticket_id}/comments`
**Purpose**: Get all comments for specific ticket  
**Security**: Requires authentication, role-based access control  
**Response**: Array of comments with user information and timestamps

#### `POST /tickets/{ticket_id}/comments`
**Purpose**: Add comment to ticket  
**Security**: Requires CSRF token and authentication  
**Request Body**:
\`\`\`json
{
  "content": "We're looking into this issue. Please provide more details about when the problem occurs."
}
\`\`\`
**Response**: Created comment object with user context

### Audit Logging

#### `GET /audit-logs`
**Purpose**: Retrieve system audit logs for security monitoring  
**Security**: Requires authentication, admin role only  
**Query Parameters**:
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 10)
- `user_id`: Filter by user ID
- `action`: Filter by action type
- `entity_type`: Filter by entity type (user, customer, ticket, etc.)
- `entity_id`: Filter by specific entity ID
- `start_date`: Filter by start date
- `end_date`: Filter by end date
**Response**: Paginated audit log entries with full context

## 🛡️ Security Implementation

### CSRF Protection
- All mutating operations (POST, PUT, PATCH, DELETE) require `X-CSRF-Token` header
- Missing or invalid tokens logged at WARNING level
- Valid tokens on successful operations logged at INFO level

### Rate Limiting
- Authentication endpoints: 10 requests/minute per IP
- Standard endpoints: 60 requests/minute per authenticated user  
- Admin endpoints: 30 requests/minute per admin user
- Requests approaching 80% threshold generate WARNING logs

### Audit Logging
- All successful mutating operations logged with user context
- Failed authentication attempts tracked
- IP addresses, user agents, and timestamps recorded
- Comprehensive operation details for security analysis

### Vulnerability Mode
When `NEXT_PUBLIC_VULN_MODE="true"`:
- CSRF token validation disabled
- HTML sanitization bypassed
- Security headers relaxed
- Used for security testing and demonstration purposes

## 📊 Data Models

### User Roles
- **admin**: Full system access, user management
- **support**: Ticket management, customer support  
- **customer**: Limited access to own tickets and profile

### Ticket Status Flow
1. **new**: Initial ticket creation
2. **in_progress**: Assigned and being worked on
3. **on_hold**: Waiting for customer response or external dependency
4. **resolved**: Issue fixed, awaiting customer confirmation
5. **closed**: Ticket completed and archived

### Priority Levels
- **low**: Non-urgent issues, standard response time
- **medium**: Normal priority, business hours response
- **high**: Important issues requiring prompt attention
- **urgent**: Critical issues requiring immediate response

This API provides a complete customer support system with enterprise-grade security features and comprehensive audit capabilities.
