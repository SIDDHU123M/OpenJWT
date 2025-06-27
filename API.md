# API Reference

## Base URL

- **Development**: `http://localhost:3000` (Node.js) or `http://localhost:5000` (Python)
- **Production**: `https://your-app.herokuapp.com`

## Authentication

All endpoints accept JSON payloads and return JSON responses. No authentication is required for the service endpoints themselves - the service manages JWT tokens for your application.

## Response Format

All responses follow this format:

```json
{
  "success": boolean,
  "message": string,
  "data": object (optional)
}
```

## Rate Limiting

- **General**: 100 requests per 15 minutes per IP
- **Authentication endpoints**: 5 requests per 15 minutes per IP

## Endpoints

### GET /

**Description**: API documentation and service information

**Response**:

```json
{
  "service": "OpenJWT - Open Source JWT Auth-as-a-Service",
  "version": "1.0.0",
  "description": "A minimal JWT authentication service for frontend developers",
  "endpoints": { ... },
  "examples": { ... },
  "security": { ... }
}
```

### GET /health

**Description**: Health check endpoint for monitoring

**Response**:

```json
{
  "success": true,
  "message": "Service is healthy",
  "timestamp": "2023-12-01T12:00:00Z",
  "uptime": 3600
}
```

### POST /register

**Description**: Register a new user account

**Request Body**:

```json
{
  "email": "string (required) - Valid email address",
  "password": "string (required) - Minimum 6 characters",
  "name": "string (required) - Full name"
}
```

**Success Response (201)**:

```json
{
  "success": true,
  "message": "User registered successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid-string",
    "email": "user@example.com",
    "name": "User Name"
  }
}
```

**Error Responses**:

- **400**: Validation errors (invalid email, short password, missing name)
- **409**: User with email already exists
- **429**: Rate limit exceeded
- **500**: Internal server error

### POST /login

**Description**: Authenticate existing user

**Request Body**:

```json
{
  "email": "string (required) - User's email address",
  "password": "string (required) - User's password"
}
```

**Success Response (200)**:

```json
{
  "success": true,
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid-string",
    "email": "user@example.com",
    "name": "User Name"
  }
}
```

**Error Responses**:

- **400**: Validation errors (invalid email format)
- **401**: Invalid email or password
- **429**: Rate limit exceeded
- **500**: Internal server error

### POST /verify

**Description**: Verify JWT token validity

**Request Body**:

```json
{
  "token": "string (required) - JWT token to verify"
}
```

**Success Response (200)**:

```json
{
  "success": true,
  "message": "Token is valid",
  "user": {
    "id": "uuid-string",
    "email": "user@example.com",
    "name": "User Name"
  }
}
```

**Error Responses**:

- **400**: Missing or empty token
- **401**: Invalid, expired, or malformed token
- **429**: Rate limit exceeded
- **500**: Internal server error

## Error Codes

| Code | Description                                 |
| ---- | ------------------------------------------- |
| 400  | Bad Request - Invalid input data            |
| 401  | Unauthorized - Invalid credentials or token |
| 404  | Not Found - Endpoint doesn't exist          |
| 409  | Conflict - Resource already exists          |
| 429  | Too Many Requests - Rate limit exceeded     |
| 500  | Internal Server Error - Server-side error   |

## JWT Token Structure

The JWT tokens contain the following claims:

```json
{
  "userId": "uuid-string",
  "email": "user@example.com",
  "name": "User Name",
  "iat": 1701432000,
  "exp": 1701518400
}
```

## Security Features

- **Password Hashing**: Bcrypt with salt (12 rounds for Node.js, default for Python)
- **JWT Signing**: HS256 algorithm with secure secret
- **Token Expiration**: 24 hours (configurable)
- **Rate Limiting**: IP-based limits on authentication endpoints
- **Input Validation**: Email format, password length, required fields
- **CORS**: Configurable allowed origins

## Client Libraries

### JavaScript/Node.js

```javascript
// Using fetch API
const response = await fetch("https://your-service.com/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, password }),
});
const data = await response.json();
```

### Python

```python
import requests

response = requests.post('https://your-service.com/login',
                        json={'email': email, 'password': password})
data = response.json()
```

### cURL

```bash
curl -X POST https://your-service.com/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'
```

## Environment Variables

### Required

- `JWT_SECRET`: Secret key for signing JWT tokens (use a strong, random string)

### Optional

- `PORT`: Server port (default: 3000 for Node.js, 5000 for Python)
- `CORS_ORIGIN`: Allowed CORS origins (default: \*)
- `JWT_EXPIRES_IN` (Node.js) / `JWT_EXPIRES_HOURS` (Python): Token expiration time
- `REDIS_URL` (Python): Redis connection string for rate limiting

## Best Practices

1. **Use HTTPS in production** - Never send tokens over HTTP
2. **Store tokens securely** - Use httpOnly cookies or secure storage
3. **Implement token refresh** - Handle expired tokens gracefully
4. **Validate on client** - Check token expiration before API calls
5. **Configure CORS properly** - Restrict origins in production
6. **Monitor rate limits** - Implement proper error handling
7. **Use strong JWT secrets** - Minimum 32 characters, random string

## Integration Examples

Check the `/examples` directory for complete integration examples with:

- React/Vue.js applications
- Express.js middleware
- Django authentication backend
- Mobile applications
- And more!
