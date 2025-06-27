# OpenJWT API Examples

Base URL: `https://openjwt-3100173929eb.herokuapp.com`

## 1. Register a New User

### cURL Example:

```bash
curl -X POST https://openjwt-3100173929eb.herokuapp.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "mypassword123",
    "name": "John Doe"
  }'
```

### Response:

```json
{
  "success": true,
  "message": "User registered successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NTY3OC05YWJjLWRlZi0xMjM0LTU2Nzg5MGFiY2RlZiIsImVtYWlsIjoiam9obi5kb2VAZXhhbXBsZS5jb20iLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MDM3NzIwMDAsImV4cCI6MTcwMzg1ODQwMH0.abc123def456ghi789",
  "user": {
    "id": "12345678-9abc-def-1234-567890abcdef",
    "email": "john.doe@example.com",
    "name": "John Doe"
  }
}
```

## 2. Login User

### cURL Example:

```bash
curl -X POST https://openjwt-3100173929eb.herokuapp.com/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "mypassword123"
  }'
```

### Response:

```json
{
  "success": true,
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NTY3OC05YWJjLWRlZi0xMjM0LTU2Nzg5MGFiY2RlZiIsImVtYWlsIjoiam9obi5kb2VAZXhhbXBsZS5jb20iLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MDM3NzIwMDAsImV4cCI6MTcwMzg1ODQwMH0.abc123def456ghi789",
  "user": {
    "id": "12345678-9abc-def-1234-567890abcdef",
    "email": "john.doe@example.com",
    "name": "John Doe"
  }
}
```

## 3. Verify Token

### cURL Example:

```bash
curl -X POST https://openjwt-3100173929eb.herokuapp.com/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NTY3OC05YWJjLWRlZi0xMjM0LTU2Nzg5MGFiY2RlZiIsImVtYWlsIjoiam9obi5kb2VAZXhhbXBsZS5jb20iLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MDM3NzIwMDAsImV4cCI6MTcwMzg1ODQwMH0.abc123def456ghi789"
  }'
```

### Response:

```json
{
  "success": true,
  "message": "Token is valid",
  "user": {
    "id": "12345678-9abc-def-1234-567890abcdef",
    "email": "john.doe@example.com",
    "name": "John Doe"
  }
}
```

## JavaScript Examples

### Using Fetch API:

#### Register:

```javascript
const registerUser = async () => {
  try {
    const response = await fetch(
      "https://openjwt-3100173929eb.herokuapp.com/register",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: "jane.smith@example.com",
          password: "securepass456",
          name: "Jane Smith",
        }),
      }
    );

    const data = await response.json();
    console.log("Registration:", data);

    if (data.success) {
      localStorage.setItem("jwt_token", data.token);
      console.log("Token saved:", data.token);
    }
  } catch (error) {
    console.error("Registration error:", error);
  }
};

registerUser();
```

#### Login:

```javascript
const loginUser = async () => {
  try {
    const response = await fetch(
      "https://openjwt-3100173929eb.herokuapp.com/login",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: "jane.smith@example.com",
          password: "securepass456",
        }),
      }
    );

    const data = await response.json();
    console.log("Login:", data);

    if (data.success) {
      localStorage.setItem("jwt_token", data.token);
      console.log("User logged in:", data.user);
    }
  } catch (error) {
    console.error("Login error:", error);
  }
};

loginUser();
```

#### Verify:

```javascript
const verifyToken = async () => {
  const token = localStorage.getItem("jwt_token");

  if (!token) {
    console.log("No token found");
    return;
  }

  try {
    const response = await fetch(
      "https://openjwt-3100173929eb.herokuapp.com/verify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          token: token,
        }),
      }
    );

    const data = await response.json();
    console.log("Token verification:", data);

    if (data.success) {
      console.log("Token is valid, user:", data.user);
    } else {
      console.log("Token is invalid, removing from storage");
      localStorage.removeItem("jwt_token");
    }
  } catch (error) {
    console.error("Verification error:", error);
  }
};

verifyToken();
```

## Python Examples

### Using requests library:

```python
import requests
import json

BASE_URL = 'https://openjwt-3100173929eb.herokuapp.com'

# Register
def register_user():
    url = f'{BASE_URL}/register'
    data = {
        'email': 'alice.wilson@example.com',
        'password': 'mypassword789',
        'name': 'Alice Wilson'
    }

    response = requests.post(url, json=data)
    result = response.json()

    print('Registration:', json.dumps(result, indent=2))

    if result.get('success'):
        return result.get('token')
    return None

# Login
def login_user():
    url = f'{BASE_URL}/login'
    data = {
        'email': 'alice.wilson@example.com',
        'password': 'mypassword789'
    }

    response = requests.post(url, json=data)
    result = response.json()

    print('Login:', json.dumps(result, indent=2))

    if result.get('success'):
        return result.get('token')
    return None

# Verify
def verify_token(token):
    url = f'{BASE_URL}/verify'
    data = {
        'token': token
    }

    response = requests.post(url, json=data)
    result = response.json()

    print('Verification:', json.dumps(result, indent=2))
    return result.get('success', False)

# Example usage
if __name__ == '__main__':
    # Register new user
    token = register_user()

    if token:
        print(f'\\nReceived token: {token[:50]}...')

        # Verify the token
        is_valid = verify_token(token)
        print(f'\\nToken is valid: {is_valid}')

        # Login with same credentials
        login_token = login_user()
        print(f'\\nLogin token: {login_token[:50] if login_token else None}...')
```

## Postman Collection

Import this JSON into Postman:

```json
{
  "info": {
    "name": "OpenJWT API",
    "description": "Open Source JWT Auth-as-a-Service API"
  },
  "item": [
    {
      "name": "Register User",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\\n  \\"email\\": \\"test@example.com\\",\\n  \\"password\\": \\"password123\\",\\n  \\"name\\": \\"Test User\\"\\n}"
        },
        "url": {
          "raw": "https://openjwt-3100173929eb.herokuapp.com/register",
          "protocol": "https",
          "host": ["openjwt-3100173929eb", "herokuapp", "com"],
          "path": ["register"]
        }
      }
    },
    {
      "name": "Login User",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\\n  \\"email\\": \\"test@example.com\\",\\n  \\"password\\": \\"password123\\"\\n}"
        },
        "url": {
          "raw": "https://openjwt-3100173929eb.herokuapp.com/login",
          "protocol": "https",
          "host": ["openjwt-3100173929eb", "herokuapp", "com"],
          "path": ["login"]
        }
      }
    },
    {
      "name": "Verify Token",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\\n  \\"token\\": \\"YOUR_JWT_TOKEN_HERE\\"\\n}"
        },
        "url": {
          "raw": "https://openjwt-3100173929eb.herokuapp.com/verify",
          "protocol": "https",
          "host": ["openjwt-3100173929eb", "herokuapp", "com"],
          "path": ["verify"]
        }
      }
    }
  ]
}
```

## Testing Your API

You can test your live API right now:

1. **Quick Register Test:**

   ```bash
   curl -X POST https://openjwt-3100173929eb.herokuapp.com/register \
     -H "Content-Type: application/json" \
     -d '{"email":"test@demo.com","password":"demo123","name":"Demo User"}'
   ```

2. **Quick Login Test:**

   ```bash
   curl -X POST https://openjwt-3100173929eb.herokuapp.com/login \
     -H "Content-Type: application/json" \
     -d '{"email":"test@demo.com","password":"demo123"}'
   ```

3. **View Documentation:**

   ```bash
   curl https://openjwt-3100173929eb.herokuapp.com/
   ```

4. **Health Check:**
   ```bash
   curl https://openjwt-3100173929eb.herokuapp.com/health
   ```

## Error Handling Examples

### Invalid Email:

```bash
curl -X POST https://openjwt-3100173929eb.herokuapp.com/register \
  -H "Content-Type: application/json" \
  -d '{"email":"invalid-email","password":"test123","name":"Test"}'
```

Response:

```json
{
  "success": false,
  "message": "Validation failed",
  "errors": [
    {
      "msg": "Please provide a valid email",
      "param": "email",
      "location": "body"
    }
  ]
}
```

### User Already Exists:

```bash
# Register same user twice
curl -X POST https://openjwt-3100173929eb.herokuapp.com/register \
  -H "Content-Type: application/json" \
  -d '{"email":"existing@example.com","password":"test123","name":"Test"}'
```

Response:

```json
{
  "success": false,
  "message": "User with this email already exists"
}
```

Your OpenJWT service is live and ready for testing! 🚀
