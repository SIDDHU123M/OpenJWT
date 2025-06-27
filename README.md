# OpenJWT - Open Source JWT Auth-as-a-Service

A minimal hosted microservice providing JWT authentication endpoints for frontend developers to test authentication without complex setups like Firebase or Auth0.

## 🚀 Live Demo

- **Heroku**: `https://your-app.herokuapp.com`
- **Documentation**: Access `/` for API usage documentation

## ✨ Features

- **Simple API**: Just 3 endpoints - `/register`, `/login`, `/verify`
- **Secure**: JWT tokens with proper encryption and validation
- **Dual Implementation**: Node.js (Express) and Python (Flask) versions
- **Production Ready**: Heroku deployment configuration included
- **Open Source**: Free to use and contribute
- **Developer Friendly**: Clear documentation and error messages

## 📋 API Endpoints

### POST /register

Register a new user account.

**Request:**

```json
{
  "email": "user@example.com",
  "password": "your-password",
  "name": "User Name"
}
```

**Response:**

```json
{
  "success": true,
  "message": "User registered successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user-id",
    "email": "user@example.com",
    "name": "User Name"
  }
}
```

### POST /login

Authenticate existing user.

**Request:**

```json
{
  "email": "user@example.com",
  "password": "your-password"
}
```

**Response:**

```json
{
  "success": true,
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user-id",
    "email": "user@example.com",
    "name": "User Name"
  }
}
```

### POST /verify

Verify JWT token validity.

**Request:**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**

```json
{
  "success": true,
  "message": "Token is valid",
  "user": {
    "id": "user-id",
    "email": "user@example.com",
    "name": "User Name"
  }
}
```

## 🛠 Quick Start

### Using the Hosted Service

1. **Register a user:**

```bash
curl -X POST https://your-app.herokuapp.com/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123","name":"Test User"}'
```

2. **Login:**

```bash
curl -X POST https://your-app.herokuapp.com/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'
```

3. **Verify token:**

```bash
curl -X POST https://your-app.herokuapp.com/verify \
  -H "Content-Type: application/json" \
  -d '{"token":"YOUR_JWT_TOKEN_HERE"}'
```

### Frontend Integration

```javascript
// Register
const register = async (email, password, name) => {
  const response = await fetch("https://your-app.herokuapp.com/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, name }),
  });
  return response.json();
};

// Login
const login = async (email, password) => {
  const response = await fetch("https://your-app.herokuapp.com/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  return response.json();
};

// Verify
const verify = async (token) => {
  const response = await fetch("https://your-app.herokuapp.com/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  return response.json();
};
```

## 🏗 Local Development

### Node.js Version

```bash
cd nodejs-version
npm install
npm run dev
```

### Python Version

```bash
cd python-version
pip install -r requirements.txt
python app.py
```

## 🚀 Deployment

### Heroku Deployment

1. Clone this repository
2. Choose your preferred implementation (Node.js or Python)
3. Deploy to Heroku:

```bash
# For Node.js
heroku create your-app-name
git subtree push --prefix nodejs-version heroku main

# For Python
heroku create your-app-name
git subtree push --prefix python-version heroku main
```

## 🔒 Security Features

- **Password Hashing**: Bcrypt with salt rounds
- **JWT Security**: Signed tokens with expiration
- **Input Validation**: Request validation and sanitization
- **Rate Limiting**: Built-in rate limiting for production
- **CORS**: Configurable CORS settings
- **Environment Variables**: Secure configuration management

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/OpenJWT/issues)
- **Documentation**: Visit `/` endpoint for live API documentation
- **Community**: Join our discussions

## 🌟 Show Your Support

Give a ⭐️ if this project helped you!

---

**Made with ❤️ for the developer community**
