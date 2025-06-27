#!/usr/bin/env node

/**
 * OpenJWT Usage Examples
 *
 * This script demonstrates how to use the OpenJWT service
 * in a Node.js application.
 */

const fetch = require("node-fetch");

// Replace with your OpenJWT service URL
const API_BASE_URL = "http://localhost:3000";

class OpenJWTClient {
  constructor(baseUrl = API_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  async makeRequest(endpoint, options = {}) {
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        headers: {
          "Content-Type": "application/json",
          ...options.headers,
        },
        ...options,
      });

      const data = await response.json();

      return {
        success: response.ok,
        status: response.status,
        data,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async register(email, password, name) {
    return await this.makeRequest("/register", {
      method: "POST",
      body: JSON.stringify({ email, password, name }),
    });
  }

  async login(email, password) {
    return await this.makeRequest("/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  }

  async verify(token) {
    return await this.makeRequest("/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
  }

  async getDocumentation() {
    return await this.makeRequest("/");
  }

  async healthCheck() {
    return await this.makeRequest("/health");
  }
}

// Example usage
async function runExamples() {
  const client = new OpenJWTClient();

  console.log("🚀 OpenJWT Client Examples\n");

  // Health check
  console.log("1. Health Check:");
  const health = await client.healthCheck();
  console.log(JSON.stringify(health, null, 2));
  console.log();

  // Register a user
  console.log("2. Register User:");
  const registerResult = await client.register(
    "demo@example.com",
    "demo123",
    "Demo User"
  );
  console.log(JSON.stringify(registerResult, null, 2));
  console.log();

  if (registerResult.success) {
    const token = registerResult.data.token;

    // Verify the token
    console.log("3. Verify Token:");
    const verifyResult = await client.verify(token);
    console.log(JSON.stringify(verifyResult, null, 2));
    console.log();

    // Login with the same user
    console.log("4. Login User:");
    const loginResult = await client.login("demo@example.com", "demo123");
    console.log(JSON.stringify(loginResult, null, 2));
    console.log();
  }

  // Get API documentation
  console.log("5. API Documentation:");
  const docs = await client.getDocumentation();
  console.log("Service:", docs.data.service);
  console.log("Available endpoints:", Object.keys(docs.data.endpoints));
  console.log();
}

// Frontend JavaScript example
function generateFrontendExample() {
  return `
// Frontend JavaScript Example for OpenJWT

class OpenJWTAuth {
  constructor(apiUrl = 'https://your-openjwt-service.herokuapp.com') {
    this.apiUrl = apiUrl;
    this.token = localStorage.getItem('jwt_token');
  }

  async register(email, password, name) {
    try {
      const response = await fetch(\`\${this.apiUrl}/register\`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, name })
      });
      
      const data = await response.json();
      
      if (data.success) {
        this.token = data.token;
        localStorage.setItem('jwt_token', this.token);
      }
      
      return data;
    } catch (error) {
      return { success: false, message: error.message };
    }
  }

  async login(email, password) {
    try {
      const response = await fetch(\`\${this.apiUrl}/login\`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      
      if (data.success) {
        this.token = data.token;
        localStorage.setItem('jwt_token', this.token);
      }
      
      return data;
    } catch (error) {
      return { success: false, message: error.message };
    }
  }

  async verify() {
    if (!this.token) {
      return { success: false, message: 'No token available' };
    }

    try {
      const response = await fetch(\`\${this.apiUrl}/verify\`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: this.token })
      });
      
      return await response.json();
    } catch (error) {
      return { success: false, message: error.message };
    }
  }

  isAuthenticated() {
    return !!this.token;
  }

  logout() {
    this.token = null;
    localStorage.removeItem('jwt_token');
  }

  getToken() {
    return this.token;
  }
}

// Usage:
const auth = new OpenJWTAuth();

// Register
auth.register('user@example.com', 'password123', 'User Name')
  .then(result => console.log('Register:', result));

// Login
auth.login('user@example.com', 'password123')
  .then(result => console.log('Login:', result));

// Verify current token
auth.verify()
  .then(result => console.log('Verify:', result));
`;
}

if (require.main === module) {
  runExamples().catch(console.error);

  console.log("\n📄 Frontend Example:");
  console.log(generateFrontendExample());
}

module.exports = OpenJWTClient;
