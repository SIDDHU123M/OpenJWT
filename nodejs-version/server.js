const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
const { v4: uuidv4 } = require("uuid");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "your-super-secret-jwt-key-change-this-in-production";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "24h";

// In-memory user storage (replace with database in production)
const users = new Map();

// Middleware
app.use(helmet());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    credentials: true,
  })
);
app.use(morgan("combined"));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: "Too many requests from this IP, please try again later.",
  },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth requests per windowMs
  message: {
    success: false,
    message: "Too many authentication attempts, please try again later.",
  },
});

app.use(limiter);

// Validation middleware
const validateRegistration = [
  body("email")
    .isEmail()
    .normalizeEmail()
    .withMessage("Please provide a valid email"),
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long"),
  body("name").trim().isLength({ min: 1 }).withMessage("Name is required"),
];

const validateLogin = [
  body("email")
    .isEmail()
    .normalizeEmail()
    .withMessage("Please provide a valid email"),
  body("password").notEmpty().withMessage("Password is required"),
];

const validateToken = [
  body("token").notEmpty().withMessage("Token is required"),
];

// Helper function to handle validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: errors.array(),
    });
  }
  next();
};

// Helper function to generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      name: user.name,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

// Helper function to hash password
const hashPassword = async (password) => {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

// Helper function to verify password
const verifyPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// Documentation endpoint
app.get("/", (req, res) => {
  const documentation = {
    service: "OpenJWT - Open Source JWT Auth-as-a-Service",
    version: "1.0.0",
    description: "A minimal JWT authentication service for frontend developers",
    endpoints: {
      register: {
        method: "POST",
        path: "/register",
        description: "Register a new user account",
        body: {
          email: "string (required)",
          password: "string (required, min 6 chars)",
          name: "string (required)",
        },
        response: {
          success: "boolean",
          message: "string",
          token: "string (JWT)",
          user: {
            id: "string",
            email: "string",
            name: "string",
          },
        },
      },
      login: {
        method: "POST",
        path: "/login",
        description: "Authenticate existing user",
        body: {
          email: "string (required)",
          password: "string (required)",
        },
        response: {
          success: "boolean",
          message: "string",
          token: "string (JWT)",
          user: {
            id: "string",
            email: "string",
            name: "string",
          },
        },
      },
      verify: {
        method: "POST",
        path: "/verify",
        description: "Verify JWT token validity",
        body: {
          token: "string (required)",
        },
        response: {
          success: "boolean",
          message: "string",
          user: {
            id: "string",
            email: "string",
            name: "string",
          },
        },
      },
    },
    examples: {
      curl_register:
        "curl -X POST " +
        (req.get("host")
          ? `${req.protocol}://${req.get("host")}`
          : "http://localhost:3000") +
        '/register -H "Content-Type: application/json" -d \'{"email":"test@example.com","password":"test123","name":"Test User"}\'',
      curl_login:
        "curl -X POST " +
        (req.get("host")
          ? `${req.protocol}://${req.get("host")}`
          : "http://localhost:3000") +
        '/login -H "Content-Type: application/json" -d \'{"email":"test@example.com","password":"test123"}\'',
      curl_verify:
        "curl -X POST " +
        (req.get("host")
          ? `${req.protocol}://${req.get("host")}`
          : "http://localhost:3000") +
        '/verify -H "Content-Type: application/json" -d \'{"token":"YOUR_JWT_TOKEN_HERE"}\'',
    },
    security: {
      password_hashing: "bcrypt with 12 salt rounds",
      jwt_algorithm: "HS256",
      token_expiration: JWT_EXPIRES_IN,
      rate_limiting:
        "Enabled (100 requests per 15 minutes, 5 auth attempts per 15 minutes)",
    },
    cors: "Enabled for all origins (configure CORS_ORIGIN environment variable for production)",
    github: "https://github.com/SIDDHU123M/OpenJWT",
    license: "MIT",
  };

  res.json(documentation);
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "Service is healthy",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Register endpoint
app.post(
  "/register",
  authLimiter,
  validateRegistration,
  handleValidationErrors,
  async (req, res) => {
    try {
      const { email, password, name } = req.body;

      // Check if user already exists
      if (users.has(email)) {
        return res.status(409).json({
          success: false,
          message: "User with this email already exists",
        });
      }

      // Hash password
      const hashedPassword = await hashPassword(password);

      // Create user
      const user = {
        id: uuidv4(),
        email,
        name,
        password: hashedPassword,
        createdAt: new Date().toISOString(),
      };

      // Store user
      users.set(email, user);

      // Generate token
      const token = generateToken(user);

      // Return success response (exclude password)
      res.status(201).json({
        success: true,
        message: "User registered successfully",
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({
        success: false,
        message: "Internal server error",
      });
    }
  }
);

// Login endpoint
app.post(
  "/login",
  authLimiter,
  validateLogin,
  handleValidationErrors,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      // Find user
      const user = users.get(email);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Invalid email or password",
        });
      }

      // Verify password
      const isPasswordValid = await verifyPassword(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({
          success: false,
          message: "Invalid email or password",
        });
      }

      // Generate token
      const token = generateToken(user);

      // Return success response
      res.json({
        success: true,
        message: "Login successful",
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({
        success: false,
        message: "Internal server error",
      });
    }
  }
);

// Verify endpoint
app.post("/verify", validateToken, handleValidationErrors, (req, res) => {
  try {
    const { token } = req.body;

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user to ensure they still exist
    const user = users.get(decoded.email);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Token is valid but user no longer exists",
      });
    }

    // Return success response
    res.json({
      success: true,
      message: "Token is valid",
      user: {
        id: decoded.userId,
        email: decoded.email,
        name: decoded.name,
      },
    });
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        message: "Token has expired",
      });
    }

    console.error("Token verification error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({
    success: false,
    message: "Endpoint not found",
    availableEndpoints: [
      "GET /",
      "GET /health",
      "POST /register",
      "POST /login",
      "POST /verify",
    ],
  });
});

// Error handler
app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);
  res.status(500).json({
    success: false,
    message: "Internal server error",
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 OpenJWT Server is running on port ${PORT}`);
  console.log(`📖 Documentation: http://localhost:${PORT}/`);
  console.log(`🏥 Health check: http://localhost:${PORT}/health`);
});

module.exports = app;
