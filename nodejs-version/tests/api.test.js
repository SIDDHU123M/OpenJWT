const request = require("supertest");
const app = require("../server");

describe("OpenJWT API", () => {
  let userToken = "";
  const testUser = {
    email: "test@example.com",
    password: "test123",
    name: "Test User",
  };

  describe("GET /", () => {
    it("should return documentation", async () => {
      const res = await request(app).get("/").expect(200);

      expect(res.body).toHaveProperty("service");
      expect(res.body).toHaveProperty("endpoints");
      expect(res.body.service).toContain("OpenJWT");
    });
  });

  describe("GET /health", () => {
    it("should return health status", async () => {
      const res = await request(app).get("/health").expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body).toHaveProperty("uptime");
    });
  });

  describe("POST /register", () => {
    it("should register a new user", async () => {
      const res = await request(app)
        .post("/register")
        .send(testUser)
        .expect(201);

      expect(res.body.success).toBe(true);
      expect(res.body).toHaveProperty("token");
      expect(res.body.user.email).toBe(testUser.email);
      expect(res.body.user.name).toBe(testUser.name);
      expect(res.body.user).not.toHaveProperty("password");

      userToken = res.body.token;
    });

    it("should not register user with existing email", async () => {
      const res = await request(app)
        .post("/register")
        .send(testUser)
        .expect(409);

      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain("already exists");
    });

    it("should validate email format", async () => {
      const res = await request(app)
        .post("/register")
        .send({
          ...testUser,
          email: "invalid-email",
        })
        .expect(400);

      expect(res.body.success).toBe(false);
    });

    it("should validate password length", async () => {
      const res = await request(app)
        .post("/register")
        .send({
          ...testUser,
          email: "test2@example.com",
          password: "123",
        })
        .expect(400);

      expect(res.body.success).toBe(false);
    });

    it("should validate required name", async () => {
      const res = await request(app)
        .post("/register")
        .send({
          email: "test3@example.com",
          password: "test123",
        })
        .expect(400);

      expect(res.body.success).toBe(false);
    });
  });

  describe("POST /login", () => {
    it("should login with valid credentials", async () => {
      const res = await request(app)
        .post("/login")
        .send({
          email: testUser.email,
          password: testUser.password,
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body).toHaveProperty("token");
      expect(res.body.user.email).toBe(testUser.email);
    });

    it("should not login with invalid email", async () => {
      const res = await request(app)
        .post("/login")
        .send({
          email: "nonexistent@example.com",
          password: testUser.password,
        })
        .expect(401);

      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain("Invalid email or password");
    });

    it("should not login with invalid password", async () => {
      const res = await request(app)
        .post("/login")
        .send({
          email: testUser.email,
          password: "wrongpassword",
        })
        .expect(401);

      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain("Invalid email or password");
    });

    it("should validate email format", async () => {
      const res = await request(app)
        .post("/login")
        .send({
          email: "invalid-email",
          password: testUser.password,
        })
        .expect(400);

      expect(res.body.success).toBe(false);
    });
  });

  describe("POST /verify", () => {
    it("should verify valid token", async () => {
      const res = await request(app)
        .post("/verify")
        .send({ token: userToken })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.user.email).toBe(testUser.email);
    });

    it("should not verify invalid token", async () => {
      const res = await request(app)
        .post("/verify")
        .send({ token: "invalid-token" })
        .expect(401);

      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain("Invalid token");
    });

    it("should not verify empty token", async () => {
      const res = await request(app)
        .post("/verify")
        .send({ token: "" })
        .expect(400);

      expect(res.body.success).toBe(false);
    });
  });

  describe("404 Handler", () => {
    it("should handle unknown endpoints", async () => {
      const res = await request(app).get("/unknown-endpoint").expect(404);

      expect(res.body.success).toBe(false);
      expect(res.body).toHaveProperty("availableEndpoints");
    });
  });
});
