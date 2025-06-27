# Deployment Guide

## Heroku Deployment

### Prerequisites

- Git installed
- Heroku CLI installed
- Heroku account

### Deploy Node.js Version

1. **Prepare the application:**

```bash
cd nodejs-version
cp .env.example .env
# Edit .env with your production values
```

2. **Create Heroku app:**

```bash
heroku create your-app-name
```

3. **Set environment variables:**

```bash
heroku config:set JWT_SECRET=your-super-secret-production-key
heroku config:set JWT_EXPIRES_IN=24h
heroku config:set CORS_ORIGIN=https://yourdomain.com
heroku config:set NODE_ENV=production
```

4. **Deploy from subdirectory:**

```bash
# From the root directory
git subtree push --prefix nodejs-version heroku main
```

### Deploy Python Version

1. **Prepare the application:**

```bash
cd python-version
cp .env.example .env
# Edit .env with your production values
```

2. **Create Heroku app:**

```bash
heroku create your-app-name
```

3. **Set environment variables:**

```bash
heroku config:set JWT_SECRET=your-super-secret-production-key
heroku config:set JWT_EXPIRES_HOURS=24
heroku config:set CORS_ORIGIN=https://yourdomain.com
heroku config:set FLASK_ENV=production
```

4. **Add Redis addon (for rate limiting):**

```bash
heroku addons:create heroku-redis:mini
```

5. **Deploy from subdirectory:**

```bash
# From the root directory
git subtree push --prefix python-version heroku main
```

## Alternative Deployment Options

### Docker Deployment

Create `Dockerfile` for Node.js:

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

Create `Dockerfile` for Python:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "app:app"]
```

### Railway Deployment

1. Connect your GitHub repository to Railway
2. Select the subdirectory (nodejs-version or python-version)
3. Set environment variables in Railway dashboard
4. Deploy automatically

### Vercel Deployment (Node.js only)

1. Install Vercel CLI: `npm i -g vercel`
2. In nodejs-version directory: `vercel`
3. Set environment variables in Vercel dashboard

## Environment Variables

### Required Variables

- `JWT_SECRET`: Strong secret key for JWT signing
- `CORS_ORIGIN`: Allowed origins for CORS (use \* for development only)

### Optional Variables

- `PORT`: Server port (defaults to 3000 for Node.js, 5000 for Python)
- `JWT_EXPIRES_IN` (Node.js) / `JWT_EXPIRES_HOURS` (Python): Token expiration
- `REDIS_URL` (Python): Redis connection for rate limiting

## Security Considerations

1. **Use strong JWT secrets** (minimum 32 characters)
2. **Configure CORS properly** for production
3. **Use HTTPS** in production
4. **Monitor rate limits** and adjust as needed
5. **Consider using a database** instead of in-memory storage
6. **Implement proper logging** and monitoring
7. **Regular security updates** for dependencies

## Monitoring and Logging

### Heroku Logs

```bash
heroku logs --tail
```

### Health Check

Both implementations provide a `/health` endpoint for monitoring.

## Scaling

### Horizontal Scaling

- Both implementations are stateless (with in-memory storage limitation)
- Use load balancers for multiple instances
- Consider Redis for session storage in Python version

### Database Integration

Replace in-memory storage with:

- PostgreSQL (recommended for Heroku)
- MongoDB
- MySQL
- SQLite (development only)

## Troubleshooting

### Common Issues

1. **CORS errors**: Check CORS_ORIGIN environment variable
2. **Token expiration**: Verify JWT expiration settings
3. **Rate limiting**: Adjust rate limit configuration
4. **Memory issues**: Consider database integration for production

### Debug Mode

- Node.js: Set `NODE_ENV=development`
- Python: Set `FLASK_ENV=development`
