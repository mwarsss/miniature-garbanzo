# Intelli-Scan Deployment Guide

This guide covers deploying Intelli-Scan to various platforms.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Variables](#environment-variables)
- [Local Deployment](#local-deployment)
- [Docker Deployment](#docker-deployment)
- [Heroku Deployment](#heroku-deployment)
- [AWS Deployment](#aws-deployment)
- [Production Checklist](#production-checklist)

## Prerequisites

- PostgreSQL database (15+)
- Google Gemini API key
- (Optional) Redis instance for caching
- (Optional) Sentry DSN for error tracking

## Environment Variables

Create a `.env` file based on `.env.example`:

```bash
# Required
DATABASE_URL=postgresql://user:password@host:5432/database
GOOGLE_API_KEY=your_gemini_api_key

# Optional but recommended
REDIS_URL=redis://localhost:6379/0
SENTRY_DSN=your_sentry_dsn
LOG_LEVEL=INFO
ENABLE_CACHING=true
```

## Local Deployment

### Backend

```bash
cd Intelli-scan/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp ../../.env.example .env
# Edit .env with your configuration

# Initialize database
python -c "from database import create_tables; from config import settings; create_tables(settings.database_url)"

# Run server
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Set API URL
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local

# Run development server
npm run dev

# Or build for production
npm run build
npm start
```

## Docker Deployment

### Using Docker Compose

```bash
cd Intelli-scan

# Build and start services
docker-compose up --build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Custom Docker Setup

**Backend Dockerfile** (already exists):
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "$PORT"]
```

**Frontend Dockerfile**:
```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
EXPOSE 3000
CMD ["npm", "start"]
```

## Heroku Deployment

### Backend (Already Deployed)

```bash
cd Intelli-scan/backend

# Login to Heroku
heroku login

# Create app
heroku create intelli-scan-api

# Add PostgreSQL
heroku addons:create heroku-postgresql:mini

# Add Redis (optional)
heroku addons:create heroku-redis:mini

# Set environment variables
heroku config:set GOOGLE_API_KEY=your_key
heroku config:set ENABLE_CACHING=true

# Deploy
git push heroku main

# View logs
heroku logs --tail
```

### Frontend

```bash
cd frontend

# Create app
heroku create intelli-scan-frontend

# Set environment variables
heroku config:set NEXT_PUBLIC_API_URL=https://intelli-scan-api.herokuapp.com

# Add buildpack
heroku buildpacks:set heroku/nodejs

# Deploy
git push heroku main
```

## AWS Deployment

### Using AWS Elastic Beanstalk

**Backend:**

```bash
# Install EB CLI
pip install awsebcli

# Initialize
cd Intelli-scan/backend
eb init -p python-3.11 intelli-scan-api

# Create environment
eb create intelli-scan-api-prod

# Set environment variables
eb setenv DATABASE_URL=your_db_url GOOGLE_API_KEY=your_key

# Deploy
eb deploy

# Open app
eb open
```

**Frontend:**

```bash
cd frontend

# Initialize
eb init -p node.js-18 intelli-scan-frontend

# Create environment
eb create intelli-scan-frontend-prod

# Set environment variables
eb setenv NEXT_PUBLIC_API_URL=your_api_url

# Deploy
eb deploy
```

### Using AWS ECS (Docker)

1. **Build and push Docker images:**

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin your-account.dkr.ecr.us-east-1.amazonaws.com

# Build and tag
docker build -t intelli-scan-api ./Intelli-scan/backend
docker tag intelli-scan-api:latest your-account.dkr.ecr.us-east-1.amazonaws.com/intelli-scan-api:latest

# Push
docker push your-account.dkr.ecr.us-east-1.amazonaws.com/intelli-scan-api:latest
```

2. **Create ECS task definition and service** (use AWS Console or CLI)

3. **Set up Application Load Balancer**

4. **Configure environment variables in task definition**

## Production Checklist

### Security

- [ ] Add authentication/authorization
- [ ] Enable HTTPS/SSL
- [ ] Set strong database passwords
- [ ] Rotate API keys regularly
- [ ] Configure CORS properly
- [ ] Enable rate limiting
- [ ] Set up firewall rules
- [ ] Use secrets manager for sensitive data

### Performance

- [ ] Enable Redis caching
- [ ] Configure database connection pooling
- [ ] Set up CDN for frontend assets
- [ ] Enable gzip compression
- [ ] Optimize database queries
- [ ] Add database indexes
- [ ] Configure auto-scaling

### Monitoring

- [ ] Set up error tracking (Sentry)
- [ ] Configure logging aggregation
- [ ] Set up uptime monitoring
- [ ] Configure alerts for failures
- [ ] Monitor database performance
- [ ] Track API response times
- [ ] Set up dashboards (Grafana)

### Reliability

- [ ] Set up automated backups
- [ ] Configure health checks
- [ ] Implement circuit breakers
- [ ] Set up retry logic
- [ ] Configure timeouts
- [ ] Test disaster recovery
- [ ] Document runbooks

### Compliance

- [ ] Review security policies
- [ ] Implement audit logging
- [ ] Set up data retention policies
- [ ] Configure GDPR compliance (if applicable)
- [ ] Document data flows
- [ ] Review third-party dependencies

## Troubleshooting

### Database Connection Issues

```bash
# Test database connection
psql $DATABASE_URL

# Check connection pool
# View logs for connection errors
```

### API Not Responding

```bash
# Check if service is running
ps aux | grep uvicorn

# Check logs
tail -f /var/log/intelli-scan/api.log

# Test endpoint
curl http://localhost:8000/health
```

### High Memory Usage

```bash
# Check memory usage
docker stats

# Restart services
docker-compose restart

# Scale down if needed
```

### Slow Scans

- Enable Redis caching
- Increase scan timeout
- Check scanner tool versions
- Monitor AI API rate limits

## Maintenance

### Updating Dependencies

```bash
# Backend
pip install --upgrade -r requirements.txt

# Frontend
npm update

# Check for security vulnerabilities
npm audit
pip-audit
```

### Database Migrations

```bash
# Backup database first
pg_dump $DATABASE_URL > backup.sql

# Run migrations
python -c "from database import create_tables; from config import settings; create_tables(settings.database_url)"
```

### Scaling

**Horizontal Scaling:**
- Add more backend instances
- Use load balancer
- Ensure stateless design

**Vertical Scaling:**
- Increase instance size
- Add more CPU/RAM
- Upgrade database tier

## Support

For deployment issues:
- Check logs first
- Review error messages
- Consult documentation
- Open GitHub issue

---

**Last Updated:** 2024-01-15
