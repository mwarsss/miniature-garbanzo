# Intelli-Scan: AI-Augmented SAST Agent

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/your-username/miniature-garbanzo/workflows/Tests/badge.svg)](https://github.com/your-username/miniature-garbanzo/actions)

**An AI agent that actually reads your code to find the SAST vulnerabilities that matter. Stop chasing ghosts. 👻**

---

## 🎯 The Problem

Your SAST scanner just dumped 157 "critical" alerts on you for your last push. Let's be real, most of them are probably noise. **Alert fatigue** is a legit problem, and it's ironically making us less secure by hiding real threats in a flood of low-context false positives. Chasing these ghosts wastes dev time and money.

## 💡 The Solution

This isn't just another scanner. It's an **AI Security Agent** that acts as an intelligence layer on top of standard SAST tools. It uses Google Gemini AI to actually *read* the relevant parts of your code and understands the application's topology to see what's *actually* exploitable.

Think of it as a junior security analyst in a box—it does the initial triage so you can focus on the real fires.

## ✨ Features

- 🔍 **Automated Security Scanning** - Trivy (SCA) + Semgrep (SAST)
- 🤖 **AI-Powered Analysis** - Gemini 2.0 Flash for intelligent triage
- 📊 **Policy-Aware** - Upload your security policies for contextual analysis
- 🎯 **Smart Prioritization** - Focus on what actually matters
- 📝 **Automated Remediation** - Get specific code fixes
- 📈 **Scan History** - Track improvements over time
- 📄 **Report Generation** - Markdown and PDF exports
- 🎨 **Modern Dashboard** - Real-time status updates

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   Next.js   │─────▶│   FastAPI    │─────▶│ PostgreSQL  │
│  Frontend   │      │   Backend    │      │  Database   │
└─────────────┘      └──────────────┘      └─────────────┘
                            │
                            ├─────▶ Trivy Scanner
                            ├─────▶ Semgrep Scanner
                            └─────▶ Gemini AI
```

### Tech Stack

- **Backend:** Python 3.11+, FastAPI, PostgreSQL
- **Frontend:** Next.js 16, React 19, TypeScript, TailwindCSS
- **AI:** Google Gemini 2.0 Flash
- **Scanners:** Trivy (SCA), Semgrep (SAST)
- **Deployment:** Docker, Heroku
- **Caching:** Redis (optional)

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Docker (optional)
- Google Gemini API key

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/miniature-garbanzo.git
   cd miniature-garbanzo
   ```

2. **Set up the backend**
   ```bash
   cd Intelli-scan/backend
   
   # Create virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Copy environment template
   cp ../../.env.example .env
   
   # Edit .env with your configuration
   nano .env
   
   # Run database migrations
   python -c "from database import create_tables; from config import settings; create_tables(settings.database_url)"
   
   # Start the server
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

3. **Set up the frontend**
   ```bash
   cd ../../frontend
   
   # Install dependencies
   npm install
   
   # Start development server
   npm run dev
   ```

4. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

### Docker Deployment

```bash
cd Intelli-scan
docker-compose up --build
```

## 📖 Usage

### Starting a Scan

1. Navigate to the dashboard
2. Enter a GitHub repository URL
3. Click "Start Scan"
4. Wait for AI analysis (typically 30-60 seconds)
5. Review prioritized vulnerabilities
6. Generate remediation plan

### API Usage

```bash
# Start a scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/example/repo"}'

# Check scan status
curl http://localhost:8000/scan/{scan_id}

# Get remediation plan
curl http://localhost:8000/scan/{scan_id}/remediation

# List all scans
curl http://localhost:8000/scans
```

### Uploading Security Policies

```bash
curl -X POST http://localhost:8000/policies \
  -F "file=@security-policy.pdf"
```

## 🧪 Testing

### Backend Tests

```bash
cd Intelli-scan/backend
pytest tests/ --cov=. --cov-report=html
```

### Frontend Tests

```bash
cd frontend
npm test
```

### Run All Tests

```bash
# Using GitHub Actions locally
act -j backend-tests
act -j frontend-tests
```

## 📊 Monitoring & Metrics

Access metrics at `http://localhost:8000/metrics` to see:

- Total scans by status
- Average scan duration
- AI analysis performance
- Scanner success rates
- Cache hit rates

## 🔧 Configuration

All configuration is managed through environment variables. See `.env.example` for a complete list.

### Key Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `GOOGLE_API_KEY` | Gemini API key | Required |
| `SCAN_TIMEOUT_MINUTES` | Max scan duration | 15 |
| `MAX_CONCURRENT_SCANS` | Parallel scan limit | 5 |
| `ENABLE_CACHING` | Enable Redis caching | true |
| `LOG_LEVEL` | Logging verbosity | INFO |

## 🛡️ Security Considerations

- **No Authentication**: Currently, the application has no authentication. **Do not expose to the public internet without adding authentication first.**
- **API Keys**: Store API keys securely using environment variables
- **Database**: Use strong passwords and restrict network access
- **CORS**: Configure `CORS_ORIGINS` appropriately for production

## 📈 Performance Optimization

- **Caching**: Enable Redis for 10x faster repeated scans
- **Connection Pooling**: Database connections are pooled automatically
- **Retry Logic**: Automatic retries with exponential backoff
- **Circuit Breakers**: Prevents cascading failures

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Write tests for new features
- Follow PEP 8 for Python code
- Use ESLint for TypeScript/JavaScript
- Update documentation as needed
- Ensure all tests pass before submitting PR

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Trivy** - Vulnerability scanner by Aqua Security
- **Semgrep** - Static analysis tool by r2c
- **Google Gemini** - AI analysis engine
- **FastAPI** - Modern Python web framework
- **Next.js** - React framework

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/miniature-garbanzo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/miniature-garbanzo/discussions)

## 🗺️ Roadmap

- [ ] User authentication and authorization
- [ ] WebSocket support for real-time updates
- [ ] Scheduled scans
- [ ] GitHub webhook integration
- [ ] Custom Semgrep rules
- [ ] Vulnerability tracking and management
- [ ] Team collaboration features
- [ ] Integration with Jira/GitHub Issues
- [ ] Multi-language support
- [ ] Self-hosted LLM option

---

**Project Status:** This is a capstone project for the Bachelor of Technology in Information Security and Assurance program. Currently under active development.

Built with ❤️ by the Intelli-Scan Team
