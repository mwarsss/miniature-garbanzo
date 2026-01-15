# Contributing to Intelli-Scan

Thank you for your interest in contributing to Intelli-Scan! This document provides guidelines and instructions for contributing.

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Git
- Docker (optional)

### Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/your-username/miniature-garbanzo.git
   cd miniature-garbanzo
   ```

2. **Set up the backend**
   ```bash
   cd Intelli-scan/backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   cp ../../.env.example .env
   # Edit .env with your configuration
   ```

3. **Set up the frontend**
   ```bash
   cd ../../frontend
   npm install
   ```

4. **Run tests**
   ```bash
   # Backend
   cd ../Intelli-scan/backend
   pytest

   # Frontend
   cd ../../frontend
   npm test
   ```

## 📝 Development Guidelines

### Code Style

**Python (Backend)**
- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use `black` for formatting
- Use `pylint` for linting

```bash
black .
pylint *.py
```

**TypeScript/JavaScript (Frontend)**
- Follow ESLint rules
- Use TypeScript for type safety
- Use functional components with hooks
- Maximum line length: 100 characters

```bash
npm run lint
```

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(api): add WebSocket support for real-time scan updates

fix(scanner): handle timeout errors gracefully

docs(readme): update installation instructions
```

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring

## 🧪 Testing

### Writing Tests

**Backend Tests**
- Place tests in `Intelli-scan/backend/tests/`
- Use pytest fixtures for common setup
- Aim for 80%+ code coverage
- Test both success and failure cases

```python
def test_scan_endpoint_success(client, mock_db):
    """Test successful scan initiation."""
    response = client.post("/scan", json={"repo_url": "https://github.com/test/repo"})
    assert response.status_code == 202
    assert "scan_id" in response.json()
```

**Frontend Tests**
- Place tests next to components (`*.test.tsx`)
- Test user interactions
- Test error states
- Use React Testing Library

### Running Tests

```bash
# Backend - all tests
cd Intelli-scan/backend
pytest

# Backend - with coverage
pytest --cov=. --cov-report=html

# Backend - specific test file
pytest tests/test_api.py

# Frontend - all tests
cd ../../frontend
npm test

# Frontend - with coverage
npm test -- --coverage
```

## 🔍 Code Review Process

1. **Self-review** your changes before submitting
2. **Run all tests** and ensure they pass
3. **Update documentation** if needed
4. **Create a pull request** with a clear description
5. **Address review comments** promptly
6. **Squash commits** before merging (if requested)

### Pull Request Checklist

- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] No console errors or warnings
- [ ] Commit messages follow convention
- [ ] PR description is clear and complete

## 🐛 Reporting Bugs

### Before Reporting

1. Check existing issues
2. Verify it's reproducible
3. Test with the latest version

### Bug Report Template

```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '...'
3. See error

**Expected behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Python version: [e.g., 3.11.5]
- Node version: [e.g., 18.17.0]

**Additional context**
Any other relevant information.
```

## 💡 Suggesting Features

### Feature Request Template

```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
A clear description of what you want to happen.

**Describe alternatives you've considered**
Other solutions you've thought about.

**Additional context**
Any other relevant information, mockups, or examples.
```

## 📚 Documentation

- Update README.md for user-facing changes
- Add docstrings to all functions and classes
- Update API documentation in code comments
- Add examples for new features

### Documentation Style

**Python Docstrings**
```python
def analyze_vulnerabilities(scan_data: dict) -> AnalysisResult:
    """
    Analyze scan data and generate vulnerability report.
    
    Args:
        scan_data: Dictionary containing SCA and SAST results
        
    Returns:
        AnalysisResult object with summary and top vulnerabilities
        
    Raises:
        ValueError: If scan_data is invalid
        AIAnalysisError: If AI analysis fails
    """
```

**TypeScript/JSDoc**
```typescript
/**
 * Fetch scan details from the API
 * @param scanId - UUID of the scan to fetch
 * @returns Promise resolving to scan details
 * @throws Error if fetch fails
 */
async function fetchScanDetails(scanId: string): Promise<ScanDetail> {
  // ...
}
```

## 🏗️ Architecture Guidelines

### Backend

- Use dependency injection where possible
- Keep functions small and focused
- Use type hints consistently
- Handle errors gracefully
- Log important events
- Use async/await for I/O operations

### Frontend

- Keep components small and reusable
- Use custom hooks for shared logic
- Implement proper error boundaries
- Use TypeScript for type safety
- Follow React best practices
- Optimize for performance

## 🔐 Security

- Never commit secrets or API keys
- Use environment variables for configuration
- Validate all user inputs
- Sanitize data before display
- Follow OWASP guidelines
- Report security issues privately

## 📞 Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security**: Email security@example.com (private)
- **Chat**: Join our Discord (if available)

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for contributing to Intelli-Scan! 🎉
