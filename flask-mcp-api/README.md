# Flask Mighty MCP Server Security API

A Flask API wrapper for the MCP Security Analyzer that provides HTTP endpoints to analyze GitHub repositories and local directories for security threats using advanced static analysis and LLM-powered detection.

## Features

- 🔒 **Comprehensive Security Analysis**: Detects 15+ attack vectors including command injection, data exfiltration, credential theft, and more
- 🤖 **AI-Powered Detection**: Integrates with Cerebras LLM for advanced threat analysis
- 🌐 **RESTful API**: Easy-to-use HTTP endpoints for integration with other tools
- 📊 **Detailed Reporting**: Returns complete JSON reports with threat details, risk scores, and recommendations
- ⚡ **Fast Analysis**: Quick mode for rapid scans, deep mode for comprehensive analysis
- 🔍 **Multiple Sources**: Supports both GitHub URLs and local directory paths

## Installation & Setup

### Prerequisites

- Python 3.11+
- `uv` package manager
- Git (for analyzing GitHub repositories)
- Optional: Cerebras API key (for LLM analysis)

### Quick Start

1. **Clone and navigate to the Flask API directory**:
   ```bash
   cd flask-mcp-api
   ```

2. **Install dependencies**:
   ```bash
   uv sync
   ```

3. **Set up environment variables** (optional, for LLM analysis):
   ```bash
   cp .env.example .env
   # Edit .env and add your CEREBRAS_API_KEY
   ```

## Running the Server

You have **two options** to run the Flask server:

### Option 1: Using run.sh (Recommended)
```bash
./run.sh
```
- ✅ Automatically activates virtual environment
- ✅ Handles missing .env file
- ✅ Sets up environment variables
- ✅ Provides helpful startup messages

### Option 2: Direct Python execution
```bash
uv run python app.py
```
- ⚡ Faster startup
- ⚠️ Requires manual environment setup
- ⚠️ Need to ensure .env is loaded manually

**Recommendation**: Use `./run.sh` for development and testing, use `uv run python app.py` for production deployments with proper environment management.

## API Endpoints

### Health Check
```http
GET /health
```
Returns server status and version information.

### Repository Analysis
```http
POST /analyze
Content-Type: application/json

{
  "github_url": "https://github.com/user/repo",
  "llm": true,
  "quick": false
}
```

**Parameters:**
- `github_url` (required): GitHub repository URL or local directory path
- `llm` (optional): Enable LLM analysis with Cerebras (default: false)
- `quick` (optional): Enable quick scan mode (default: false)

**Example Requests:**

```bash
# Basic analysis without LLM
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/github/github-mcp-server"}'

# Full analysis with LLM
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/github/github-mcp-server", "llm": true}'

# Quick scan of local directory
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"github_url": "/path/to/local/repo", "quick": true}'
```

## Response Format

The API returns a comprehensive JSON response with:

```json
{
  "status": "success",
  "repository": "https://github.com/user/repo",
  "scan_timestamp": "2025-08-10T17:10:58.824903",
  
  "assessment_summary": "Formatted summary like CLI output...",
  
  "threat_level": "LOW",
  "threat_score": 0.236,
  "confidence": 0.7,
  
  "threats_found": [
    {
      "attack_vector": "AttackVector.OBFUSCATION",
      "severity": "ThreatSeverity.MEDIUM",
      "confidence": 0.7,
      "file_path": "cmd/mcpcurl/main.go",
      "description": "Suspicious variable names detected",
      "evidence": {...}
    }
  ],
  
  "llm_analysis": {
    "aggregate_risk": 0.056,
    "total_findings": 1,
    "findings_by_type": {...}
  },
  
  "combined_ai_assessment": {
    "files_analyzed": 11,
    "combined_risk": 0.09,
    "verdict": "MINIMAL RISK - Safe to use"
  },
  
  "ml_explanations": [
    "LLM Risk Score: 5.45%",
    "AI Verdict: MINIMAL RISK - Safe to use"
  ],
  
  "recommendations": [...],
  "mitigations": [...]
}
```

## LLM Analysis Setup

To enable AI-powered analysis with Cerebras:

1. **Get Cerebras API Key**: Sign up at [Cerebras Cloud](https://cloud.cerebras.ai/)

2. **Set Environment Variable**:
   ```bash
   export CEREBRAS_API_KEY="your_api_key_here"
   ```
   
   Or add to `.env` file:
   ```
   CEREBRAS_API_KEY=your_api_key_here
   ```

3. **Use in API calls**:
   ```json
   {
     "github_url": "https://github.com/user/repo",
     "llm": true
   }
   ```

## Configuration

### Environment Variables
- `CEREBRAS_API_KEY`: Required for LLM analysis
- `PORT`: Server port (default: 5000, but often runs on 8080)

### Analysis Modes
- **Quick Mode** (`"quick": true`): Fast analysis, skips deep inspection
- **Deep Mode** (`"quick": false`): Comprehensive analysis with data flow detection
- **LLM Mode** (`"llm": true`): Adds AI-powered threat detection

## Error Handling

The API returns appropriate HTTP status codes:
- `200`: Successful analysis
- `400`: Bad request (missing parameters, invalid input)
- `500`: Server error (analysis failure, missing dependencies)

Example error response:
```json
{
  "status": "error",
  "error": "CEREBRAS_API_KEY not found",
  "message": "Please set CEREBRAS_API_KEY environment variable"
}
```

## Development

### Project Structure
```
flask-mcp-api/
├── app.py              # Main Flask application
├── run.sh              # Startup script
├── pyproject.toml      # Dependencies
├── .env.example        # Environment template
└── reports/            # Generated reports (auto-created)
```

### Dependencies
- Flask 3.0+ for web framework
- Cerebras Cloud SDK for LLM integration
- GitPython for repository cloning
- NumPy, NetworkX for analysis algorithms

### Testing
```bash
# Test health endpoint
curl http://localhost:8080/health

# Test basic analysis
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/github/github-mcp-server"}'
```

## Production Deployment

For production use:

1. **Use a production WSGI server** (e.g., Gunicorn):
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:8080 app:app
   ```

2. **Set environment variables** securely
3. **Configure reverse proxy** (nginx) for SSL/TLS
4. **Set up monitoring** and logging

## Troubleshooting

### Common Issues

**Port already in use**: macOS AirPlay uses port 5000
```bash
# Use different port
PORT=8080 uv run python app.py
```

**LLM not working**: Check API key and dependencies
```bash
echo $CEREBRAS_API_KEY  # Should show your key
uv sync  # Reinstall dependencies
```

**Import errors**: Ensure parent directory is accessible
```bash
# Run from project root
cd /path/to/secure-toolings/flask-mcp-api
```

## Integration Examples

### Postman Collection
Import these endpoints into Postman:
- `GET {{base_url}}/health`
- `POST {{base_url}}/analyze` with JSON body

### Python Client
```python
import requests

response = requests.post('http://localhost:8080/analyze', json={
    'github_url': 'https://github.com/user/repo',
    'llm': True
})

result = response.json()
print(f"Threat Level: {result['threat_level']}")
print(f"AI Verdict: {result['combined_ai_assessment']['verdict']}")
```

### JavaScript/Node.js
```javascript
const response = await fetch('http://localhost:8080/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    github_url: 'https://github.com/user/repo',
    llm: true
  })
});

const result = await response.json();
console.log('Threats found:', result.threats_found.length);
```

---

## Related

- Main analyzer: `../analyzers/comprehensive_mcp_analyzer.py`
- Command-line version: Use `python comprehensive_mcp_analyzer.py --help`
- Report formatter: `../analyzers/report_formatter.py`