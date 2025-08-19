"""
Security middleware and utilities for the MCP Security Dashboard.
Implements rate limiting, input validation, and security controls.
"""

import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


class SecurityValidator:
    """Secure input validation for API endpoints"""

    # Allowed GitHub domains
    ALLOWED_GITHUB_DOMAINS = {'github.com', 'raw.githubusercontent.com'}

    # Blocked path patterns
    BLOCKED_PATH_PATTERNS = [
        r'\.\./',           # Directory traversal
        r'/\.\.',           # Directory traversal
        r'^/etc/',          # System files
        r'^/var/',          # System files
        r'^/usr/',          # System files
        r'^/root/',         # Root directory
        r'^/home/[^/]+/\.',  # Hidden files in home dirs
        r'\.ssh/',          # SSH keys
        r'\.env',           # Environment files
        r'\.git/',          # Git repositories
        r'\.svn/',          # SVN repositories
        r'id_rsa',          # SSH private keys
        r'\.pem$',          # Certificate files
        r'\.key$',          # Key files
        r'shadow$',         # Password files
        r'passwd$',         # Password files
    ]

    @classmethod
    def validate_local_path(cls, path: str) -> str:
        """Validate and sanitize local file paths"""
        if not path:
            raise HTTPException(status_code=400, detail="Path cannot be empty")

        # Resolve to absolute path to prevent traversal
        try:
            abs_path = Path(path).resolve()
        except (OSError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid path format")

        # Convert to string for pattern checking
        path_str = str(abs_path)

        # Check against blocked patterns
        for pattern in cls.BLOCKED_PATH_PATTERNS:
            if re.search(pattern, path_str, re.IGNORECASE):
                raise HTTPException(
                    status_code=403,
                    detail="Access denied: Path contains restricted pattern"
                )

        # Ensure path exists and is readable
        if not abs_path.exists():
            raise HTTPException(status_code=404, detail="Path does not exist")

        if not os.access(abs_path, os.R_OK):
            raise HTTPException(status_code=403, detail="Permission denied")

        # Check if it's in allowed directories
        cwd = Path.cwd().resolve()
        
        # Find project root by looking for pyproject.toml or .git
        current = Path(__file__).parent.resolve()
        project_root = None
        while current != current.parent:
            if (current / "pyproject.toml").exists() or (current / ".git").exists():
                project_root = current
                break
            current = current.parent
        
        if not project_root:
            # Fallback to 2 levels up from dashboard
            project_root = Path(__file__).parent.parent.parent.resolve()
        
        # Allow paths within current working directory, project root, or temp dirs
        allowed = False
        
        # Check if path is within cwd
        try:
            abs_path.relative_to(cwd)
            allowed = True
        except ValueError:
            pass
        
        # Check if path is within project root
        if not allowed:
            try:
                abs_path.relative_to(project_root)
                allowed = True
            except ValueError:
                pass
        
        # Check if it's the project root itself
        if not allowed and abs_path == project_root:
            allowed = True
        
        # Check if it's an allowed system scan directory
        if not allowed:
            allowed_scan_dirs = ['/tmp', '/var/tmp']
            if any(str(abs_path).startswith(allowed_dir) for allowed_dir in allowed_scan_dirs):
                allowed = True
        
        if not allowed:
            raise HTTPException(
                status_code=403,
                detail="Access denied: Path outside allowed directories"
            )

        return str(abs_path)

    @classmethod
    def validate_github_url(cls, url: str) -> str:
        """Validate and sanitize GitHub URLs"""
        if not url:
            raise HTTPException(status_code=400, detail="URL cannot be empty")

        try:
            parsed = urlparse(url)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid URL format")

        # Check scheme
        if parsed.scheme not in ('http', 'https'):
            raise HTTPException(status_code=400, detail="Only HTTP/HTTPS URLs allowed")

        # Check domain
        if parsed.netloc not in cls.ALLOWED_GITHUB_DOMAINS:
            raise HTTPException(
                status_code=400,
                detail=f"Only {', '.join(cls.ALLOWED_GITHUB_DOMAINS)} domains allowed"
            )

        # Additional GitHub URL validation
        if not re.match(r'^https?://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+/?$', url):
            raise HTTPException(status_code=400, detail="Invalid GitHub repository URL format")

        return url

    @classmethod
    def validate_scan_options(cls, options: dict) -> dict:
        """Validate scan configuration options"""
        safe_options = {}

        # Validate boolean options
        bool_options = ['quick_mode', 'enable_llm', 'deep_scan']
        for opt in bool_options:
            if opt in options:
                if not isinstance(options[opt], bool):
                    raise HTTPException(status_code=400, detail=f"{opt} must be boolean")
                safe_options[opt] = options[opt]

        # Validate profile option
        if 'profile' in options:
            allowed_profiles = ['production', 'development', 'security-tool']
            if options['profile'] not in allowed_profiles:
                raise HTTPException(
                    status_code=400,
                    detail=f"Profile must be one of: {', '.join(allowed_profiles)}"
                )
            safe_options['profile'] = options['profile']

        return safe_options

class RateLimiter:
    """Simple in-memory rate limiter"""

    def __init__(self):
        self.requests: dict[str, list[float]] = {}
        self.limits = {
            '/api/scan/local': (20, 300),      # 20 requests per 5 minutes
            '/api/scan/github': (15, 300),     # 15 requests per 5 minutes
            '/api/scan/config-discovery': (30, 60),  # 30 requests per minute
            '/api/stats': (100, 60),           # 100 requests per minute for stats
            '/api/run': (100, 60),             # 100 requests per minute for run details
            'default': (60, 60)                # 60 requests per minute for other endpoints
        }

    def is_allowed(self, client_ip: str, endpoint: str) -> bool:
        """Check if request is within rate limits"""
        now = time.time()
        key = f"{client_ip}:{endpoint}"

        # Get limits for this endpoint
        max_requests, window = self.limits.get(endpoint, self.limits['default'])

        # Initialize if not exists
        if key not in self.requests:
            self.requests[key] = []

        # Clean old requests outside the window
        self.requests[key] = [req_time for req_time in self.requests[key] if now - req_time < window]

        # Check if limit exceeded
        if len(self.requests[key]) >= max_requests:
            return False

        # Add current request
        self.requests[key].append(now)
        return True

# Global rate limiter instance
rate_limiter = RateLimiter()

async def security_middleware(request: Request, call_next):
    """Security middleware for API endpoints"""

    # Skip middleware for static files and non-API routes
    if not request.url.path.startswith('/api/'):
        response = await call_next(request)
        return response

    # Get client IP
    client_ip = request.client.host
    if 'x-forwarded-for' in request.headers:
        client_ip = request.headers['x-forwarded-for'].split(',')[0].strip()

    # Rate limiting
    if not rate_limiter.is_allowed(client_ip, request.url.path):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please try again later."}
        )

    # Add security headers to response
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return response

def safe_error_handler(error: Exception) -> HTTPException:
    """Safely handle errors without information disclosure"""

    # Log the actual error internally (you'd want proper logging here)
    print(f"Internal error: {type(error).__name__}: {str(error)}")

    # Return generic error to client
    if isinstance(error, HTTPException):
        return error

    # Don't expose internal errors
    return HTTPException(
        status_code=500,
        detail="Internal server error occurred"
    )
