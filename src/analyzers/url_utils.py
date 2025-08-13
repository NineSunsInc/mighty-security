#!/usr/bin/env python3
"""
Shared URL utilities for DRY URL handling across analyzers
"""

import re
from urllib.parse import urlparse
from typing import Tuple, Optional


def is_github_url(target: str) -> bool:
    """
    Check if a target is a GitHub URL.
    
    Args:
        target: The target string to check
        
    Returns:
        True if it's a GitHub URL, False otherwise
    """
    if not isinstance(target, str):
        return False
        
    # Handle both http and https
    github_patterns = [
        r'^https?://github\.com/',
        r'^https?://www\.github\.com/',
        r'^github\.com/',
        r'^www\.github\.com/'
    ]
    
    for pattern in github_patterns:
        if re.match(pattern, target, re.IGNORECASE):
            return True
    
    return False


def parse_github_url(url: str) -> Optional[Tuple[str, str]]:
    """
    Parse a GitHub URL to extract owner and repo name.
    
    Args:
        url: GitHub URL to parse
        
    Returns:
        Tuple of (owner, repo) or None if not a valid GitHub URL
    """
    if not is_github_url(url):
        return None
    
    # Clean up the URL
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) >= 2:
            owner = path_parts[0]
            repo = path_parts[1]
            
            # Remove .git extension if present
            if repo.endswith('.git'):
                repo = repo[:-4]
            
            return (owner, repo)
    except Exception:
        pass
    
    return None


def is_url(target: str) -> bool:
    """
    Check if a target is any URL (not just GitHub).
    
    Args:
        target: The target string to check
        
    Returns:
        True if it's a URL, False otherwise
    """
    if not isinstance(target, str):
        return False
    
    url_patterns = [
        r'^https?://',
        r'^ftp://',
        r'^git://',
        r'^ssh://'
    ]
    
    for pattern in url_patterns:
        if re.match(pattern, target, re.IGNORECASE):
            return True
    
    # Also check for common domains without protocol
    common_domains = [
        r'^github\.com/',
        r'^gitlab\.com/',
        r'^bitbucket\.org/',
        r'^www\.'
    ]
    
    for pattern in common_domains:
        if re.match(pattern, target, re.IGNORECASE):
            return True
    
    return False


def normalize_github_url(url: str) -> str:
    """
    Normalize a GitHub URL to a consistent format.
    
    Args:
        url: GitHub URL to normalize
        
    Returns:
        Normalized URL or original if not a GitHub URL
    """
    parsed = parse_github_url(url)
    if parsed:
        owner, repo = parsed
        return f"https://github.com/{owner}/{repo}"
    return url