#!/usr/bin/env python3
"""
GitHub Metadata Extractor
Pre-fetches repository information without cloning
"""

import re
import json
import subprocess
from typing import Dict, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime
import requests
from dataclasses import dataclass

@dataclass
class GitHubRepoInfo:
    """GitHub repository metadata"""
    owner: str
    repo_name: str
    full_name: str
    default_branch: str
    latest_commit_sha: str
    latest_commit_date: str
    latest_commit_message: str
    latest_commit_author: str
    size_kb: int
    language: str
    languages: Dict[str, int]
    stars: int
    forks: int
    open_issues: int
    created_at: str
    updated_at: str
    has_releases: bool
    latest_release: Optional[str]
    topics: list
    is_fork: bool
    is_archived: bool
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'owner': self.owner,
            'repo_name': self.repo_name,
            'full_name': self.full_name,
            'default_branch': self.default_branch,
            'latest_commit': {
                'sha': self.latest_commit_sha,
                'date': self.latest_commit_date,
                'message': self.latest_commit_message,
                'author': self.latest_commit_author
            },
            'size_kb': self.size_kb,
            'language': self.language,
            'languages': self.languages,
            'stats': {
                'stars': self.stars,
                'forks': self.forks,
                'open_issues': self.open_issues
            },
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'has_releases': self.has_releases,
            'latest_release': self.latest_release,
            'topics': self.topics,
            'is_fork': self.is_fork,
            'is_archived': self.is_archived,
            'description': self.description
        }

class GitHubMetadataExtractor:
    """Extract GitHub repository metadata without cloning"""
    
    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize with optional GitHub token for API access
        Token increases rate limits from 60 to 5000 requests per hour
        """
        self.github_token = github_token
        self.api_base = "https://api.github.com"
        self.headers = {
            'Accept': 'application/vnd.github.v3+json'
        }
        if github_token:
            self.headers['Authorization'] = f'token {github_token}'
    
    def extract_from_url(self, repo_url: str) -> Optional[GitHubRepoInfo]:
        """Extract metadata from GitHub URL without cloning"""
        
        # Parse GitHub URL
        owner, repo = self._parse_github_url(repo_url)
        if not owner or not repo:
            return None
        
        try:
            # Get repository info
            repo_data = self._get_repo_info(owner, repo)
            if not repo_data:
                return None
            
            # Get latest commit info
            commit_data = self._get_latest_commit(owner, repo, repo_data.get('default_branch', 'main'))
            
            # Get languages
            languages = self._get_languages(owner, repo)
            
            # Get latest release
            latest_release = self._get_latest_release(owner, repo)
            
            # Build metadata object
            return GitHubRepoInfo(
                owner=owner,
                repo_name=repo,
                full_name=f"{owner}/{repo}",
                default_branch=repo_data.get('default_branch', 'main'),
                latest_commit_sha=commit_data.get('sha', ''),
                latest_commit_date=commit_data.get('date', ''),
                latest_commit_message=commit_data.get('message', ''),
                latest_commit_author=commit_data.get('author', ''),
                size_kb=repo_data.get('size', 0),
                language=repo_data.get('language', ''),
                languages=languages,
                stars=repo_data.get('stargazers_count', 0),
                forks=repo_data.get('forks_count', 0),
                open_issues=repo_data.get('open_issues_count', 0),
                created_at=repo_data.get('created_at', ''),
                updated_at=repo_data.get('updated_at', ''),
                has_releases=repo_data.get('has_releases', False),
                latest_release=latest_release,
                topics=repo_data.get('topics', []),
                is_fork=repo_data.get('fork', False),
                is_archived=repo_data.get('archived', False),
                description=repo_data.get('description', '')
            )
            
        except Exception as e:
            print(f"Error extracting GitHub metadata: {e}")
            return None
    
    def check_using_git_ls_remote(self, repo_url: str) -> Optional[Dict[str, str]]:
        """
        Quick check using git ls-remote (doesn't require API token)
        Returns latest commit SHA and refs without cloning
        """
        try:
            # Use git ls-remote to get refs without cloning
            result = subprocess.run(
                ["git", "ls-remote", repo_url, "HEAD"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                # Parse the output (format: SHA\tHEAD)
                sha = result.stdout.strip().split('\t')[0]
                
                # Get all refs for more info
                result_all = subprocess.run(
                    ["git", "ls-remote", "--heads", "--tags", repo_url],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                refs = {}
                branches = []
                tags = []
                
                if result_all.returncode == 0:
                    for line in result_all.stdout.strip().split('\n'):
                        if line:
                            sha_ref, ref = line.split('\t')
                            refs[ref] = sha_ref
                            
                            if ref.startswith('refs/heads/'):
                                branches.append(ref.replace('refs/heads/', ''))
                            elif ref.startswith('refs/tags/'):
                                tags.append(ref.replace('refs/tags/', ''))
                
                return {
                    'latest_commit_sha': sha,
                    'branches': branches,
                    'tags': tags,
                    'refs': refs
                }
                
        except Exception as e:
            print(f"git ls-remote failed: {e}")
        
        return None
    
    def _parse_github_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse GitHub URL to extract owner and repo name"""
        patterns = [
            r'github\.com[:/]([^/]+)/([^/.]+)',  # HTTPS or SSH
            r'github\.com/([^/]+)/([^/.]+)',      # Plain HTTPS
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                owner = match.group(1)
                repo = match.group(2).replace('.git', '')
                return owner, repo
        
        return None, None
    
    def _get_repo_info(self, owner: str, repo: str) -> Optional[Dict]:
        """Get repository information from GitHub API"""
        url = f"{self.api_base}/repos/{owner}/{repo}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Failed to get repo info: {e}")
        
        return None
    
    def _get_latest_commit(self, owner: str, repo: str, branch: str) -> Dict[str, str]:
        """Get latest commit information"""
        url = f"{self.api_base}/repos/{owner}/{repo}/commits/{branch}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'sha': data.get('sha', ''),
                    'date': data.get('commit', {}).get('committer', {}).get('date', ''),
                    'message': data.get('commit', {}).get('message', ''),
                    'author': data.get('commit', {}).get('author', {}).get('name', '')
                }
        except Exception:
            pass
        
        return {}
    
    def _get_languages(self, owner: str, repo: str) -> Dict[str, int]:
        """Get repository languages"""
        url = f"{self.api_base}/repos/{owner}/{repo}/languages"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        
        return {}
    
    def _get_latest_release(self, owner: str, repo: str) -> Optional[str]:
        """Get latest release tag"""
        url = f"{self.api_base}/repos/{owner}/{repo}/releases/latest"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('tag_name')
        except Exception:
            pass
        
        return None

class CacheAwareAnalyzer:
    """Analyzer that checks cache before cloning"""
    
    def __init__(self, cache_db):
        self.cache_db = cache_db
        self.metadata_extractor = GitHubMetadataExtractor()
    
    def should_analyze(self, repo_url: str, force: bool = False) -> Tuple[bool, Optional[Dict]]:
        """
        Check if repository needs analysis
        Returns (should_analyze, metadata)
        """
        if force:
            return True, None
        
        # First, get quick metadata without cloning
        print(f"Checking repository metadata for {repo_url}...")
        
        # Try git ls-remote first (faster, no API limits)
        git_info = self.metadata_extractor.check_using_git_ls_remote(repo_url)
        
        if git_info:
            latest_sha = git_info['latest_commit_sha']
            
            # Check if we have this SHA in cache
            cached = self.cache_db.check_cached_analysis(
                repo_url=repo_url,
                commit_sha=latest_sha,
                max_age_hours=24
            )
            
            if cached:
                print(f"✓ Found cached analysis for commit {latest_sha[:8]}")
                print(f"  Last scanned: {cached['scan_timestamp']}")
                print(f"  Threat level: {cached['threat_level']}")
                print(f"  Use --no-cache to force rescan")
                return False, {
                    'cached': True,
                    'commit_sha': latest_sha,
                    'scan_timestamp': cached['scan_timestamp'],
                    'threat_level': cached['threat_level'],
                    'threat_score': cached['threat_score']
                }
            else:
                print(f"✗ No cached analysis for commit {latest_sha[:8]}")
                return True, {
                    'cached': False,
                    'commit_sha': latest_sha,
                    'branches': git_info.get('branches', []),
                    'tags': git_info.get('tags', [])
                }
        
        # Fallback to API if git ls-remote fails
        github_info = self.metadata_extractor.extract_from_url(repo_url)
        if github_info:
            # Check cache with API metadata
            cached = self.cache_db.check_cached_analysis(
                repo_url=repo_url,
                commit_sha=github_info.latest_commit_sha,
                max_age_hours=24
            )
            
            if cached:
                print(f"✓ Found cached analysis")
                return False, {
                    'cached': True,
                    **github_info.to_dict()
                }
            else:
                print(f"✗ No cached analysis, proceeding with scan")
                return True, {
                    'cached': False,
                    **github_info.to_dict()
                }
        
        # If we can't get metadata, proceed with analysis
        return True, None