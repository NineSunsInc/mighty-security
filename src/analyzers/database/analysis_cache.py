#!/usr/bin/env python3
"""
Analysis Cache Database
Stores scan results, git metadata, and prevents redundant analysis
"""

import hashlib
import json
import sqlite3
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


@dataclass
class RepositoryMetadata:
    """Repository metadata for caching"""
    repo_url: str
    repo_name: str
    latest_commit_sha: str
    latest_commit_date: str
    branch: str
    remote_url: str | None = None
    tags: list[str] = field(default_factory=list)
    release_version: str | None = None
    total_commits: int = 0
    contributors: list[str] = field(default_factory=list)

@dataclass
class AnalysisRun:
    """Single analysis run record"""
    run_id: str
    repo_url: str
    commit_sha: str
    branch: str
    scan_timestamp: str
    scan_type: str  # 'quick' or 'deep'
    llm_enabled: bool

    # Results
    threat_level: str
    threat_score: float
    confidence: float
    total_files: int
    total_threats: int
    critical_threats: int

    # Fingerprints
    sha512_fingerprint: str
    sha3_512_fingerprint: str
    merkle_root: str

    # Performance
    scan_duration_seconds: float
    tokens_used: int = 0

    # Full report stored as JSON
    full_report: dict[str, Any] = field(default_factory=dict)

class AnalysisCacheDB:
    """SQLite database for caching analysis results"""

    def __init__(self, db_path: str = "analysis_cache.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_database()

    def _init_database(self):
        """Initialize database schema"""
        cursor = self.conn.cursor()

        # Repository metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS repositories (
                repo_url TEXT PRIMARY KEY,
                repo_name TEXT NOT NULL,
                latest_commit_sha TEXT,
                latest_commit_date TEXT,
                branch TEXT,
                remote_url TEXT,
                release_version TEXT,
                total_commits INTEGER DEFAULT 0,
                tags TEXT,  -- JSON array
                contributors TEXT,  -- JSON array
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata_json TEXT  -- Full metadata as JSON
            )
        """)

        # Analysis runs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_runs (
                run_id TEXT PRIMARY KEY,
                repo_url TEXT NOT NULL,
                commit_sha TEXT NOT NULL,
                branch TEXT,
                scan_timestamp TIMESTAMP NOT NULL,
                scan_type TEXT NOT NULL,
                llm_enabled BOOLEAN DEFAULT 0,
                
                -- Results
                threat_level TEXT,
                threat_score REAL,
                confidence REAL,
                total_files INTEGER,
                total_threats INTEGER,
                critical_threats INTEGER,
                
                -- Fingerprints
                sha512_fingerprint TEXT,
                sha3_512_fingerprint TEXT,
                merkle_root TEXT,
                
                -- Performance
                scan_duration_seconds REAL,
                tokens_used INTEGER DEFAULT 0,
                
                -- Full report
                full_report TEXT,  -- JSON
                
                -- Indexes
                FOREIGN KEY (repo_url) REFERENCES repositories(repo_url),
                UNIQUE(repo_url, commit_sha, scan_type, llm_enabled)
            )
        """)

        # Individual threats table for querying
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                threat_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                attack_vector TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL,
                file_path TEXT,
                line_numbers TEXT,  -- JSON array
                description TEXT,
                evidence TEXT,  -- JSON
                
                FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id)
            )
        """)

        # File fingerprints table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_fingerprints (
                fingerprint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha512 TEXT NOT NULL,
                sha3_512 TEXT,
                file_size INTEGER,
                entropy REAL,
                
                FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id),
                UNIQUE(run_id, file_path)
            )
        """)

        # Create indexes for performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_runs_repo_commit 
            ON analysis_runs(repo_url, commit_sha)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_run 
            ON threats(run_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_severity 
            ON threats(severity)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_fingerprints_run 
            ON file_fingerprints(run_id)
        """)

        self.conn.commit()

    def get_repository_metadata(self, repo_path: Path) -> RepositoryMetadata | None:
        """Extract git metadata from repository"""
        try:
            # Get current commit SHA
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            commit_sha = result.stdout.strip() if result.returncode == 0 else None

            # Get current branch
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            branch = result.stdout.strip() if result.returncode == 0 else "main"

            # Get commit date
            result = subprocess.run(
                ["git", "show", "-s", "--format=%ci", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            commit_date = result.stdout.strip() if result.returncode == 0 else datetime.now().isoformat()

            # Get remote URL
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            remote_url = result.stdout.strip() if result.returncode == 0 else None

            # Get tags
            result = subprocess.run(
                ["git", "tag", "--points-at", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            tags = result.stdout.strip().split('\n') if result.returncode == 0 else []
            tags = [t for t in tags if t]  # Remove empty strings

            # Get latest release tag
            result = subprocess.run(
                ["git", "describe", "--tags", "--abbrev=0"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            release_version = result.stdout.strip() if result.returncode == 0 else None

            # Get total commit count
            result = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            total_commits = int(result.stdout.strip()) if result.returncode == 0 else 0

            # Get contributors (limit to top 10)
            result = subprocess.run(
                ["git", "shortlog", "-sn", "--all", "--no-merges"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            contributors = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n')[:10]:
                    if '\t' in line:
                        contributors.append(line.split('\t')[1])

            # Extract repo name from remote URL or path
            repo_name = repo_path.name
            if remote_url:
                import re
                match = re.search(r'github\.com[:/]([^/]+)/([^/.]+)', remote_url)
                if match:
                    repo_name = f"{match.group(1)}/{match.group(2)}"

            return RepositoryMetadata(
                repo_url=str(repo_path),
                repo_name=repo_name,
                latest_commit_sha=commit_sha or "unknown",
                latest_commit_date=commit_date,
                branch=branch,
                remote_url=remote_url,
                tags=tags,
                release_version=release_version,
                total_commits=total_commits,
                contributors=contributors
            )

        except Exception as e:
            print(f"Error extracting git metadata: {e}")
            return None

    def check_cached_analysis(
        self,
        repo_url: str,
        commit_sha: str | None = None,
        scan_type: str = "deep",
        llm_enabled: bool = False,
        max_age_hours: int = 24
    ) -> dict[str, Any] | None:
        """Check if we have a recent cached analysis for this commit"""

        cursor = self.conn.cursor()

        # If no commit SHA provided, get the latest one for this repo
        if not commit_sha:
            cursor.execute("""
                SELECT latest_commit_sha FROM repositories 
                WHERE repo_url = ?
            """, (repo_url,))
            row = cursor.fetchone()
            if row:
                commit_sha = row['latest_commit_sha']
            else:
                return None

        # Check for existing analysis
        cursor.execute("""
            SELECT * FROM analysis_runs 
            WHERE repo_url = ? 
            AND commit_sha = ? 
            AND scan_type = ?
            AND llm_enabled = ?
            AND datetime(scan_timestamp) > datetime('now', ? || ' hours')
            ORDER BY scan_timestamp DESC
            LIMIT 1
        """, (repo_url, commit_sha, scan_type, llm_enabled, f'-{max_age_hours}'))

        row = cursor.fetchone()
        if row:
            # Return the cached analysis
            return {
                'run_id': row['run_id'],
                'cached': True,
                'scan_timestamp': row['scan_timestamp'],
                'threat_level': row['threat_level'],
                'threat_score': row['threat_score'],
                'confidence': row['confidence'],
                'total_threats': row['total_threats'],
                'critical_threats': row['critical_threats'],
                'full_report': json.loads(row['full_report']) if row['full_report'] else None
            }

        return None

    def save_analysis(
        self,
        repo_path: Path,
        report: Any,  # SecurityReport object
        scan_type: str = "deep",
        llm_enabled: bool = False,
        scan_duration: float = 0.0,
        original_url: str = None  # Add parameter for original URL
    ) -> str:
        """Save analysis results to database"""

        # Generate run ID
        run_id = hashlib.sha256(
            f"{repo_path}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        # Get repository metadata
        metadata = self.get_repository_metadata(repo_path)
        
        # Override repo_url with original_url if provided (for GitHub clones)
        if metadata and original_url and 'github.com' in original_url:
            import re
            match = re.search(r'github\.com[/:]([^/]+)/([^/\.]+)', original_url)
            if match:
                metadata.repo_url = original_url
                metadata.repo_name = f"{match.group(1)}/{match.group(2)}"
        
        if not metadata:
            # Fallback for non-git directories
            # Use original_url if provided (for GitHub clones in temp directories)
            repo_url = original_url if original_url else str(repo_path)
            repo_name = repo_path.name
            
            # Extract GitHub repo name if it's a GitHub URL
            if original_url and 'github.com' in original_url:
                import re
                match = re.search(r'github\.com[/:]([^/]+)/([^/\.]+)', original_url)
                if match:
                    repo_name = f"{match.group(1)}/{match.group(2)}"
                    repo_url = original_url
            
            metadata = RepositoryMetadata(
                repo_url=repo_url,
                repo_name=repo_name,
                latest_commit_sha="no-git",
                latest_commit_date=datetime.now().isoformat(),
                branch="none"
            )

        cursor = self.conn.cursor()

        # Update or insert repository metadata
        cursor.execute("""
            INSERT OR REPLACE INTO repositories (
                repo_url, repo_name, latest_commit_sha, latest_commit_date,
                branch, remote_url, release_version, total_commits,
                tags, contributors, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            metadata.repo_url,
            metadata.repo_name,
            metadata.latest_commit_sha,
            metadata.latest_commit_date,
            metadata.branch,
            metadata.remote_url,
            metadata.release_version,
            metadata.total_commits,
            json.dumps(metadata.tags),
            json.dumps(metadata.contributors),
            json.dumps(asdict(metadata))
        ))

        # Count threats
        total_threats = len(report.threats_found) if hasattr(report, 'threats_found') else 0
        critical_threats = 0
        if hasattr(report, 'threats_found'):
            for threat in report.threats_found:
                severity = threat.severity
                if hasattr(severity, 'value') and severity.value == 'CRITICAL':
                    critical_threats += 1
                elif severity == 'CRITICAL':
                    critical_threats += 1

        # Calculate tokens used
        tokens_used = 0
        if hasattr(report, 'llm_analysis') and report.llm_analysis:
            tokens_used = report.llm_analysis.get('tokens_used', 0)

        # Convert report to dict for JSON storage
        if hasattr(report, '__dict__'):
            report_dict = report.__dict__.copy()
        else:
            report_dict = asdict(report)

        # Convert any remaining enums to strings
        def convert_enums(obj):
            if hasattr(obj, 'value'):
                return obj.value
            elif isinstance(obj, dict):
                return {k: convert_enums(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enums(item) for item in obj]
            else:
                return obj

        report_dict = convert_enums(report_dict)

        # Insert analysis run
        cursor.execute("""
            INSERT OR REPLACE INTO analysis_runs (
                run_id, repo_url, commit_sha, branch, scan_timestamp,
                scan_type, llm_enabled, threat_level, threat_score,
                confidence, total_files, total_threats, critical_threats,
                sha512_fingerprint, sha3_512_fingerprint, merkle_root,
                scan_duration_seconds, tokens_used, full_report
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            metadata.repo_url,
            metadata.latest_commit_sha,
            metadata.branch,
            datetime.now().isoformat(),
            scan_type,
            llm_enabled,
            report.threat_level,
            report.threat_score,
            report.confidence,
            report.total_files_scanned,
            total_threats,
            critical_threats,
            report.sha512_fingerprint,
            report.sha3_512_fingerprint,
            report.merkle_root,
            scan_duration,
            tokens_used,
            json.dumps(report_dict, default=str)
        ))

        # Insert individual threats for querying
        if hasattr(report, 'threats_found'):
            for threat in report.threats_found:
                cursor.execute("""
                    INSERT INTO threats (
                        run_id, attack_vector, severity, confidence,
                        file_path, line_numbers, description, evidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    run_id,
                    str(threat.attack_vector),
                    str(threat.severity),
                    threat.confidence,
                    threat.file_path,
                    json.dumps(threat.line_numbers) if hasattr(threat, 'line_numbers') else "[]",
                    threat.description,
                    json.dumps(threat.evidence) if hasattr(threat, 'evidence') else "{}"
                ))

        # Insert file fingerprints
        if hasattr(report, 'file_fingerprints'):
            for file_path, fingerprint in report.file_fingerprints.items():
                cursor.execute("""
                    INSERT OR REPLACE INTO file_fingerprints (
                        run_id, file_path, sha512, sha3_512, file_size, entropy
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    run_id,
                    file_path,
                    fingerprint.get('sha512'),
                    fingerprint.get('sha3_512'),
                    fingerprint.get('size', 0),
                    fingerprint.get('entropy', 0.0)
                ))

        self.conn.commit()
        return run_id

    def get_repository_history(self, repo_url: str) -> list[dict[str, Any]]:
        """Get analysis history for a repository"""
        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT run_id, commit_sha, branch, scan_timestamp, scan_type,
                   llm_enabled, threat_level, threat_score, total_threats,
                   critical_threats, scan_duration_seconds
            FROM analysis_runs
            WHERE repo_url = ?
            ORDER BY scan_timestamp DESC
            LIMIT 50
        """, (repo_url,))

        history = []
        for row in cursor.fetchall():
            history.append({
                'run_id': row['run_id'],
                'commit_sha': row['commit_sha'],
                'branch': row['branch'],
                'scan_timestamp': row['scan_timestamp'],
                'scan_type': row['scan_type'],
                'llm_enabled': bool(row['llm_enabled']),
                'threat_level': row['threat_level'],
                'threat_score': row['threat_score'],
                'total_threats': row['total_threats'],
                'critical_threats': row['critical_threats'],
                'scan_duration': row['scan_duration_seconds']
            })

        return history

    def get_threat_statistics(self, repo_url: str | None = None) -> dict[str, Any]:
        """Get threat statistics across all or specific repository"""
        cursor = self.conn.cursor()

        where_clause = "WHERE r.repo_url = ?" if repo_url else ""
        params = (repo_url,) if repo_url else ()

        # Get threat distribution
        cursor.execute(f"""
            SELECT t.severity, t.attack_vector, COUNT(*) as count
            FROM threats t
            JOIN analysis_runs r ON t.run_id = r.run_id
            {where_clause}
            GROUP BY t.severity, t.attack_vector
            ORDER BY count DESC
        """, params)

        threat_distribution = {}
        for row in cursor.fetchall():
            severity = row['severity']
            if severity not in threat_distribution:
                threat_distribution[severity] = {}
            threat_distribution[severity][row['attack_vector']] = row['count']

        # Get top vulnerable files
        cursor.execute(f"""
            SELECT t.file_path, COUNT(*) as threat_count,
                   GROUP_CONCAT(DISTINCT t.severity) as severities
            FROM threats t
            JOIN analysis_runs r ON t.run_id = r.run_id
            {where_clause}
            GROUP BY t.file_path
            ORDER BY threat_count DESC
            LIMIT 10
        """, params)

        top_vulnerable_files = []
        for row in cursor.fetchall():
            top_vulnerable_files.append({
                'file': row['file_path'],
                'threat_count': row['threat_count'],
                'severities': row['severities'].split(',') if row['severities'] else []
            })

        # Get summary stats
        cursor.execute(f"""
            SELECT 
                COUNT(DISTINCT r.repo_url) as total_repos,
                COUNT(DISTINCT r.run_id) as total_scans,
                AVG(r.threat_score) as avg_threat_score,
                MAX(r.threat_score) as max_threat_score,
                SUM(r.total_threats) as total_threats_found,
                SUM(r.critical_threats) as total_critical_threats
            FROM analysis_runs r
            {where_clause}
        """, params)

        stats = cursor.fetchone()

        return {
            'summary': {
                'total_repos': stats['total_repos'],
                'total_scans': stats['total_scans'],
                'avg_threat_score': stats['avg_threat_score'],
                'max_threat_score': stats['max_threat_score'],
                'total_threats': stats['total_threats_found'],
                'critical_threats': stats['total_critical_threats']
            },
            'threat_distribution': threat_distribution,
            'top_vulnerable_files': top_vulnerable_files
        }

    def cleanup_old_runs(self, days: int = 30):
        """Remove analysis runs older than specified days"""
        cursor = self.conn.cursor()

        cutoff_date = datetime.now() - timedelta(days=days)

        # Get runs to delete
        cursor.execute("""
            SELECT run_id FROM analysis_runs
            WHERE datetime(scan_timestamp) < ?
        """, (cutoff_date.isoformat(),))

        run_ids = [row['run_id'] for row in cursor.fetchall()]

        if run_ids:
            # Delete threats
            cursor.execute("""
                DELETE FROM threats 
                WHERE run_id IN ({})
            """.format(','.join('?' * len(run_ids))), run_ids)

            # Delete fingerprints
            cursor.execute("""
                DELETE FROM file_fingerprints
                WHERE run_id IN ({})
            """.format(','.join('?' * len(run_ids))), run_ids)

            # Delete runs
            cursor.execute("""
                DELETE FROM analysis_runs
                WHERE run_id IN ({})
            """.format(','.join('?' * len(run_ids))), run_ids)

            self.conn.commit()

        return len(run_ids)

    def export_to_json(self, run_id: str) -> dict[str, Any] | None:
        """Export a specific run to JSON format"""
        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT * FROM analysis_runs WHERE run_id = ?
        """, (run_id,))

        run = cursor.fetchone()
        if not run:
            return None

        # Get threats
        cursor.execute("""
            SELECT * FROM threats WHERE run_id = ?
        """, (run_id,))

        threats = []
        for row in cursor.fetchall():
            threats.append({
                'attack_vector': row['attack_vector'],
                'severity': row['severity'],
                'confidence': row['confidence'],
                'file_path': row['file_path'],
                'line_numbers': json.loads(row['line_numbers']) if row['line_numbers'] else [],
                'description': row['description'],
                'evidence': json.loads(row['evidence']) if row['evidence'] else []
            })

        # Get fingerprints
        cursor.execute("""
            SELECT * FROM file_fingerprints WHERE run_id = ?
        """, (run_id,))

        fingerprints = {}
        for row in cursor.fetchall():
            fingerprints[row['file_path']] = {
                'sha512': row['sha512'],
                'sha3_512': row['sha3_512'],
                'size': row['file_size'],
                'entropy': row['entropy']
            }

        return {
            'run_id': run['run_id'],
            'repo_url': run['repo_url'],
            'commit_sha': run['commit_sha'],
            'branch': run['branch'],
            'scan_timestamp': run['scan_timestamp'],
            'scan_type': run['scan_type'],
            'llm_enabled': bool(run['llm_enabled']),
            'results': {
                'threat_level': run['threat_level'],
                'threat_score': run['threat_score'],
                'confidence': run['confidence'],
                'total_files': run['total_files'],
                'total_threats': run['total_threats'],
                'critical_threats': run['critical_threats']
            },
            'threats': threats,
            'file_fingerprints': fingerprints,
            'full_report': json.loads(run['full_report']) if run['full_report'] else None
        }

    def store_analysis_run(self, repo_url: str, scan_type: str, threat_level: str,
                           threat_score: float, total_threats: int) -> str:
        """Store a new analysis run and return run_id"""
        from datetime import datetime

        run_id = str(uuid.uuid4())
        cursor = self.conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO analysis_runs (
                run_id, repo_url, commit_sha, branch, scan_timestamp, scan_type,
                llm_enabled, threat_level, threat_score, confidence, total_files,
                total_threats, critical_threats, sha512_fingerprint, sha3_512_fingerprint,
                merkle_root, scan_duration_seconds, tokens_used, full_report
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id, repo_url, 'latest', 'main', datetime.now().isoformat(), scan_type,
            False, threat_level, threat_score, 0.8, 0, total_threats, 0,
            '', '', '', 0, 0, '{}'
        ))

        self.conn.commit()
        return run_id

    def store_repository(self, repo_url: str, repo_name: str, latest_commit_sha: str,
                        scan_timestamp):
        """Store repository metadata"""
        cursor = self.conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO repositories (
                repo_url, repo_name, latest_commit_sha, latest_commit_date, 
                branch, last_updated
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            repo_url, repo_name, latest_commit_sha,
            scan_timestamp.isoformat() if hasattr(scan_timestamp, 'isoformat') else scan_timestamp,
            'main', scan_timestamp.isoformat() if hasattr(scan_timestamp, 'isoformat') else scan_timestamp
        ))

        self.conn.commit()

    def store_threat(self, run_id: str, attack_vector: str, severity: str,
                    confidence: float, file_path: str, line_numbers: list,
                    description: str, evidence: list):
        """Store individual threat details"""
        cursor = self.conn.cursor()

        cursor.execute("""
            INSERT INTO threats (
                run_id, attack_vector, severity, confidence,
                file_path, line_numbers, description, evidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id, attack_vector, severity, confidence,
            file_path, json.dumps(line_numbers) if line_numbers else '[]',
            description, json.dumps(evidence) if evidence else '[]'
        ))

        self.conn.commit()

    def close(self):
        """Close database connection"""
        self.conn.close()
