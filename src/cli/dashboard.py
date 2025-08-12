#!/usr/bin/env python3
"""
Mighty MCP Security Dashboard CLI.

Command-line interface to start the web dashboard for GitHub repository scanning.
"""

import argparse
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Start the Mighty MCP Security Dashboard',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.cli.dashboard                    # Start on default port 5000
  python -m src.cli.dashboard --port 8080       # Start on port 8080
  python -m src.cli.dashboard --host 0.0.0.0    # Allow external connections
        """
    )
    
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind to (default: 127.0.0.1)'
    )
    
    parser.add_argument(
        '--port', 
        type=int,
        default=5000,
        help='Port to bind to (default: 5000)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    args = parser.parse_args()
    
    # Import and start the dashboard
    try:
        from src.dashboard.app import app
        
        print("🛡️ Starting Mighty MCP Security Dashboard")
        print(f"📍 URL: http://{args.host}:{args.port}")
        print("📖 Usage:")
        print("  1. Enter a GitHub repository URL")
        print("  2. Click 'Scan Repository'")
        print("  3. View results and security reports")
        print()
        print("🚨 Policy: HIGH and CRITICAL threats are automatically blocked")
        print("💾 Results are saved to SQLite database")
        print("🔄 Duplicate commits are automatically detected and reused")
        print()
        
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug
        )
        
    except ImportError as e:
        print(f"❌ Failed to import dashboard: {e}")
        print("Make sure you're running from the secure-toolings directory")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped")
    except Exception as e:
        print(f"❌ Failed to start dashboard: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()