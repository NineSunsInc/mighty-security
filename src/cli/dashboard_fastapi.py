#!/usr/bin/env python3
"""
Mighty MCP Security Dashboard CLI (FastAPI Version).

Command-line interface to start the FastAPI web dashboard for GitHub repository scanning.
"""

import argparse
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Start the Mighty MCP Security Dashboard (FastAPI)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.cli.dashboard_fastapi                    # Start on default port 8000
  python -m src.cli.dashboard_fastapi --port 8080       # Start on port 8080
  python -m src.cli.dashboard_fastapi --host 0.0.0.0    # Allow external connections
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
        default=8000,
        help='Port to bind to (default: 8000)'
    )

    parser.add_argument(
        '--reload',
        action='store_true',
        help='Enable auto-reload on code changes'
    )

    args = parser.parse_args()

    # Import and start the dashboard
    try:
        import uvicorn

        from src.dashboard.app import app

        print("🛡️ Starting Mighty MCP Security Dashboard (FastAPI)")
        print(f"📍 Dashboard URL: http://{args.host}:{args.port}")
        print(f"📖 API Docs: http://{args.host}:{args.port}/docs")
        print(f"🔧 Interactive API: http://{args.host}:{args.port}/redoc")
        print()
        print("📋 Features:")
        print("  • GitHub repository scanning with commit tracking")
        print("  • HIGH/CRITICAL threat blocking policy")
        print("  • SQLite storage for scan history")
        print("  • Duplicate scan prevention")
        print("  • Real-time vulnerability analysis")
        print()
        print("Press Ctrl+C to stop the server")

        uvicorn.run(
            "src.dashboard.app:app",
            host=args.host,
            port=args.port,
            reload=args.reload
        )

    except ImportError as e:
        print(f"❌ Failed to import required modules: {e}")
        print("\nMake sure FastAPI and uvicorn are installed:")
        print("  pip install fastapi uvicorn")
        print("  or")
        print("  uv pip install fastapi uvicorn")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped")
    except Exception as e:
        print(f"❌ Failed to start dashboard: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
