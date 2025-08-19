# Dashboard Instructions

## Core Commandments
1. **NEVER take shortcuts** - The hard route is the only way to success
2. **This saves lives** - We build security tools that protect developers and users
3. **Quality over speed** - Better to do it right than do it fast
4. **DRY principle** - Reuse existing code, don't duplicate functionality
5. **Test failures matter** - NEVER skip failing tests, understand and fix them
6. **No destructive operations** - NEVER use `rm -rf` without explicit permission
7. **Mighty brand identity** - Use our colors (goldenYellow, vividSkyBlue, darkBlue, naturalLight)
8. **OSS excellence** - Document clearly, avoid jargon, build community trust

## Quick Start
```bash
# Setup (from dashboard directory)
cd ../..
uv sync
source .venv/bin/activate
cd src/dashboard

# Run backend
python3 app.py  # Port 8083

# Run frontend (separate terminal)
npm run dev     # Port 3002

# Build for production
npm run build
```

## Architecture
- **Backend**: FastAPI (app.py) - serves API and static files
- **Frontend**: React + Vite + Tailwind CSS
- **Database**: SQLite (analysis_cache.db)
- **Main entry**: mighty_mcp.py (all functionality through this CLI)

## Brand Guidelines
- **Colors**: goldenYellow (#FEDC25), vividSkyBlue (#178EB9), darkBlue (#127294)
- **Logo**: /static/mighty-icon.png and mighty-logo.png
- **Copyright**: "A Mighty OSS Project by Nine Suns, Inc. • mightynetwork.ai"

## Testing
```bash
# ALWAYS use python3 explicitly
python3 app.py
```

## Dependencies
All dependencies are managed via UV package manager in the root pyproject.toml. 
- DO NOT install packages directly with pip
- Use `uv add <package>` from the root directory if new dependencies are needed
- Use `uv sync` to install all dependencies

## Important Notes
- The project uses `uv` for dependency management
- Always source/activate the virtual environment before running
- Always use `python3` (not `python`) for all commands
- The dashboard runs on port 8080 by default
- Access at http://localhost:8080

## Testing the Dashboard
```bash
# Start the server
source ../../.venv/bin/activate
python3 app.py

# Then open browser to http://localhost:8080
```