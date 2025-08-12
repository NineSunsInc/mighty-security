# Dashboard Instructions

## Environment Setup
ALWAYS activate the virtual environment first using uv:
```bash
# From dashboard directory
cd ../..
uv sync
source .venv/bin/activate
cd src/dashboard
```

## Running the Dashboard
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