#!/bin/bash

# Flask MCP API Runner Script

echo "================================================"
echo "🚀 Flask Mighty MCP Server Security API"
echo "================================================"

# Check if .venv exists
if [ ! -d ".venv" ]; then
    echo "⚠️  Virtual environment not found. Running uv sync..."
    uv sync
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source .venv/bin/activate

# Check for .env file
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Creating from template..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "📝 Please edit .env and add your CEREBRAS_API_KEY if you want to use LLM analysis"
    fi
fi

# Load environment variables
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

# Set default port if not specified
export PORT=${PORT:-5000}

# Run the Flask app
echo "🚀 Starting Flask server on port $PORT..."
echo "📍 Server will be available at: http://localhost:$PORT"
echo ""
python app.py