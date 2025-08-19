#!/bin/bash
set -e

echo "🚀 Building MCP Security Dashboard..."

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Build React app
echo "🔨 Building React app..."
npm run build

# Copy built files to the correct location
echo "📋 Organizing build files..."
mkdir -p static/dist
cp -r dist/* static/dist/

echo "✅ Build complete! React app is ready to serve."
echo "🌐 Start the dashboard with: python3 app.py"