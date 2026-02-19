#!/bin/bash

# Couch Potato Controller - Easy Installer
# Run this on your computer to set up the receiver server

set -e

echo "🛋️  Couch Potato Controller - Installer"
echo "========================================"
echo ""

# Check Python version
echo "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed!"
    echo "   Please install Python 3.7 or higher first."
    echo "   Visit: https://www.python.org/downloads/"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✅ Found Python $PYTHON_VERSION"
echo ""

# Check pip
echo "Checking pip installation..."
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed!"
    echo "   Please install pip first."
    exit 1
fi

echo "✅ pip3 is available"
echo ""

# Install dependencies
echo "Installing dependencies..."
echo "Running: pip3 install -r requirements.txt"
echo ""

pip3 install -r requirements.txt

echo ""
echo "✅ Installation complete!"
echo ""
echo "📋 Next Steps:"
echo "   1. Run the receiver server:"
echo "      python3 receiver_server.py"
echo ""
echo "   2. Note the IP address shown"
echo ""
echo "   3. On your iPhone (Pythonista):"
echo "      - Copy pythonista_server.py and couch_controller.html"
echo "      - Run pythonista_server.py"
echo "      - Open Safari → http://localhost:8080"
echo "      - Go to Settings → Enter computer IP → Connect"
echo ""
echo "📖 For detailed instructions, see SETUP_GUIDE.md"
echo ""
