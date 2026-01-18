#!/bin/bash
# Mobile AI Recon Agent - Quick Installation Script

echo "🚀 Installing Mobile AI Recon Agent..."
echo ""

# Check Python version
echo "📋 Checking Python version..."
python3 --version

if [ $? -ne 0 ]; then
    echo "❌ Python 3 not found. Please install Python 3.7+"
    exit 1
fi

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Create directories
echo ""
echo "📁 Creating directories..."
mkdir -p config results logs

# Copy config template
if [ ! -f "config/config.json" ]; then
    echo "⚙️ Creating config file..."
    cp config/config.example.json config/config.json
    echo "✅ Config created at config/config.json - Please edit with your settings"
else
    echo "⏭️ Config already exists, skipping..."
fi

# Make scripts executable
echo ""
echo "🔧 Setting permissions..."
chmod +x scripts/run_agent.sh
chmod +x scripts/recon_agent.py

echo ""
echo "✅ Installation complete!"
echo ""
echo "📝 Next steps:"
echo "1. Edit config/config.json with your settings"
echo "2. Run: python3 scripts/recon_agent.py -t example.com"
echo "3. Or start web interface: cd web-interface && python3 app.py"
echo ""
echo "📖 Read docs/MOBILE_SETUP_GUIDE.md for complete setup instructions"
echo ""
echo "Happy hunting! 🐛💰"
