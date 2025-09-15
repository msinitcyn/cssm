#!/bin/bash
set -e

echo "Building VSCode extension with latest scanner..."

# Activate venv
source venv/bin/activate

# Install pyinstaller if not already installed
pip install pyinstaller

# Generate temporary CLI entry point
cat > aws_scanner_cli.py << 'EOF'
#!/usr/bin/env python3
import sys
import os
src_dir = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_dir)
from aws_scanner.cli.main import main
if __name__ == "__main__":
    main()
EOF

# Build binary
echo "Building scanner binary..."
pyinstaller --onefile aws_scanner_cli.py --name aws-scanner-linux

# Copy to extension
echo "Copying binary to extension..."
mkdir -p vscode-extension/bin
cp dist/aws-scanner-linux vscode-extension/bin/
chmod +x vscode-extension/bin/aws-scanner-linux

# Build extension
echo "Building TypeScript extension..."
cd vscode-extension
npm install
npm run compile

# Cleanup
cd ..
rm aws_scanner_cli.py
rm -rf build/ dist/ *.spec

echo "Extension built successfully!"
echo "Press F5 in vscode-extension/ to test"