#!/data/data/com.termux/files/usr/bin/bash

# Termux Firewall & Anti-Malware Installation Script
echo "=================================================="
echo "🔒 Termux Firewall & Anti-Malware Installer 🔒"
echo "=================================================="

# Check if running in Termux
if [ ! -d "/data/data/com.termux" ]; then
    echo "❌ Error: This script must be run in Termux!"
    exit 1
fi

# Create directory for the app
APP_DIR="$HOME/termux-firewall"
DATA_DIR="$HOME/.termux-firewall"

echo "📁 Creating application directories..."
mkdir -p "$APP_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/logs"
mkdir -p "$DATA_DIR/scan_results"

# Update package repositories
echo "🔄 Updating package repositories..."
pkg update -y

# Install required packages
echo "📦 Installing required packages..."
pkg install -y python python-pip clang libffi openssl

# Check if installation was successful
if [ $? -ne 0 ]; then
    echo "❌ Failed to install required packages. Please check your internet connection and try again."
    exit 1
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install flask scapy psutil requests

# Copy files to the app directory
echo "📋 Copying application files..."
cd "$(dirname "$0")"

# Copy all Python files and scripts
cp *.py "$APP_DIR/"
cp *.sh "$APP_DIR/"
cp -r templates "$APP_DIR/"
cp -r static "$APP_DIR/"

# Make scripts executable
chmod +x "$APP_DIR/startup.sh"
chmod +x "$APP_DIR/install.sh" 
chmod +x "$APP_DIR/termux-firewall"

# Create symlink in Termux bin directory for easy access
echo "🔗 Creating command-line access..."
ln -sf "$APP_DIR/termux-firewall" "$PREFIX/bin/termux-firewall"

# Create Termux startup script
echo "⚙️ Setting up auto-start capability..."
BOOT_DIR="$HOME/.termux/boot"
mkdir -p "$BOOT_DIR"

cat > "$BOOT_DIR/start-firewall.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# Auto-start script for Termux Firewall

# Wait for system to fully boot
sleep 20

# Start the firewall
"$APP_DIR/startup.sh"
EOF

chmod +x "$BOOT_DIR/start-firewall.sh"

# Create desktop shortcut
echo "🔗 Creating desktop shortcut..."
cat > "$HOME/start-firewall.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
cd "$APP_DIR"
python main.py
EOF

chmod +x "$HOME/start-firewall.sh"

# Create shortcut if Termux:API is available
if command -v termux-shortcut &>/dev/null; then
    echo "🔗 Creating Termux shortcut..."
    termux-shortcut -n "Termux Firewall" -s "$HOME/start-firewall.sh"
fi

echo "✅ Installation completed successfully!"
echo ""
echo "You can now use the 'termux-firewall' command from anywhere in Termux!"
echo ""
echo "Common commands:"
echo "  termux-firewall start     # Start the firewall in background"
echo "  termux-firewall stop      # Stop the firewall"
echo "  termux-firewall status    # Check status"
echo "  termux-firewall scan      # Run a malware scan"
echo "  termux-firewall web       # Start the web interface"
echo "  termux-firewall cli       # Start interactive CLI"
echo "  termux-firewall help      # Show all available commands"
echo ""
echo "The firewall will automatically start when your device boots if you have"
echo "the Termux:Boot app installed from F-Droid or Google Play Store."
echo ""
echo "For web interface:"
echo "  Run 'termux-firewall web'"
echo "  Then visit: http://localhost:5000 in your browser"
echo ""
echo "🔒 Thank you for installing Termux Firewall & Anti-Malware! 🔒"
