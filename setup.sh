#!/bin/bash

# QUIC VPN Development Environment Setup Script
# This script sets up the complete development environment

set -e

echo "🚀 Setting up QUIC VPN Development Environment"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    print_status "Detected macOS"
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        print_error "Homebrew is required. Please install it first:"
        echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    
    # Install Go
    if ! command -v go &> /dev/null; then
        print_status "Installing Go..."
        brew install go
    else
        print_status "Go is already installed: $(go version)"
    fi
    
    # Install Docker
    if ! command -v docker &> /dev/null; then
        print_status "Installing Docker..."
        brew install --cask docker
    else
        print_status "Docker is already installed: $(docker --version)"
    fi
    
    # Install Rust
    if ! command -v rustup &> /dev/null; then
        print_status "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source ~/.cargo/env
    else
        print_status "Rust is already installed: $(rustup --version)"
    fi

# Check if running on Linux
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    print_status "Detected Linux"
    
    # Update package list
    if command -v apt-get &> /dev/null; then
        print_status "Updating package list..."
        sudo apt-get update
        
        # Install Go
        if ! command -v go &> /dev/null; then
            print_status "Installing Go..."
            sudo apt-get install -y golang-go
        else
            print_status "Go is already installed: $(go version)"
        fi
        
        # Install Docker
        if ! command -v docker &> /dev/null; then
            print_status "Installing Docker..."
            sudo apt-get install -y docker.io docker-compose
            sudo usermod -aG docker $USER
            print_warning "Please log out and back in for Docker group changes to take effect"
        else
            print_status "Docker is already installed: $(docker --version)"
        fi
        
        # Install Rust
        if ! command -v rustup &> /dev/null; then
            print_status "Installing Rust..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source ~/.cargo/env
        else
            print_status "Rust is already installed: $(rustup --version)"
        fi
        
    elif command -v yum &> /dev/null; then
        print_status "Using yum package manager..."
        # Add similar installation logic for yum-based systems
        print_warning "Please install Go, Docker, and Rust manually for your distribution"
    else
        print_warning "Unsupported Linux distribution. Please install dependencies manually."
    fi

else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

# Setup Go modules
print_status "Setting up Go modules..."
cd server
go mod tidy
cd ..

# Setup Rust targets for Android
print_status "Setting up Rust Android targets..."
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android
rustup target add i686-linux-android

# Create necessary directories
print_status "Creating project structure..."
mkdir -p android/app/src/main/res/layout
mkdir -p android/app/src/main/res/values
mkdir -p android/app/src/main/res/drawable

# Create basic resource files
print_status "Creating Android resource files..."

# Create strings.xml
cat > android/app/src/main/res/values/strings.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">QUIC VPN</string>
    <string name="connect">Connect</string>
    <string name="disconnect">Disconnect</string>
    <string name="server_address">Server Address</string>
    <string name="server_port">Server Port</string>
    <string name="status">Status</string>
    <string name="connected">Connected</string>
    <string name="disconnected">Disconnected</string>
</resources>
EOF

# Create basic layout
cat > android/app/src/main/res/layout/activity_main.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp">

    <EditText
        android:id="@+id/server_address"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="@string/server_address"
        android:inputType="text" />

    <EditText
        android:id="@+id/server_port"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="@string/server_port"
        android:inputType="number" />

    <Button
        android:id="@+id/connect_button"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginTop="16dp"
        android:text="@string/connect" />

    <TextView
        android:id="@+id/status_text"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginTop="16dp"
        android:gravity="center"
        android:text="@string/status"
        android:textSize="18sp" />

</LinearLayout>
EOF

# Create basic theme
cat > android/app/src/main/res/values/themes.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <style name="Theme.QuicVpn" parent="Theme.MaterialComponents.DayNight.DarkActionBar">
        <item name="colorPrimary">@color/purple_500</item>
        <item name="colorPrimaryVariant">@color/purple_700</item>
        <item name="colorOnPrimary">@color/white</item>
        <item name="colorSecondary">@color/teal_200</item>
        <item name="colorSecondaryVariant">@color/teal_700</item>
        <item name="colorOnSecondary">@color/black</item>
        <item name="android:statusBarColor">?attr/colorPrimaryVariant</item>
    </style>
</resources>
EOF

# Create colors.xml
cat > android/app/src/main/res/values/colors.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <color name="purple_200">#FFBB86FC</color>
    <color name="purple_500">#FF6200EE</color>
    <color name="purple_700">#FF3700B3</color>
    <color name="teal_200">#FF03DAC5</color>
    <color name="teal_700">#FF018786</color>
    <color name="black">#FF000000</color>
    <color name="white">#FFFFFFFF</color>
</resources>
EOF

# Make scripts executable
print_status "Making scripts executable..."
chmod +x scripts/*.sh

print_status "✅ Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. cd server && go run main.go  # Test server"
echo "2. cd android && ./gradlew assembleDebug  # Build Android app"
echo "3. Read docs/DEVELOPMENT_GUIDE.md for detailed instructions"
echo ""
echo "Happy coding! 🚀"
