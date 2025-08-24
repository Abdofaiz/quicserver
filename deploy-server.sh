#!/bin/bash

# QUIC VPN Server Deployment Script
# This script deploys the QUIC VPN server to a Linux server

set -e

# Configuration
SERVER_IP="your-server-ip"
SERVER_USER="root"
SERVER_PORT="4433"
DOCKER_IMAGE="quicvpn-server:latest"

echo "🚀 Deploying QUIC VPN Server to $SERVER_IP"

# Build Docker image
echo "📦 Building Docker image..."
cd server
docker build -t $DOCKER_IMAGE .

# Save image to tar file
echo "💾 Saving Docker image..."
docker save $DOCKER_IMAGE | gzip > quicvpn-server.tar.gz

# Copy to server
echo "📤 Copying files to server..."
scp quicvpn-server.tar.gz $SERVER_USER@$SERVER_IP:/tmp/
scp docker-compose.yml $SERVER_USER@$SERVER_IP:/tmp/

# Deploy on server
echo "🔧 Deploying on server..."
ssh $SERVER_USER@$SERVER_IP << 'EOF'
    cd /tmp
    
    # Load Docker image
    docker load < quicvpn-server.tar.gz
    
    # Create app directory
    mkdir -p /opt/quicvpn
    cd /opt/quicvpn
    
    # Copy docker-compose file
    cp /tmp/docker-compose.yml .
    
    # Start services
    docker-compose up -d
    
    # Cleanup
    rm /tmp/quicvpn-server.tar.gz
    rm /tmp/docker-compose.yml
    
    echo "✅ QUIC VPN Server deployed successfully!"
    echo "🌐 Server running on port $SERVER_PORT"
    echo "📱 Clients can connect to: $SERVER_IP:$SERVER_PORT"
EOF

echo "🎉 Deployment completed!"
echo "📱 Android clients can now connect to $SERVER_IP:$SERVER_PORT"
