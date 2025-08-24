#!/bin/bash

# QUIC VPN Server Installation Script for Ubuntu
# This script installs and configures the QUIC VPN server on Ubuntu

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Check if running on Ubuntu
if ! grep -q "Ubuntu" /etc/os-release; then
    print_error "This script is designed for Ubuntu. Please use the appropriate script for your distribution."
    exit 1
fi

print_header "QUIC VPN Server Installation for Ubuntu VPS"

# Update system
print_status "Updating system packages..."
apt update && apt upgrade -y

# Install required packages
print_status "Installing required packages..."
apt install -y curl wget git build-essential software-properties-common apt-transport-https ca-certificates gnupg lsb-release

# Install Go
print_status "Installing Go..."
if ! command -v go &> /dev/null; then
    GO_VERSION="1.21.5"
    wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    rm go${GO_VERSION}.linux-amd64.tar.gz
    print_status "Go installed: $(go version)"
else
    print_status "Go is already installed: $(go version)"
fi

# Install Docker
print_status "Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    print_status "Docker installed: $(docker --version)"
else
    print_status "Docker is already installed: $(docker --version)"
fi

# Install Docker Compose
print_status "Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    print_status "Docker Compose installed: $(docker-compose --version)"
else
    print_status "Docker Compose is already installed: $(docker-compose --version)"
fi

# Create application directory
print_status "Creating application directory..."
mkdir -p /opt/quicvpn
cd /opt/quicvpn

# Download server files
print_status "Downloading server files..."
if [ -d "server" ]; then
    print_warning "Server directory already exists. Updating..."
    rm -rf server
fi

# Create server directory structure
mkdir -p server
cd server

# Create go.mod
cat > go.mod << 'EOF'
module quic-vpn-server

go 1.21

require (
	github.com/quic-go/quic-go v0.40.0
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
)

require (
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/quic-go/qtls-go1-20 v0.4.1 // indirect
	golang.org/x/crypto v0.4.0 // indirect
	golang.org/x/exp v0.0.0-20221205204356-47842c84f3db // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/tools v0.9.1 // indirect
)
EOF

# Create main.go (basic QUIC VPN server)
cat > main.go << 'EOF'
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
)

type VPNClient struct {
	conn     quic.Connection
	ip       net.IP
	lastSeen time.Time
}

type VPNServer struct {
	listener quic.Listener
	clients  map[string]*VPNClient
	mutex    sync.RWMutex
	ipPool   *IPPool
	tunIface *water.Interface
}

type IPPool struct {
	network *net.IPNet
	nextIP  net.IP
	mutex   sync.Mutex
}

func NewIPPool(network string) (*IPPool, error) {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, err
	}

	pool := &IPPool{
		network: ipNet,
		nextIP:  make(net.IP, len(ipNet.IP)),
	}
	copy(pool.nextIP, ipNet.IP)
	pool.nextIP[3] += 2 // Start from .2 (skip .1 for server)

	return pool, nil
}

func (p *IPPool) GetNextIP() net.IP {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	ip := make(net.IP, len(p.nextIP))
	copy(ip, p.nextIP)

	// Increment IP
	for i := len(p.nextIP) - 1; i >= 0; i-- {
		p.nextIP[i]++
		if p.nextIP[i] != 0 {
			break
		}
	}

	return ip
}

func (p *IPPool) ReleaseIP(ip net.IP) {
	// In a production environment, you'd want to track released IPs
	// For simplicity, we'll just log it
	log.Printf("Released IP: %s", ip.String())
}

func NewVPNServer() *VPNServer {
	return &VPNServer{
		clients: make(map[string]*VPNClient),
	}
}

func (s *VPNServer) setupTUN() error {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(config)
	if err != nil {
		return err
	}

	s.tunIface = iface

	// Configure TUN interface
	cmd := exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", iface.Name())
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("ip", "link", "set", iface.Name(), "up")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Enable IP forwarding
	cmd = exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Configure iptables
	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/24", "-o", "eth0", "-j", "MASQUERADE")
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: iptables configuration failed: %v", err)
	}

	log.Printf("TUN interface %s configured", iface.Name())
	return nil
}

func (s *VPNServer) generateTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"QUIC VPN Server"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// Write to files for debugging
	os.WriteFile("server.crt", certPEM, 0644)
	os.WriteFile("server.key", keyPEM, 0600)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:  []string{"quic-vpn"},
	}, nil
}

func (s *VPNServer) start() error {
	tlsConfig, err := s.generateTLSConfig()
	if err != nil {
		return err
	}

	if err := s.setupTUN(); err != nil {
		return err
	}

	addr := ":4433"
	listener, err := quic.ListenAddr(addr, tlsConfig, nil)
	if err != nil {
		return err
	}

	s.listener = listener
	log.Printf("QUIC VPN Server listening on %s", addr)

	// Start packet forwarding
	go s.forwardPackets()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *VPNServer) handleConnection(conn quic.Connection) {
	log.Printf("New connection from %s", conn.RemoteAddr())

	// Assign IP to client
	clientIP := s.ipPool.GetNextIP()
	client := &VPNClient{
		conn:     conn,
		ip:       clientIP,
		lastSeen: time.Now(),
	}

	s.mutex.Lock()
	s.clients[conn.RemoteAddr().String()] = client
	s.mutex.Unlock()

	// Send assigned IP to client
	stream, err := conn.OpenStream()
	if err != nil {
		log.Printf("Failed to open stream: %v", err)
		return
	}

	response := fmt.Sprintf("IP:%s", clientIP.String())
	stream.Write([]byte(response))
	stream.Close()

	log.Printf("Assigned IP %s to client %s", clientIP.String(), conn.RemoteAddr())

	// Keep connection alive
	for {
		time.Sleep(time.Second * 30)
		if time.Since(client.lastSeen) > time.Minute*5 {
			break
		}
	}

	// Cleanup
	s.mutex.Lock()
	delete(s.clients, conn.RemoteAddr().String())
	s.mutex.Unlock()

	s.ipPool.ReleaseIP(clientIP)
	conn.CloseWithError(0, "timeout")
	log.Printf("Client %s disconnected", conn.RemoteAddr())
}

func (s *VPNServer) forwardPackets() {
	buffer := make([]byte, 1500)
	for {
		n, err := s.tunIface.Read(buffer)
		if err != nil {
			log.Printf("Error reading from TUN: %v", err)
			continue
		}

		// Parse IP packet to find destination
		if n < 20 {
			continue
		}

		// Simple IP header parsing
		version := buffer[0] >> 4
		if version != 4 {
			continue
		}

		destIP := net.IP(buffer[16:20])
		s.mutex.RLock()
		for _, client := range s.clients {
			if client.ip.Equal(destIP) {
				// Send to client
				client.conn.SendDatagram(buffer[:n])
				client.lastSeen = time.Now()
				break
			}
		}
		s.mutex.RUnlock()
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Initialize IP pool
	ipPool, err := NewIPPool("10.0.0.0/24")
	if err != nil {
		log.Fatal("Failed to create IP pool:", err)
	}

	server := NewVPNServer()
	server.ipPool = ipPool

	log.Println("Starting QUIC VPN Server...")
	if err := server.start(); err != nil {
		log.Fatal("Server failed:", err)
	}
}
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o quicvpn-server .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache iptables iproute2

# Create non-root user
RUN addgroup -g 1001 -S quicvpn && \
    adduser -u 1001 -S quicvpn -G quicvpn

# Copy binary from builder
COPY --from=builder /app/quicvpn-server /usr/local/bin/

# Set ownership
RUN chown quicvpn:quicvpn /usr/local/bin/quicvpn-server

# Switch to non-root user
USER quicvpn

# Expose port
EXPOSE 4433

# Run the application
CMD ["quicvpn-server"]
EOF

# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  quicvpn-server:
    image: quicvpn-server:latest
    container_name: quicvpn-server
    restart: unless-stopped
    ports:
      - "4433:4433/udp"
    volumes:
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    devices:
      - /dev/net/tun
    environment:
      - VPN_NETWORK=10.0.0.0/24
      - VPN_SERVER_IP=10.0.0.1
      - SERVER_PORT=:4433
    networks:
      - quicvpn-network

networks:
  quicvpn-network:
    driver: bridge
EOF

# Create systemd service
cat > /etc/systemd/system/quicvpn.service << 'EOF'
[Unit]
Description=QUIC VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/quicvpn/server
ExecStart=/usr/local/go/bin/go run main.go
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create firewall configuration script
cat > /opt/quicvpn/firewall-setup.sh << 'EOF'
#!/bin/bash

# Firewall configuration for QUIC VPN Server
# This script configures UFW firewall rules

# Enable UFW
ufw --force enable

# Allow SSH (adjust port if needed)
ufw allow ssh

# Allow QUIC VPN port
ufw allow 4433/udp

# Allow HTTP/HTTPS (optional, for management)
ufw allow 80/tcp
ufw allow 443/tcp

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Configure iptables for NAT
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE

# Save iptables rules
iptables-save > /etc/iptables.rules

# Create iptables restore script
cat > /etc/network/if-up.d/iptables << 'EOF2'
#!/bin/bash
iptables-restore < /etc/iptables.rules
EOF2

chmod +x /etc/network/if-up.d/iptables

echo "Firewall configured successfully!"
EOF

chmod +x /opt/quicvpn/firewall-setup.sh

# Create management script
cat > /opt/quicvpn/manage.sh << 'EOF'
#!/bin/bash

# QUIC VPN Server Management Script

case "$1" in
    start)
        echo "Starting QUIC VPN Server..."
        systemctl start quicvpn
        ;;
    stop)
        echo "Stopping QUIC VPN Server..."
        systemctl stop quicvpn
        ;;
    restart)
        echo "Restarting QUIC VPN Server..."
        systemctl restart quicvpn
        ;;
    status)
        systemctl status quicvpn
        ;;
    logs)
        journalctl -u quicvpn -f
        ;;
    build)
        echo "Building Docker image..."
        cd /opt/quicvpn/server
        docker build -t quicvpn-server .
        ;;
    deploy)
        echo "Deploying with Docker Compose..."
        cd /opt/quicvpn/server
        docker-compose up -d
        ;;
    firewall)
        echo "Configuring firewall..."
        /opt/quicvpn/firewall-setup.sh
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|build|deploy|firewall}"
        exit 1
        ;;
esac
EOF

chmod +x /opt/quicvpn/manage.sh

# Create status check script
cat > /opt/quicvpn/status.sh << 'EOF'
#!/bin/bash

# QUIC VPN Server Status Check

echo "=== QUIC VPN Server Status ==="
echo ""

echo "Service Status:"
systemctl is-active quicvpn

echo ""
echo "Recent Logs:"
journalctl -u quicvpn --no-pager -n 20

echo ""
echo "Network Interfaces:"
ip addr show | grep -E "(tun|10\.0\.0)"

echo ""
echo "Active Connections:"
netstat -tuln | grep 4433

echo ""
echo "Docker Status:"
docker ps | grep quicvpn
EOF

chmod +x /opt/quicvpn/status.sh

# Install dependencies and build
print_status "Installing Go dependencies..."
cd /opt/quicvpn/server
export PATH=$PATH:/usr/local/go/bin
go mod tidy

# Build the server
print_status "Building QUIC VPN server..."
go build -o quicvpn-server main.go

# Create symbolic link
ln -sf /opt/quicvpn/server/quicvpn-server /usr/local/bin/quicvpn-server

# Set permissions
chmod +x /usr/local/bin/quicvpn-server

# Reload systemd
systemctl daemon-reload

# Configure firewall
print_status "Configuring firewall..."
/opt/quicvpn/firewall-setup.sh

print_header "Installation Complete!"

echo ""
echo "✅ QUIC VPN Server has been installed successfully!"
echo ""
echo "📁 Installation directory: /opt/quicvpn"
echo "🔧 Management script: /opt/quicvpn/manage.sh"
echo "📊 Status script: /opt/quicvpn/status.sh"
echo ""
echo "🚀 Quick Start Commands:"
echo "  Start server:     /opt/quicvpn/manage.sh start"
echo "  Check status:     /opt/quicvpn/status.sh"
echo "  View logs:        /opt/quicvpn/manage.sh logs"
echo "  Build Docker:     /opt/quicvpn/manage.sh build"
echo "  Deploy Docker:    /opt/quicvpn/manage.sh deploy"
echo ""
echo "🌐 Server will listen on port 4433/UDP"
echo "📱 Android clients can connect to: $(curl -s ifconfig.me):4433"
echo ""
echo "⚠️  Important: Make sure your VPS firewall allows UDP port 4433"
echo ""
echo "Happy VPN-ing! 🚀"
