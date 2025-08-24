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
	"os/exec"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
)

const (
	SERVER_PORT   = ":4433"
	TUN_NAME      = "tun0"
	VPN_NETWORK   = "10.0.0.0/24"
	VPN_SERVER_IP = "10.0.0.1"
)

type VPNServer struct {
	listener   *quic.Listener
	tunDevice  *water.Interface
	clients    map[string]*VPNClient
	clientsMux sync.RWMutex
	ipPool     *IPPool
}

type VPNClient struct {
	id         string
	connection quic.Connection
	assignedIP net.IP
	lastSeen   time.Time
}

type IPPool struct {
	pool    []net.IP
	used    map[string]bool
	current int
	mutex   sync.Mutex
}

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Success    bool   `json:"success"`
	AssignedIP string `json:"assigned_ip"`
	ServerIP   string `json:"server_ip"`
	Message    string `json:"message"`
}

func NewIPPool() *IPPool {
	pool := &IPPool{
		pool: make([]net.IP, 0),
		used: make(map[string]bool),
	}

	// Generate IP pool from 10.0.0.2 to 10.0.0.254
	for i := 2; i <= 254; i++ {
		ip := net.IPv4(10, 0, 0, byte(i))
		pool.pool = append(pool.pool, ip)
	}

	return pool
}

func (p *IPPool) AllocateIP() net.IP {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for i := 0; i < len(p.pool); i++ {
		idx := (p.current + i) % len(p.pool)
		ip := p.pool[idx]
		ipStr := ip.String()

		if !p.used[ipStr] {
			p.used[ipStr] = true
			p.current = (idx + 1) % len(p.pool)
			return ip
		}
	}

	return nil // No available IPs
}

func (p *IPPool) ReleaseIP(ip net.IP) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	delete(p.used, ip.String())
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "QUIC VPN Server",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-vpn"},
	}
}

func setupTunDevice() (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: TUN_NAME,
		},
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, err
	}

	// Configure the TUN interface
	commands := [][]string{
		{"ip", "addr", "add", VPN_SERVER_IP + "/24", "dev", TUN_NAME},
		{"ip", "link", "set", "dev", TUN_NAME, "up"},
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", VPN_NETWORK, "-o", "eth0", "-j", "MASQUERADE"},
		{"echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			log.Printf("Warning: Command failed: %v", cmd)
		}
	}

	return iface, nil
}

func (s *VPNServer) handleConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "connection closed")

	log.Printf("New connection from %s", conn.RemoteAddr())

	// Handle authentication
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Failed to accept auth stream: %v", err)
		return
	}
	defer stream.Close()

	// Simple authentication (in production, use proper auth)
	clientIP := s.ipPool.AllocateIP()
	if clientIP == nil {
		log.Printf("No available IP addresses")
		return
	}

	client := &VPNClient{
		id:         conn.RemoteAddr().String(),
		connection: conn,
		assignedIP: clientIP,
		lastSeen:   time.Now(),
	}

	s.clientsMux.Lock()
	s.clients[client.id] = client
	s.clientsMux.Unlock()

	// Send IP assignment to client
	_, err = stream.Write([]byte(fmt.Sprintf("IP:%s", clientIP.String())))
	if err != nil {
		log.Printf("Failed to send IP assignment: %v", err)
		return
	}

	log.Printf("Assigned IP %s to client %s", clientIP.String(), client.id)

	// Handle data transfer using datagrams
	go s.handleDatagrams(conn, client)

	// Keep connection alive
	for {
		time.Sleep(time.Second * 30)
		if time.Since(client.lastSeen) > time.Minute*5 {
			break
		}
	}

	// Cleanup
	s.clientsMux.Lock()
	delete(s.clients, client.id)
	s.clientsMux.Unlock()
	s.ipPool.ReleaseIP(clientIP)

	log.Printf("Client %s disconnected", client.id)
}

func (s *VPNServer) handleDatagrams(conn quic.Connection, client *VPNClient) {
	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			if err != nil {
				break
			}
			log.Printf("Error receiving datagram: %v", err)
			continue
		}

		// Forward packet to TUN interface
		_, err = s.tunDevice.Write(data)
		if err != nil {
			log.Printf("Error writing to TUN: %v", err)
		}

		client.lastSeen = time.Now()
	}
}

func (s *VPNServer) tunReader() {
	buffer := make([]byte, 1500)

	for {
		n, err := s.tunDevice.Read(buffer)
		if err != nil {
			log.Printf("Error reading from TUN: %v", err)
			continue
		}

		packet := buffer[:n]

		// Parse destination IP from packet
		if len(packet) < 20 {
			continue
		}

		destIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])

		// Find client with matching IP
		s.clientsMux.RLock()
		var targetClient *VPNClient
		for _, client := range s.clients {
			if client.assignedIP.Equal(destIP) {
				targetClient = client
				break
			}
		}
		s.clientsMux.RUnlock()

		if targetClient != nil {
			// Send packet to client
			err = targetClient.connection.SendDatagram(packet)
			if err != nil {
				log.Printf("Error sending datagram to client: %v", err)
			}
		}
	}
}

func NewVPNServer() *VPNServer {
	return &VPNServer{
		clients: make(map[string]*VPNClient),
		ipPool:  NewIPPool(),
	}
}

func (s *VPNServer) Start() error {
	// Setup TUN device
	tunDevice, err := setupTunDevice()
	if err != nil {
		return fmt.Errorf("failed to setup TUN device: %v", err)
	}
	s.tunDevice = tunDevice

	// Generate TLS config
	tlsConfig := generateTLSConfig()

	// Create QUIC listener
	listener, err := quic.ListenAddr(SERVER_PORT, tlsConfig, &quic.Config{
		Allow0RTT: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %v", err)
	}
	s.listener = listener

	log.Printf("QUIC VPN Server started on %s", SERVER_PORT)
	log.Printf("VPN network: %s", VPN_NETWORK)
	log.Printf("Server IP: %s", VPN_SERVER_IP)

	// Start TUN reader
	go s.tunReader()

	// Accept connections
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func main() {
	server := NewVPNServer()

	if err := server.Start(); err != nil {
		log.Fatal(err)
	}
}
