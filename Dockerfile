FROM golang:1.21 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y git gcc

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o quicvpn-server .

# Final stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y iptables iproute2 && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false quicvpn

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
