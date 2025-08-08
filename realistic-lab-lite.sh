#!/bin/bash

# OSCP Realistic Lab LITE - Optimized for 2GB RAM Vultr Server
# 7 lightweight targets + 4 Kali machines

echo "================================================"
echo "   OSCP Lab LITE - Optimized for $12 Vultr"
echo "   7 Targets + 4 Kali (2GB RAM Friendly)"
echo "================================================"
echo ""

# Create optimized docker-compose for 2GB RAM
cat > /opt/oscp-labs/docker-compose-lite.yml << 'EOF'
version: '3.8'

networks:
  lab_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.0.0/24

services:
  # Kali machines (lightweight command)
  kali1:
    image: kalilinux/kali-rolling
    container_name: kali-user1
    hostname: kali-1
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.11
    command: /bin/bash
    mem_limit: 256m
    cpus: 0.25

  kali2:
    image: kalilinux/kali-rolling
    container_name: kali-user2
    hostname: kali-2
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.12
    command: /bin/bash
    mem_limit: 256m
    cpus: 0.25

  kali3:
    image: kalilinux/kali-rolling
    container_name: kali-user3
    hostname: kali-3
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.13
    command: /bin/bash
    mem_limit: 256m
    cpus: 0.25

  kali4:
    image: kalilinux/kali-rolling
    container_name: kali-user4
    hostname: kali-4
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.14
    command: /bin/bash
    mem_limit: 256m
    cpus: 0.25

  # Target 1: Multi-service Linux box
  target-linux:
    image: ubuntu:20.04
    container_name: target-linux
    hostname: linux-server
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.20
    command: /bin/bash -c "
      apt-get update && 
      apt-get install -y openssh-server vsftpd netcat &&
      echo 'root:toor' | chpasswd &&
      service ssh start &&
      service vsftpd start &&
      tail -f /dev/null"
    mem_limit: 128m

  # Target 2: Web server with multiple ports
  target-web:
    image: vulnerables/web-dvwa
    container_name: target-web
    hostname: web-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.30
    mem_limit: 256m

  # Target 3: Database server (MySQL)
  target-db:
    image: mysql:5.7
    container_name: target-db
    hostname: db-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.40
    environment:
      - MYSQL_ROOT_PASSWORD=password
      - MYSQL_DATABASE=testdb
    mem_limit: 256m

  # Target 4: Windows-like SMB
  target-smb:
    image: dperson/samba
    container_name: target-smb
    hostname: smb-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.50
    environment:
      - SHARE=public;/share;yes;no;yes;all;none
    mem_limit: 128m

  # Target 5: Tomcat server
  target-tomcat:
    image: tomcat:9-jdk8-openjdk-slim
    container_name: target-tomcat
    hostname: tomcat-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.60
    mem_limit: 256m

  # Target 6: Redis cache
  target-redis:
    image: redis:alpine
    container_name: target-redis
    hostname: redis-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.70
    mem_limit: 64m

  # Target 7: Simple HTTP server
  target-http:
    image: httpd:alpine
    container_name: target-http
    hostname: http-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.80
    mem_limit: 64m
EOF

echo "Stopping existing containers..."
cd /opt/oscp-labs
docker-compose down 2>/dev/null || true

echo "Starting optimized lab..."
docker-compose -f docker-compose-lite.yml up -d

echo ""
echo "================================================"
echo "   Optimized Lab Running!"
echo "================================================"
echo ""
echo "Targets available:"
echo "  172.16.0.20 - Linux (SSH, FTP)"
echo "  172.16.0.30 - DVWA Web App"
echo "  172.16.0.40 - MySQL Database"
echo "  172.16.0.50 - SMB Server"
echo "  172.16.0.60 - Tomcat"
echo "  172.16.0.70 - Redis"
echo "  172.16.0.80 - Apache"
echo ""
echo "This uses ~1.5GB RAM total - perfect for $12 Vultr!"