#!/bin/bash

# OSCP Lab Multi-User Setup Script for Vultr
# Supports 4 simultaneous users with isolated environments

set -e

echo "================================================"
echo "     OSCP Multi-User Lab Setup (4 Users)"
echo "================================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/7] Creating user accounts...${NC}"

# Create 4 user accounts
for i in {1..4}; do
    username="oscpuser$i"
    password="OscpLab$i!2024"
    
    # Check if user exists
    if id "$username" &>/dev/null; then
        echo "User $username already exists, skipping..."
    else
        # Create user with home directory
        useradd -m -s /bin/bash "$username"
        echo "$username:$password" | chpasswd
        
        # Add to docker group
        usermod -aG docker "$username"
        
        echo -e "${GREEN}✓ Created user: $username (password: $password)${NC}"
    fi
done

echo -e "${YELLOW}[2/7] Setting up Docker environment...${NC}"

# Ensure Docker is installed
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | bash
    systemctl enable docker
    systemctl start docker
fi

# Ensure Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    apt update
    apt install -y docker-compose
fi

echo -e "${YELLOW}[3/7] Creating isolated lab environments...${NC}"

# Create base directory for labs
mkdir -p /opt/oscp-labs

# Create docker-compose configuration for 4 isolated labs
cat > /opt/oscp-labs/docker-compose.yml << 'EOF'
version: '3.8'

networks:
  lab1_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.1.0/24
  
  lab2_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.2.0/24
  
  lab3_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.3.0/24
  
  lab4_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.4.0/24

services:
  # Lab 1 - User 1
  kali1:
    image: kalilinux/kali-rolling
    container_name: oscp-kali-user1
    hostname: kali-user1
    tty: true
    stdin_open: true
    networks:
      lab1_network:
        ipv4_address: 172.16.1.10
    command: /bin/bash
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    volumes:
      - /home/oscpuser1/work:/root/work
  
  target1-linux:
    image: ubuntu:20.04
    container_name: oscp-target-linux-user1
    hostname: target-linux-1
    tty: true
    stdin_open: true
    networks:
      lab1_network:
        ipv4_address: 172.16.1.20
    command: /bin/bash
  
  target1-web:
    image: vulnerables/web-dvwa
    container_name: oscp-web-user1
    hostname: web-server-1
    networks:
      lab1_network:
        ipv4_address: 172.16.1.40
  
  # Lab 2 - User 2
  kali2:
    image: kalilinux/kali-rolling
    container_name: oscp-kali-user2
    hostname: kali-user2
    tty: true
    stdin_open: true
    networks:
      lab2_network:
        ipv4_address: 172.16.2.10
    command: /bin/bash
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    volumes:
      - /home/oscpuser2/work:/root/work
  
  target2-linux:
    image: ubuntu:20.04
    container_name: oscp-target-linux-user2
    hostname: target-linux-2
    tty: true
    stdin_open: true
    networks:
      lab2_network:
        ipv4_address: 172.16.2.20
    command: /bin/bash
  
  target2-web:
    image: vulnerables/web-dvwa
    container_name: oscp-web-user2
    hostname: web-server-2
    networks:
      lab2_network:
        ipv4_address: 172.16.2.40
  
  # Lab 3 - User 3
  kali3:
    image: kalilinux/kali-rolling
    container_name: oscp-kali-user3
    hostname: kali-user3
    tty: true
    stdin_open: true
    networks:
      lab3_network:
        ipv4_address: 172.16.3.10
    command: /bin/bash
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    volumes:
      - /home/oscpuser3/work:/root/work
  
  target3-linux:
    image: ubuntu:20.04
    container_name: oscp-target-linux-user3
    hostname: target-linux-3
    tty: true
    stdin_open: true
    networks:
      lab3_network:
        ipv4_address: 172.16.3.20
    command: /bin/bash
  
  target3-web:
    image: vulnerables/web-dvwa
    container_name: oscp-web-user3
    hostname: web-server-3
    networks:
      lab3_network:
        ipv4_address: 172.16.3.40
  
  # Lab 4 - User 4
  kali4:
    image: kalilinux/kali-rolling
    container_name: oscp-kali-user4
    hostname: kali-user4
    tty: true
    stdin_open: true
    networks:
      lab4_network:
        ipv4_address: 172.16.4.10
    command: /bin/bash
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    volumes:
      - /home/oscpuser4/work:/root/work
  
  target4-linux:
    image: ubuntu:20.04
    container_name: oscp-target-linux-user4
    hostname: target-linux-4
    tty: true
    stdin_open: true
    networks:
      lab4_network:
        ipv4_address: 172.16.4.20
    command: /bin/bash
  
  target4-web:
    image: vulnerables/web-dvwa
    container_name: oscp-web-user4
    hostname: web-server-4
    networks:
      lab4_network:
        ipv4_address: 172.16.4.40
EOF

echo -e "${YELLOW}[4/7] Starting Docker containers...${NC}"

cd /opt/oscp-labs
docker-compose pull
docker-compose up -d

# Wait for containers to start
sleep 15

echo -e "${YELLOW}[5/7] Creating helper scripts for each user...${NC}"

# Create access scripts for each user
for i in {1..4}; do
    username="oscpuser$i"
    script_path="/home/$username/start-lab.sh"
    
    cat > "$script_path" << EOF
#!/bin/bash
echo "================================================"
echo "     OSCP Lab - User $i"
echo "================================================"
echo ""
echo "Your isolated lab network: 172.16.$i.0/24"
echo ""
echo "Targets:"
echo "  • Linux Target: 172.16.$i.20"
echo "  • Web Server:   172.16.$i.40"
echo ""
echo "Accessing your Kali machine..."
echo "================================================"
echo ""
docker exec -it oscp-kali-user$i bash
EOF
    
    chmod +x "$script_path"
    chown "$username:$username" "$script_path"
    
    # Create work directory
    mkdir -p "/home/$username/work"
    chown -R "$username:$username" "/home/$username/work"
done

echo -e "${YELLOW}[6/7] Installing tmux for session management...${NC}"
apt install -y tmux

echo -e "${YELLOW}[7/7] Creating management script...${NC}"

# Create admin management script
cat > /root/manage-labs.sh << 'EOF'
#!/bin/bash

echo "OSCP Multi-User Lab Management"
echo "=============================="
echo ""
echo "1. View all containers status"
echo "2. Restart all labs"
echo "3. Stop all labs"
echo "4. View user connections"
echo "5. Exit"
echo ""
read -p "Choose option: " choice

case $choice in
    1)
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Networks}}"
        ;;
    2)
        docker-compose -f /opt/oscp-labs/docker-compose.yml restart
        echo "All labs restarted"
        ;;
    3)
        docker-compose -f /opt/oscp-labs/docker-compose.yml stop
        echo "All labs stopped"
        ;;
    4)
        who
        ;;
    5)
        exit
        ;;
    *)
        echo "Invalid option"
        ;;
esac
EOF

chmod +x /root/manage-labs.sh

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}     ✅ Multi-User Setup Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}User Credentials:${NC}"
echo "─────────────────────────────────────"
for i in {1..4}; do
    echo -e "User $i: ${GREEN}oscpuser$i${NC} / Password: ${GREEN}OscpLab$i!2024${NC}"
    echo "  Lab Network: 172.16.$i.0/24"
    echo "  Kali Container: oscp-kali-user$i"
    echo ""
done

echo -e "${YELLOW}How to Connect:${NC}"
echo "─────────────────────────────────────"
echo "Each user should SSH in:"
echo -e "${GREEN}ssh oscpuser1@155.138.197.128${NC}"
echo ""
echo "Then run their lab:"
echo -e "${GREEN}./start-lab.sh${NC}"
echo ""

echo -e "${YELLOW}Container Status:${NC}"
echo "─────────────────────────────────────"
docker ps --format "table {{.Names}}\t{{.Status}}"

echo ""
echo -e "${YELLOW}Management:${NC}"
echo "─────────────────────────────────────"
echo "Admin can manage labs with: ${GREEN}/root/manage-labs.sh${NC}"
echo ""
echo -e "${RED}⚠️  IMPORTANT: Remember to destroy the server when done!${NC}"
echo "================================================"