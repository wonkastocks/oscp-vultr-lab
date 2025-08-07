#!/bin/bash

# Quick deployment script to copy to your Vultr server
# This creates a lighter version with 4 users but shared target machines to save resources

echo "================================================"
echo "   OSCP Multi-User Lab - Optimized Version"
echo "================================================"

# Create users
for i in {1..4}; do
    useradd -m -s /bin/bash oscpuser$i 2>/dev/null
    echo "oscpuser$i:OscpLab$i!2024" | chpasswd
    usermod -aG docker oscpuser$i
    echo "✓ Created oscpuser$i"
done

# Install Docker if needed
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | bash
fi

# Create optimized docker-compose
mkdir -p /opt/oscp-labs
cat > /opt/oscp-labs/docker-compose.yml << 'EOF'
version: '3.8'

networks:
  lab_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.0.0/24

services:
  # 4 Kali containers for users
  kali1:
    image: kalilinux/kali-rolling
    container_name: kali-user1
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.11
    command: /bin/bash
    volumes:
      - /home/oscpuser1/work:/root/work

  kali2:
    image: kalilinux/kali-rolling
    container_name: kali-user2
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.12
    command: /bin/bash
    volumes:
      - /home/oscpuser2/work:/root/work

  kali3:
    image: kalilinux/kali-rolling
    container_name: kali-user3
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.13
    command: /bin/bash
    volumes:
      - /home/oscpuser3/work:/root/work

  kali4:
    image: kalilinux/kali-rolling
    container_name: kali-user4
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.14
    command: /bin/bash
    volumes:
      - /home/oscpuser4/work:/root/work

  # Shared targets (all users can practice on these)
  target-linux:
    image: ubuntu:20.04
    container_name: target-linux
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.20
    command: /bin/bash

  target-web:
    image: vulnerables/web-dvwa
    container_name: target-web
    networks:
      lab_network:
        ipv4_address: 172.16.0.40

  target-smb:
    image: dperson/samba
    container_name: target-smb
    networks:
      lab_network:
        ipv4_address: 172.16.0.60
    environment:
      - SHARE=public;/share;yes;no;yes;all;none
EOF

# Start containers
cd /opt/oscp-labs
docker-compose up -d

# Create access scripts
for i in {1..4}; do
    cat > /home/oscpuser$i/start-lab.sh << EOF
#!/bin/bash
echo "OSCP Lab - User $i"
echo "Your Kali IP: 172.16.0.1$i"
echo "Targets: .20 (Linux), .40 (Web), .60 (SMB)"
docker exec -it kali-user$i bash
EOF
    chmod +x /home/oscpuser$i/start-lab.sh
    chown oscpuser$i:oscpuser$i /home/oscpuser$i/start-lab.sh
    mkdir -p /home/oscpuser$i/work
    chown -R oscpuser$i:oscpuser$i /home/oscpuser$i/work
done

echo ""
echo "✅ Setup Complete!"
echo ""
echo "Users can SSH in:"
for i in {1..4}; do
    echo "  ssh oscpuser$i@$(hostname -I | cut -d' ' -f1)"
    echo "  Password: OscpLab$i!2024"
done
echo ""
echo "Then run: ./start-lab.sh"