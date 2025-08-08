#!/bin/bash

# OSCP Realistic Lab Setup - 10 Target Machines
# Creates a diverse environment with various vulnerable services

echo "================================================"
echo "   OSCP Realistic Lab Environment Setup"
echo "   10 Targets with Multiple Services"
echo "================================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}[1/5] Creating advanced Docker Compose configuration...${NC}"

# Create the advanced lab setup
mkdir -p /opt/oscp-realistic-lab
cd /opt/oscp-realistic-lab

# Create docker-compose.yml with 10 diverse targets
cat > docker-compose.yml << 'EOF'
version: '3.8'

networks:
  lab_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.0.0/24

services:
  # Kali machines for 4 users
  kali1:
    image: kalilinux/kali-rolling
    container_name: kali-user1
    hostname: kali-attack-1
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
    hostname: kali-attack-2
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
    hostname: kali-attack-3
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
    hostname: kali-attack-4
    tty: true
    stdin_open: true
    networks:
      lab_network:
        ipv4_address: 172.16.0.14
    command: /bin/bash
    volumes:
      - /home/oscpuser4/work:/root/work

  # Target 1: Linux SSH Server (Ubuntu)
  target-ssh:
    image: rastasheep/ubuntu-sshd:18.04
    container_name: target-ssh-server
    hostname: ssh-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.20
    environment:
      - ROOT_PASSWORD=toor

  # Target 2: Web Application (DVWA)
  target-web-dvwa:
    image: vulnerables/web-dvwa
    container_name: target-web-dvwa
    hostname: dvwa-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.30
    ports:
      - "8080:80"

  # Target 3: FTP Server
  target-ftp:
    image: garethflowers/ftp-server
    container_name: target-ftp-server
    hostname: ftp-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.40
    environment:
      - FTP_USER=anonymous
      - FTP_PASS=anonymous

  # Target 4: MySQL Database
  target-mysql:
    image: mysql:5.7
    container_name: target-mysql-db
    hostname: mysql-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.50
    environment:
      - MYSQL_ROOT_PASSWORD=password123
      - MYSQL_DATABASE=testdb
      - MYSQL_USER=dbuser
      - MYSQL_PASSWORD=dbpass

  # Target 5: SMB/Samba Server
  target-smb:
    image: dperson/samba
    container_name: target-smb-server
    hostname: smb-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.60
    environment:
      - SHARE=public;/share;yes;no;yes;all;none
      - USER=smbuser;password123
    volumes:
      - /tmp/samba:/share

  # Target 6: Apache Tomcat
  target-tomcat:
    image: tomcat:8.5.35
    container_name: target-tomcat
    hostname: tomcat-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.70
    environment:
      - TOMCAT_USERNAME=admin
      - TOMCAT_PASSWORD=admin

  # Target 7: Redis Database
  target-redis:
    image: redis:5.0
    container_name: target-redis
    hostname: redis-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.80
    command: redis-server --requirepass redis123

  # Target 8: PostgreSQL Database
  target-postgres:
    image: postgres:11
    container_name: target-postgres
    hostname: postgres-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.90
    environment:
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_USER=postgres
      - POSTGRES_DB=testdb

  # Target 9: WordPress Site
  target-wordpress:
    image: wordpress:5.2.2
    container_name: target-wordpress
    hostname: wordpress-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.100
    environment:
      - WORDPRESS_DB_HOST=172.16.0.50
      - WORDPRESS_DB_USER=dbuser
      - WORDPRESS_DB_PASSWORD=dbpass
      - WORDPRESS_DB_NAME=wordpress

  # Target 10: Vulnerable WebGoat Application
  target-webgoat:
    image: webgoat/webgoat-8.0
    container_name: target-webgoat
    hostname: webgoat-server
    networks:
      lab_network:
        ipv4_address: 172.16.0.110
    environment:
      - WEBGOAT_HOST=0.0.0.0
      - WEBGOAT_PORT=8080
EOF

echo -e "${YELLOW}[2/5] Creating initialization script for targets...${NC}"

# Create initialization script to set up services
cat > init-targets.sh << 'EOF'
#!/bin/bash

echo "Initializing target services..."

# Initialize SMB share with files
docker exec target-smb-server sh -c "
mkdir -p /share
echo 'admin:password123' > /share/credentials.txt
echo 'Secret company data' > /share/confidential.doc
chmod 777 /share/*
"

# Set up Tomcat manager
docker exec target-tomcat sh -c "
cat > /usr/local/tomcat/conf/tomcat-users.xml << 'TOMCAT'
<?xml version='1.0' encoding='UTF-8'?>
<tomcat-users>
  <role rolename='manager-gui'/>
  <role rolename='admin-gui'/>
  <user username='admin' password='admin' roles='manager-gui,admin-gui'/>
  <user username='tomcat' password='s3cret' roles='manager-gui'/>
</tomcat-users>
TOMCAT
"

# Create some data in MySQL
docker exec target-mysql-db sh -c "
mysql -uroot -ppassword123 -e 'CREATE DATABASE IF NOT EXISTS company;'
mysql -uroot -ppassword123 -e 'USE company; CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50));'
mysql -uroot -ppassword123 -e \"USE company; INSERT INTO users VALUES (1, 'admin', 'admin123'), (2, 'user', 'password');\"
"

# Set up FTP with files
docker exec target-ftp-server sh -c "
echo 'Welcome to FTP server' > /home/ftpuser/welcome.txt
"

echo "Target initialization complete!"
EOF

chmod +x init-targets.sh

echo -e "${YELLOW}[3/5] Starting all containers...${NC}"

# Start containers
docker-compose up -d

# Wait for containers to start
echo "Waiting for containers to initialize..."
sleep 20

# Run initialization
./init-targets.sh

echo -e "${YELLOW}[4/5] Creating target information file...${NC}"

cat > TARGET_INFORMATION.md << 'EOF'
# OSCP Realistic Lab - Target Information

## Network Map (172.16.0.0/24)

### Attack Machines (Kali)
- 172.16.0.11 - Kali User 1
- 172.16.0.12 - Kali User 2
- 172.16.0.13 - Kali User 3
- 172.16.0.14 - Kali User 4

### Target Machines (10 Targets)

| IP | Hostname | Services | Default Creds | Notes |
|----|----------|----------|---------------|-------|
| 172.16.0.20 | ssh-server | SSH (22) | root:toor | Ubuntu 18.04 |
| 172.16.0.30 | dvwa-server | HTTP (80) | admin:password | DVWA vulnerable web app |
| 172.16.0.40 | ftp-server | FTP (21) | anonymous:anonymous | Anonymous FTP enabled |
| 172.16.0.50 | mysql-server | MySQL (3306) | root:password123 | MySQL 5.7 database |
| 172.16.0.60 | smb-server | SMB (139,445) | smbuser:password123 | Samba shares with files |
| 172.16.0.70 | tomcat-server | HTTP (8080) | admin:admin | Apache Tomcat 8.5 |
| 172.16.0.80 | redis-server | Redis (6379) | -:redis123 | Redis with password |
| 172.16.0.90 | postgres-server | PostgreSQL (5432) | postgres:postgres | PostgreSQL 11 |
| 172.16.0.100 | wordpress-server | HTTP (80) | admin:admin | WordPress 5.2.2 |
| 172.16.0.110 | webgoat-server | HTTP (8080) | guest:guest | WebGoat training app |

## Service Details

### SSH Server (172.16.0.20)
- **Service**: OpenSSH
- **Vulnerability**: Weak credentials
- **Attack Vector**: Brute force, password spray

### DVWA (172.16.0.30)
- **Service**: Apache + PHP
- **Vulnerabilities**: SQLi, XSS, Command Injection, File Upload
- **Attack Vector**: Web application attacks

### FTP Server (172.16.0.40)
- **Service**: Pure-FTPd
- **Vulnerability**: Anonymous access
- **Attack Vector**: File upload/download, information disclosure

### MySQL Database (172.16.0.50)
- **Service**: MySQL 5.7
- **Vulnerability**: Weak root password, remote access
- **Attack Vector**: Password attack, SQL injection

### SMB Server (172.16.0.60)
- **Service**: Samba
- **Vulnerability**: Weak credentials, sensitive files
- **Attack Vector**: Null sessions, authenticated access

### Tomcat Server (172.16.0.70)
- **Service**: Apache Tomcat 8.5.35
- **Vulnerability**: Default manager credentials
- **Attack Vector**: WAR file deployment, manager access

### Redis Server (172.16.0.80)
- **Service**: Redis 5.0
- **Vulnerability**: Weak password
- **Attack Vector**: Command execution, data extraction

### PostgreSQL Server (172.16.0.90)
- **Service**: PostgreSQL 11
- **Vulnerability**: Default credentials
- **Attack Vector**: Database access, privilege escalation

### WordPress (172.16.0.100)
- **Service**: WordPress 5.2.2
- **Vulnerability**: Outdated version, plugins
- **Attack Vector**: Admin access, plugin vulnerabilities

### WebGoat (172.16.0.110)
- **Service**: Spring Boot application
- **Vulnerability**: Training vulnerabilities
- **Attack Vector**: Various web vulnerabilities

## Scanning Expectations

When students run `nmap -sn 172.16.0.0/24`, they should find:
- 4 Kali machines (172.16.0.11-14)
- 10 target machines (various IPs)
- Total: 14 live hosts

Port scanning will reveal:
- SSH (22): 1 host
- FTP (21): 1 host
- HTTP (80): 2 hosts
- MySQL (3306): 1 host
- SMB (139,445): 1 host
- Tomcat (8080): 2 hosts
- Redis (6379): 1 host
- PostgreSQL (5432): 1 host

This provides a realistic OSCP-like environment with multiple attack vectors!
EOF

echo -e "${YELLOW}[5/5] Verifying setup...${NC}"

# Check running containers
echo ""
echo "Running containers:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Networks}}"

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}   ✅ Realistic Lab Setup Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "You now have 10 diverse targets:"
echo "  • SSH Server (172.16.0.20)"
echo "  • DVWA Web App (172.16.0.30)"
echo "  • FTP Server (172.16.0.40)"
echo "  • MySQL Database (172.16.0.50)"
echo "  • SMB/Samba Server (172.16.0.60)"
echo "  • Apache Tomcat (172.16.0.70)"
echo "  • Redis Database (172.16.0.80)"
echo "  • PostgreSQL Database (172.16.0.90)"
echo "  • WordPress Site (172.16.0.100)"
echo "  • WebGoat Application (172.16.0.110)"
echo ""
echo "Students will find a much more realistic scanning experience!"
echo ""
echo -e "${RED}⚠️  Resource Usage:${NC}"
echo "  • RAM: ~2-3GB total for all containers"
echo "  • CPU: Moderate usage (10-20% idle)"
echo "  • Disk: ~5GB for all images"
echo ""
echo "Your Vultr server should handle this with the $12-24/month plan."
EOF

chmod +x realistic-lab-setup.sh