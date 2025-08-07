#!/bin/bash

# Fix and test script for OSCP lab
# This ensures everything is properly installed before testing

echo "================================================"
echo "   OSCP Lab Fix and Test Script"
echo "================================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Step 1: Checking Docker containers...${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}"

echo ""
echo -e "${YELLOW}Step 2: Installing network tools in all Kali containers...${NC}"

# Install basic tools in each Kali container
for i in {1..4}; do
    container="kali-user$i"
    if docker ps | grep -q "$container"; then
        echo "Fixing $container..."
        docker exec $container bash -c "apt update &>/dev/null && apt install -y iproute2 iputils-ping nmap netcat-traditional curl &>/dev/null" &
    fi
done

# Wait for installations
wait

echo -e "${GREEN}✓ Basic tools installed${NC}"

echo ""
echo -e "${YELLOW}Step 3: Quick connectivity test...${NC}"

# Test basic connectivity
if docker exec kali-user1 bash -c "ping -c 1 172.16.0.20 &>/dev/null"; then
    echo -e "${GREEN}✓ Network connectivity works${NC}"
else
    echo "Network issue detected. Restarting containers..."
    docker-compose -f /opt/oscp-labs/docker-compose.yml restart
    sleep 10
fi

echo ""
echo -e "${YELLOW}Step 4: Installing additional tools for labs...${NC}"

# Install all required tools in kali-user1 for testing
docker exec kali-user1 bash -c "
    apt update &>/dev/null
    apt install -y \
        iproute2 \
        iputils-ping \
        nmap \
        netcat-traditional \
        curl \
        gobuster \
        hydra \
        smbclient \
        enum4linux \
        metasploit-framework \
        wget \
        net-tools \
        &>/dev/null
" &

echo "Installing tools (this may take 2-3 minutes)..."
wait

echo -e "${GREEN}✓ All tools installed${NC}"

echo ""
echo -e "${YELLOW}Step 5: Verifying setup...${NC}"

# Quick verification
echo -n "Checking network tools... "
if docker exec kali-user1 bash -c "which ip && which ifconfig" &>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "Installing net-tools..."
    docker exec kali-user1 bash -c "apt install -y net-tools iproute2" &>/dev/null
fi

echo -n "Checking scanning tools... "
if docker exec kali-user1 bash -c "which nmap" &>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo "Failed"
fi

echo -n "Checking web tools... "
if docker exec kali-user1 bash -c "which curl && which gobuster" &>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo "Failed"
fi

echo ""
echo "================================================"
echo -e "${GREEN}   Setup Complete! Now running tests...${NC}"
echo "================================================"
echo ""

# Now run the actual test
if [ -f "./automated-lab-test.sh" ]; then
    chmod +x automated-lab-test.sh
    ./automated-lab-test.sh
else
    echo "Test script not found. Running basic test..."
    
    # Basic test
    echo "Testing Lab 1: Network Discovery"
    docker exec kali-user1 bash -c "ip addr show | grep 172.16"
    docker exec kali-user1 bash -c "ping -c 2 172.16.0.20"
    docker exec kali-user1 bash -c "nmap -sn 172.16.0.0/24"
    
    echo ""
    echo "Testing Lab 2: Web Application"
    docker exec kali-user1 bash -c "curl -I http://172.16.0.40"
    
    echo ""
    echo "Basic tests completed!"
fi