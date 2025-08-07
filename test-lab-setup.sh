#!/bin/bash

# OSCP Lab Validation Script
# Run this on your Vultr server to verify everything works

set -e

echo "================================================"
echo "     OSCP Lab Setup Validation Test"
echo "================================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

# Function to test a condition
test_condition() {
    local test_name="$1"
    local command="$2"
    
    echo -n "Testing: $test_name... "
    
    if eval "$command" &>/dev/null; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((TESTS_FAILED++))
    fi
}

echo -e "${YELLOW}[1/5] Testing User Accounts${NC}"
echo "----------------------------------------"

for i in {1..4}; do
    test_condition "User oscpuser$i exists" "id oscpuser$i"
    test_condition "User oscpuser$i in docker group" "groups oscpuser$i | grep -q docker"
    test_condition "User oscpuser$i has start script" "[ -f /home/oscpuser$i/start-lab.sh ]"
done

echo ""
echo -e "${YELLOW}[2/5] Testing Docker Setup${NC}"
echo "----------------------------------------"

test_condition "Docker is installed" "command -v docker"
test_condition "Docker is running" "docker ps"
test_condition "Docker Compose exists" "[ -f /opt/oscp-labs/docker-compose.yml ]"

echo ""
echo -e "${YELLOW}[3/5] Testing Containers${NC}"
echo "----------------------------------------"

# Check if containers are running
for i in {1..4}; do
    test_condition "Kali container user$i running" "docker ps | grep -q kali-user$i"
done

test_condition "Target Linux container running" "docker ps | grep -q target-linux"
test_condition "Target Web container running" "docker ps | grep -q target-web"

echo ""
echo -e "${YELLOW}[4/5] Testing Network Connectivity${NC}"
echo "----------------------------------------"

# Test network connectivity between containers
test_condition "Kali1 can reach network" "docker exec kali-user1 ping -c 1 172.16.0.20"
test_condition "Target responds to ping" "docker exec kali-user1 ping -c 1 172.16.0.20"

echo ""
echo -e "${YELLOW}[5/5] Testing Lab Functionality${NC}"
echo "----------------------------------------"

# Test actual lab exercises
echo "Running Lab 1 test (Network Discovery)..."
if docker exec kali-user1 bash -c "apt update && apt install -y nmap &>/dev/null && nmap -sn 172.16.0.0/24" &>/dev/null; then
    echo -e "${GREEN}✓ Lab 1: Network scanning works${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ Lab 1: Network scanning failed${NC}"
    ((TESTS_FAILED++))
fi

echo "Running Lab 2 test (Web Application)..."
if docker exec kali-user1 bash -c "apt install -y curl &>/dev/null && curl -s http://172.16.0.40 | grep -q DVWA" &>/dev/null; then
    echo -e "${GREEN}✓ Lab 2: Web server accessible${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ Lab 2: Web server not accessible${NC}"
    ((TESTS_FAILED++))
fi

echo "Running Lab 3 test (SMB Enumeration)..."
if docker exec kali-user1 bash -c "apt install -y smbclient &>/dev/null && smbclient -L //172.16.0.60 -N 2>/dev/null | grep -q public" &>/dev/null; then
    echo -e "${GREEN}✓ Lab 3: SMB shares enumerable${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ Lab 3: SMB enumeration failed${NC}"
    ((TESTS_FAILED++))
fi

# Final Report
echo ""
echo "================================================"
echo "              TEST RESULTS SUMMARY"
echo "================================================"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED! Lab is ready for students.${NC}"
    echo ""
    echo "Students can now connect using:"
    for i in {1..4}; do
        echo "  ssh oscpuser$i@$(hostname -I | cut -d' ' -f1)"
    done
else
    echo -e "${RED}⚠️  Some tests failed. Please check the setup.${NC}"
    echo ""
    echo "Try running the setup script again:"
    echo "  ./quick-multi-user-deploy.sh"
fi

echo ""
echo "================================================"
echo "          QUICK MANUAL TEST COMMANDS"
echo "================================================"
echo ""
echo "Test as Student 1:"
echo "  docker exec -it kali-user1 bash"
echo "  nmap 172.16.0.0/24"
echo "  exit"
echo ""
echo "Check all containers:"
echo "  docker ps"
echo ""
echo "View logs if needed:"
echo "  docker logs kali-user1"
echo ""
echo "================================================"