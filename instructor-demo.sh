#!/bin/bash

# INSTRUCTOR-ONLY DEMO RUNNER
# This script runs the automated demonstration from the server
# Only works when run as root from /root directory

# Security checks
if [ "$EUID" -ne 0 ]; then 
    echo "❌ This is an instructor-only tool. Must be run as root."
    exit 1
fi

if [[ "$(pwd)" != "/root" && "$(pwd)" != "/root/"* ]]; then
    echo "❌ Must be run from /root directory"
    echo "Current directory: $(pwd)"
    exit 1
fi

echo "================================================"
echo "   INSTRUCTOR DEMONSTRATION PANEL"
echo "   Root Access Only - Educational Demo"
echo "================================================"
echo ""

# Select container
echo "Which container should run the demonstration?"
echo ""
echo "1) kali-user1 - Student 1's container"
echo "2) kali-user2 - Student 2's container"
echo "3) kali-user3 - Student 3's container"
echo "4) kali-user4 - Student 4's container"
echo ""
read -p "Select container (1-4): " CHOICE

case $CHOICE in
    1) CONTAINER="kali-user1" ;;
    2) CONTAINER="kali-user2" ;;
    3) CONTAINER="kali-user3" ;;
    4) CONTAINER="kali-user4" ;;
    *) echo "Invalid selection"; exit 1 ;;
esac

echo ""
echo "Selected: $CONTAINER"
echo ""

# Check container is running
if ! docker ps | grep -q $CONTAINER; then
    echo "Starting container $CONTAINER..."
    docker start $CONTAINER
    sleep 3
fi

# Create the actual demo script that will run INSIDE the container
cat > /tmp/container-demo.sh << 'DEMO_SCRIPT'
#!/bin/bash

# This runs INSIDE the container with full demo

set +e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

# Timing
COMMAND_DELAY=2
SHORT_PAUSE=5
MEDIUM_PAUSE=8
LONG_PAUSE=12

show_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}${BOLD}   $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    sleep 3
}

explain() {
    echo ""
    echo -e "${MAGENTA}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│ 📚 EXPLANATION:                                             │${NC}"
    echo -e "${MAGENTA}│                                                             │${NC}"
    echo -e "${MAGENTA}│${NC} $1"
    echo -e "${MAGENTA}│                                                             │${NC}"
    echo -e "${MAGENTA}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    sleep $MEDIUM_PAUSE
}

run_command() {
    echo -e "${CYAN}┌[student@kali]─[~]${NC}"
    echo -e "${CYAN}└──╼ \$${NC} ${YELLOW}$1${NC}"
    sleep $COMMAND_DELAY
    echo ""
    eval "$1"
    echo ""
    sleep $SHORT_PAUSE
}

clear
echo -e "${GREEN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║          INSTRUCTOR-LED OSCP LAB DEMONSTRATION                   ║"
echo "║                                                                   ║"
echo "║            Automated Walkthrough with Explanations               ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "${YELLOW}This demonstration shows real attacks on the lab environment${NC}"
echo ""
sleep 5

# PHASE 1: Tool Installation
show_section "PHASE 1: INSTALLING TOOLS"
explain "First, we need to install penetration testing tools."
run_command "apt update 2>&1 | tail -5"
run_command "apt install -y nmap netcat-traditional net-tools iputils-ping 2>&1 | grep 'Setting' | tail -3"

# PHASE 2: Network Discovery  
show_section "PHASE 2: NETWORK DISCOVERY"
explain "Discovering all hosts on the 172.16.0.0/24 network"
run_command "ip addr show eth0 | grep inet"
run_command "nmap -sn 172.16.0.0/24 | grep 'Nmap scan report'"

# PHASE 3: Port Scanning
show_section "PHASE 3: PORT SCANNING"
explain "Now we scan for open ports on discovered hosts"
run_command "nmap -p22 172.16.0.20"
run_command "nmap -p80 172.16.0.30 | grep open"
run_command "nmap -p21 172.16.0.40 | grep open"

# PHASE 4: Service Enumeration
show_section "PHASE 4: SERVICE ENUMERATION"
explain "Gathering information about each service"
run_command "echo 'Checking FTP anonymous access...'"
echo -e "USER anonymous\nPASS anonymous\nQUIT" | timeout 3 nc 172.16.0.40 21 | head -5

# PHASE 5: Exploitation
show_section "PHASE 5: EXPLOITATION"
explain "Attempting to exploit discovered vulnerabilities"
echo -e "admin\npassword\ntoor\nroot" > /tmp/pass.txt
run_command "echo 'Password list created: admin, password, toor, root'"

# Summary
show_section "DEMONSTRATION COMPLETE"
echo -e "${GREEN}✅ Successfully demonstrated:${NC}"
echo "  • Tool installation"
echo "  • Network discovery" 
echo "  • Port scanning"
echo "  • Service enumeration"
echo "  • Basic exploitation"
echo ""
echo -e "${YELLOW}Students can now practice these techniques manually!${NC}"
echo ""
DEMO_SCRIPT

# Copy demo script to container
echo "📤 Deploying demonstration to $CONTAINER..."
docker cp /tmp/container-demo.sh $CONTAINER:/tmp/demo.sh
docker exec $CONTAINER chmod +x /tmp/demo.sh

echo ""
echo "🎬 Starting demonstration in $CONTAINER..."
echo "================================================"
echo ""

# Run the demonstration
docker exec -it $CONTAINER /tmp/demo.sh

# Cleanup
rm -f /tmp/container-demo.sh

echo ""
echo "================================================"
echo "   Instructor Demo Complete"
echo "================================================"