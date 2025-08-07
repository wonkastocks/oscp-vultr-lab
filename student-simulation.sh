#!/bin/bash

# OSCP Lab Student Simulation Script
# This script simulates a student going through all labs step-by-step
# Shows real commands and expected outputs

set -e

echo "================================================"
echo "   OSCP Lab Student Simulation"
echo "   Simulating Student 1 Experience"
echo "================================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
KALI="kali-user1"
DELAY=1  # Delay between commands for readability

# Function to simulate typing
simulate_command() {
    echo -e "${CYAN}student@kali:~\$ ${NC}$1"
    sleep $DELAY
}

# Function to show output
show_output() {
    echo -e "${GREEN}$1${NC}"
    sleep $DELAY
}

# Function to show section
show_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}   $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    sleep 2
}

# Function to run actual command in container
run_in_container() {
    local command="$1"
    docker exec $KALI bash -c "$command" 2>/dev/null || echo "Command output would appear here"
}

echo -e "${YELLOW}Starting Student Simulation...${NC}"
echo "This simulates what a student would do step-by-step"
echo ""
sleep 2

# Initial Connection
show_section "INITIAL CONNECTION"
simulate_command "ssh oscpuser1@155.138.197.128"
show_output "oscpuser1@155.138.197.128's password: "
show_output "Welcome to Ubuntu 22.04.3 LTS"
show_output ""
simulate_command "./start-lab.sh"
show_output "OSCP Lab - User 1"
show_output "Your Kali IP: 172.16.0.11"
show_output "Targets: .20 (Linux), .40 (Web), .60 (SMB)"
show_output "root@kali-user1:/#"

# LAB 1: Network Discovery
show_section "LAB 1: NETWORK DISCOVERY"

echo "Step 1: Check our network configuration"
simulate_command "ifconfig eth0"
run_in_container "ifconfig eth0 2>/dev/null || ip addr show"

echo ""
echo "Step 2: Discover live hosts on the network"
simulate_command "nmap -sn 172.16.0.0/24"
run_in_container "nmap -sn 172.16.0.0/24 | head -20"

echo ""
echo "Step 3: Detailed scan of Linux target"
simulate_command "nmap -sV -sC 172.16.0.20"
run_in_container "nmap -sV -p 22,80 172.16.0.20"

# LAB 2: Web Application Testing
show_section "LAB 2: WEB APPLICATION TESTING"

echo "Step 1: Check if web server is running"
simulate_command "curl http://172.16.0.40"
run_in_container "curl -s http://172.16.0.40 | head -10"

echo ""
echo "Step 2: Enumerate directories"
simulate_command "gobuster dir -u http://172.16.0.40 -w /usr/share/wordlists/dirb/common.txt"
show_output "==============================================================="
show_output "Gobuster v3.6"
show_output "==============================================================="
show_output "/login.php            (Status: 200) [Size: 1523]"
show_output "/setup.php            (Status: 200) [Size: 3549]"
show_output "/config               (Status: 301) [Size: 313]"
show_output "/vulnerabilities      (Status: 301) [Size: 322]"

echo ""
echo "Step 3: Test for SQL injection"
simulate_command "curl 'http://172.16.0.40/vulnerabilities/sqli/?id=1'"
show_output "First name: admin"
show_output "Surname: admin"

# LAB 3: SMB Enumeration
show_section "LAB 3: SMB ENUMERATION"

echo "Step 1: Check SMB ports"
simulate_command "nmap -p 139,445 172.16.0.60"
run_in_container "nmap -p 139,445 172.16.0.60"

echo ""
echo "Step 2: List SMB shares"
simulate_command "smbclient -L //172.16.0.60 -N"
show_output "Anonymous login successful"
show_output ""
show_output "        Sharename       Type      Comment"
show_output "        ---------       ----      -------"
show_output "        public          Disk      "
show_output "        IPC$            IPC       IPC Service"

echo ""
echo "Step 3: Access public share"
simulate_command "smbclient //172.16.0.60/public -N"
show_output "Anonymous login successful"
show_output "Try \"help\" to get a list of possible commands."
show_output "smb: \\> ls"
show_output "  .                                   D        0  Thu Dec  7 12:00:00 2023"
show_output "  ..                                  D        0  Thu Dec  7 12:00:00 2023"
show_output "  test.txt                            N       33  Thu Dec  7 12:00:00 2023"

# LAB 4: Password Attacks
show_section "LAB 4: PASSWORD ATTACKS"

echo "Step 1: Create password list"
simulate_command "cat > passwords.txt << EOF"
simulate_command "password"
simulate_command "admin"
simulate_command "123456"
simulate_command "root"
simulate_command "toor"
simulate_command "EOF"

echo ""
echo "Step 2: Run Hydra against SSH"
simulate_command "hydra -l root -P passwords.txt ssh://172.16.0.20"
show_output "Hydra v9.4 (c) 2022 by van Hauser/THC"
show_output ""
show_output "[DATA] max 5 tasks per 1 server, overall 5 tasks"
show_output "[DATA] attacking ssh://172.16.0.20:22/"
show_output "[22][ssh] host: 172.16.0.20   login: root   password: toor"
show_output "1 of 1 target successfully completed"

# LAB 5: Exploitation
show_section "LAB 5: EXPLOITATION PRACTICE"

echo "Step 1: Start Metasploit"
simulate_command "msfconsole -q"
show_output "msf6 > "

echo ""
echo "Step 2: Search for DVWA exploits"
simulate_command "search dvwa"
show_output "Matching Modules"
show_output "================"
show_output ""
show_output "   #  Name                                  Rank    Description"
show_output "   -  ----                                  ----    -----------"
show_output "   0  exploit/unix/webapp/dvwa_sqli_blind  manual  DVWA SQL Injection"
show_output "   1  auxiliary/scanner/http/dvwa_login    normal  DVWA Login Scanner"

echo ""
echo "Step 3: Use DVWA login scanner"
simulate_command "use auxiliary/scanner/http/dvwa_login"
simulate_command "set RHOSTS 172.16.0.40"
simulate_command "set USERNAME admin"
simulate_command "set PASSWORD password"
simulate_command "run"
show_output "[+] 172.16.0.40:80 - Login Successful: admin:password"
show_output "[*] Scanned 1 of 1 hosts (100% complete)"

# Summary
show_section "LAB COMPLETION SUMMARY"

echo -e "${GREEN}✅ Lab 1: Network Discovery - COMPLETED${NC}"
echo "   - Discovered 7 hosts on network"
echo "   - Identified open services"
echo ""

echo -e "${GREEN}✅ Lab 2: Web Application Testing - COMPLETED${NC}"
echo "   - Found DVWA installation"
echo "   - Enumerated directories"
echo "   - Identified SQL injection vulnerability"
echo ""

echo -e "${GREEN}✅ Lab 3: SMB Enumeration - COMPLETED${NC}"
echo "   - Listed SMB shares"
echo "   - Accessed public share anonymously"
echo ""

echo -e "${GREEN}✅ Lab 4: Password Attacks - COMPLETED${NC}"
echo "   - Successfully brute-forced SSH"
echo "   - Found credential: root:toor"
echo ""

echo -e "${GREEN}✅ Lab 5: Exploitation - COMPLETED${NC}"
echo "   - Used Metasploit framework"
echo "   - Exploited DVWA login"
echo ""

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}   ALL LABS COMPLETED SUCCESSFULLY!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Student has successfully completed all 5 OSCP preparation labs."
echo "Skills demonstrated:"
echo "  • Network reconnaissance"
echo "  • Service enumeration"
echo "  • Web application testing"
echo "  • Password attacks"
echo "  • Exploitation techniques"
echo ""
echo "Time to complete: ~45 minutes"
echo "================================================"