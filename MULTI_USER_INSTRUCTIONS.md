# 🔥 Multi-User OSCP Lab Setup Instructions

## Quick Setup on Your Vultr Server (155.138.197.128)

### Step 1: Upload and Run Setup Script

```bash
# SSH into your Vultr server as root
ssh root@155.138.197.128

# Download the setup script
cat > multi-user-setup.sh << 'SCRIPT_END'
[paste the entire multi-user-setup.sh content here]
SCRIPT_END

# Make it executable and run
chmod +x multi-user-setup.sh
./multi-user-setup.sh
```

### Step 2: User Access Information

After setup completes, you'll have 4 users ready:

| User | Username | Password | Lab Network | SSH Command |
|------|----------|----------|-------------|-------------|
| 1 | oscpuser1 | OscpLab1!2024 | 172.16.1.0/24 | `ssh oscpuser1@155.138.197.128` |
| 2 | oscpuser2 | OscpLab2!2024 | 172.16.2.0/24 | `ssh oscpuser2@155.138.197.128` |
| 3 | oscpuser3 | OscpLab3!2024 | 172.16.3.0/24 | `ssh oscpuser3@155.138.197.128` |
| 4 | oscpuser4 | OscpLab4!2024 | 172.16.4.0/24 | `ssh oscpuser4@155.138.197.128` |

### Step 3: How Each User Practices

Each user gets:
- Their own Kali Linux container
- Their own target machines
- Isolated network (no interference)
- Personal work directory

**User Instructions:**
```bash
# 1. SSH into the server
ssh oscpuser1@155.138.197.128
# Enter password: OscpLab1!2024

# 2. Start your lab
./start-lab.sh

# 3. You're now in your Kali container!
# Start practicing:
apt update
apt install -y nmap netcat-traditional metasploit-framework
nmap 172.16.1.0/24
```

## What Each User Gets

### Isolated Environment
- **Kali Attack Machine**: `172.16.X.10` (X = user number)
- **Linux Target**: `172.16.X.20`
- **Web Target (DVWA)**: `172.16.X.40`

### No Interference
- Each user has their own network segment
- User 1: 172.16.1.0/24
- User 2: 172.16.2.0/24
- User 3: 172.16.3.0/24
- User 4: 172.16.4.0/24

## Server Management

### For Admin (root user)

**Check all containers:**
```bash
docker ps
```

**Manage labs:**
```bash
/root/manage-labs.sh
```

**Monitor users:**
```bash
who  # See who's logged in
htop  # Monitor resource usage
```

**Restart all labs:**
```bash
cd /opt/oscp-labs
docker-compose restart
```

## Resource Usage

With 4 users running simultaneously:

| Component | RAM Usage | CPU Usage |
|-----------|-----------|-----------|
| Each Kali | ~200MB | 5-10% |
| Each Target | ~50MB | 1-2% |
| Total (4 users) | ~1GB | 20-40% |

Your Vultr server should handle this easily!

## Quick Reference Commands

### For Users
```bash
# Access your Kali
./start-lab.sh

# Exit Kali container
exit

# Check your targets
nmap 172.16.[your-number].0/24
```

### For Admin
```bash
# View all users
cat /etc/passwd | grep oscpuser

# Reset a user's password
passwd oscpuser1

# Stop user 1's containers
docker stop oscp-kali-user1 oscp-target-linux-user1 oscp-web-user1

# Start user 1's containers
docker start oscp-kali-user1 oscp-target-linux-user1 oscp-web-user1
```

## Troubleshooting

### User can't access Docker?
```bash
# As root, add user to docker group
usermod -aG docker oscpuser1
# User needs to logout and login again
```

### Container not starting?
```bash
# Check logs
docker logs oscp-kali-user1

# Restart specific container
docker restart oscp-kali-user1
```

### Out of resources?
```bash
# Check server resources
free -h  # Memory
df -h    # Disk
htop     # CPU and Memory
```

## Cost Reminder

**Vultr Pricing:**
- Your server: $12/month = $0.018/hour
- 24 hours = $0.43
- 8 hours practice = $0.14

**⚠️ IMPORTANT: DESTROY SERVER WHEN DONE!**

To destroy:
1. Go to [my.vultr.com](https://my.vultr.com)
2. Click your server
3. Click "Server Destroy"
4. Type "DESTROY" to confirm

## Alternative: Lighter Setup

If resources are tight, you can run 2 users at a time:

```bash
# Stop users 3 and 4
docker stop oscp-kali-user3 oscp-kali-user4
docker stop oscp-target-linux-user3 oscp-target-linux-user4
docker stop oscp-web-user3 oscp-web-user4

# When users 1&2 are done, start 3&4
docker start oscp-kali-user3 oscp-kali-user4
docker start oscp-target-linux-user3 oscp-target-linux-user4
docker start oscp-web-user3 oscp-web-user4
```

## Ready to Practice!

Your server is at: **155.138.197.128**

Share these credentials with your 4 users:
- User 1: oscpuser1 / OscpLab1!2024
- User 2: oscpuser2 / OscpLab2!2024
- User 3: oscpuser3 / OscpLab3!2024
- User 4: oscpuser4 / OscpLab4!2024

Everyone can practice simultaneously without interfering with each other!