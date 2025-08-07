# 🔐 OSCP Lab Access Information

## Server Details
- **IP Address:** 155.138.197.128
- **Platform:** Vultr Cloud
- **Cost:** $0.43/day (remember to destroy when done!)

---

## 👤 User 1
```
Username: oscpuser1
Password: OscpLab1!2024
Connect: ssh oscpuser1@155.138.197.128
```

## 👤 User 2
```
Username: oscpuser2
Password: OscpLab2!2024
Connect: ssh oscpuser2@155.138.197.128
```

## 👤 User 3
```
Username: oscpuser3
Password: OscpLab3!2024
Connect: ssh oscpuser3@155.138.197.128
```

## 👤 User 4
```
Username: oscpuser4
Password: OscpLab4!2024
Connect: ssh oscpuser4@155.138.197.128
```

---

## 📋 Quick Start Instructions

1. **Connect to the server:**
   ```bash
   ssh [your-username]@155.138.197.128
   # Enter your password when prompted
   ```

2. **Start your lab:**
   ```bash
   ./start-lab.sh
   ```

3. **You're now in Kali! Install tools:**
   ```bash
   apt update
   apt install -y nmap netcat-traditional metasploit-framework
   ```

4. **Find targets:**
   ```bash
   nmap 172.16.0.0/24
   ```

---

## 🎯 Target Machines

| Target | IP Address | Description |
|--------|------------|-------------|
| Linux | 172.16.0.20 | Ubuntu server |
| Web | 172.16.0.40 | DVWA vulnerable web app |
| SMB | 172.16.0.60 | Samba file share |

---

## 💡 Tips

- Each user has their own Kali machine
- All users share the same targets
- Your work is saved in your home directory
- Type `exit` to leave Kali container
- Type `exit` again to disconnect from server

---

## ⚠️ Important

**The server costs money ($0.43/day)!**
Please notify the admin when you're done practicing so they can destroy the server.