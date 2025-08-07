"""
OSCP Lab Practice Environment - Enhanced Realistic Version
More realistic simulation with actual command outputs and responses
"""

import streamlit as st
import pandas as pd
import json
import hashlib
import base64
import random
import time
import socket
import struct
from datetime import datetime
import re

# Page configuration
st.set_page_config(
    page_title="OSCP Lab Practice - Realistic",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'completed_exercises' not in st.session_state:
    st.session_state.completed_exercises = []
if 'current_lab' not in st.session_state:
    st.session_state.current_lab = 1
if 'score' not in st.session_state:
    st.session_state.score = 0
if 'terminal_output' not in st.session_state:
    st.session_state.terminal_output = []
if 'command_history' not in st.session_state:
    st.session_state.command_history = []
if 'current_directory' not in st.session_state:
    st.session_state.current_directory = "/root"
if 'files_system' not in st.session_state:
    # Simulated file system
    st.session_state.files_system = {
        "/root": ["notes.txt", "tools", "scripts", ".bashrc", ".bash_history"],
        "/root/tools": ["nmap", "gobuster", "nikto", "hydra"],
        "/root/scripts": ["scan.sh", "enum.sh", "exploit.py"],
        "/etc": ["passwd", "shadow", "hosts", "resolv.conf"],
        "/var/www/html": ["index.html", "login.php", "config.php", "uploads"],
        "/tmp": ["backdoor.sh", "linpeas.sh", "payload.elf"]
    }

# Enhanced target systems with more realistic data
TARGETS = {
    "172.16.0.20": {
        "hostname": "target-linux",
        "os": "Linux target-linux 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 GNU/Linux",
        "services": {
            22: {
                "name": "ssh",
                "product": "OpenSSH",
                "version": "7.9p1 Debian 10+deb10u2",
                "banner": "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2",
                "vulns": []
            },
            80: {
                "name": "http",
                "product": "Apache httpd",
                "version": "2.4.38",
                "banner": "Apache/2.4.38 (Debian)",
                "extra": "PHP/7.3.27",
                "paths": ["/", "/admin", "/login.php", "/uploads", "/backup", "/phpmyadmin"],
                "vulns": ["CVE-2021-41773 - Path Traversal"]
            },
            3306: {
                "name": "mysql",
                "product": "MySQL",
                "version": "5.7.33",
                "banner": "5.7.33-0ubuntu0.18.04.1",
                "vulns": ["Anonymous login allowed"]
            },
            21: {
                "name": "ftp",
                "product": "vsftpd",
                "version": "3.0.3",
                "banner": "220 (vsFTPd 3.0.3)",
                "vulns": ["Anonymous FTP login allowed"]
            }
        },
        "users": ["root", "admin", "www-data", "mysql", "ftp", "john", "sarah", "backup"],
        "passwords": ["password123", "admin", "letmein", "123456", "qwerty"],
        "files": {
            "/home/john/.ssh/id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA3IIf6Wczcdm38MZ9+c...",
            "/var/www/html/config.php": "<?php\n$db_host='localhost';\n$db_user='root';\n$db_pass='MySQLR00t!';\n?>",
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\njohn:x:1000:1000:John Doe:/home/john:/bin/bash",
            "/home/john/user.txt": "flag{user_level_access_granted}",
            "/root/root.txt": "flag{you_got_root_congratulations}"
        }
    },
    "172.16.0.60": {
        "hostname": "smb-server",
        "os": "Windows Server 2016 Datacenter 14393",
        "services": {
            139: {
                "name": "netbios-ssn",
                "product": "Microsoft Windows netbios-ssn"
            },
            445: {
                "name": "microsoft-ds",
                "product": "Windows Server 2016 Standard 14393 microsoft-ds",
                "shares": {
                    "ADMIN$": {"access": "NO ACCESS", "type": "IPC"},
                    "C$": {"access": "NO ACCESS", "type": "Disk"},
                    "IPC$": {"access": "READ", "type": "IPC"},
                    "Public": {"access": "READ/WRITE", "type": "Disk"},
                    "Users": {"access": "READ", "type": "Disk"},
                    "Backup": {"access": "READ", "type": "Disk"}
                },
                "vulns": ["MS17-010 EternalBlue - VULNERABLE"]
            },
            3389: {
                "name": "ms-wbt-server",
                "product": "Microsoft Terminal Services",
                "vulns": ["BlueKeep (CVE-2019-0708) - VULNERABLE"]
            }
        },
        "users": ["Administrator", "Guest", "john.smith", "jane.doe", "backup_admin"],
        "groups": ["Domain Admins", "Domain Users", "Backup Operators"]
    },
    "172.16.0.50": {
        "hostname": "mail-server",
        "os": "Linux mail 5.4.0-72-generic #80-Ubuntu",
        "services": {
            25: {
                "name": "smtp",
                "product": "Postfix smtpd",
                "banner": "220 mail.megacorpone.com ESMTP Postfix (Ubuntu)",
                "commands": ["EHLO", "MAIL FROM", "RCPT TO", "DATA", "VRFY", "EXPN"],
                "vulns": ["VRFY command enabled - User enumeration possible"]
            },
            110: {
                "name": "pop3",
                "product": "Dovecot pop3d"
            },
            143: {
                "name": "imap",
                "product": "Dovecot imapd"
            }
        },
        "users": ["postmaster", "admin", "john", "sarah", "sales", "support", "info"],
        "emails": ["admin@megacorpone.com", "info@megacorpone.com"]
    }
}

# Custom CSS for better terminal appearance
st.markdown("""
<style>
    .terminal {
        background-color: #1e1e1e;
        color: #00ff00;
        font-family: 'Courier New', monospace;
        padding: 15px;
        border-radius: 5px;
        min-height: 400px;
        max-height: 600px;
        overflow-y: auto;
        white-space: pre-wrap;
        word-wrap: break-word;
        line-height: 1.5;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        padding: 10px;
        border-radius: 5px;
        color: #155724;
    }
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeeba;
        padding: 10px;
        border-radius: 5px;
        color: #856404;
    }
    .error-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        padding: 10px;
        border-radius: 5px;
        color: #721c24;
    }
</style>
""", unsafe_allow_html=True)

def simulate_realistic_nmap(target_ip, options=""):
    """Generate realistic nmap output"""
    if target_ip not in TARGETS:
        return f"Note: Host seems down. If it is really up, try -Pn"
    
    target = TARGETS[target_ip]
    output = f"""Starting Nmap 7.91 ( https://nmap.org ) at {datetime.now().strftime('%Y-%m-%d %H:%M')} EDT
Nmap scan report for {target['hostname']} ({target_ip})
Host is up (0.00031s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE     VERSION"""
    
    for port, service in target['services'].items():
        state = "open"
        output += f"\n{port}/tcp".ljust(9) + f"{state}".ljust(6)
        output += f"{service['name']}".ljust(13)
        
        if '-sV' in options or '-A' in options:
            if 'product' in service:
                output += f"{service['product']}"
            if 'version' in service:
                output += f" {service['version']}"
            if 'extra' in service:
                output += f" ({service['extra']})"
    
    if '-O' in options or '-A' in options:
        output += f"\nOS details: {target['os']}"
    
    if '--script vuln' in options:
        output += "\n\nHost script results:"
        for port, service in target['services'].items():
            if 'vulns' in service and service['vulns']:
                for vuln in service['vulns']:
                    output += f"\n| {vuln}"
    
    output += f"\n\nNmap done: 1 IP address (1 host up) scanned in 3.37 seconds"
    return output

def simulate_gobuster(target_ip):
    """Simulate gobuster directory enumeration"""
    if target_ip not in TARGETS:
        return "Error: Unable to connect to target"
    
    target = TARGETS[target_ip]
    if 80 not in target['services']:
        return "Error: No web service found on port 80"
    
    paths = target['services'][80].get('paths', [])
    output = f"""===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://{target_ip}
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Status codes:            200,204,301,302,307,401,403
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
==============================================================="""
    
    for path in paths:
        status = "200" if path != "/admin" else "401"
        size = random.randint(100, 5000)
        output += f"\n{path}".ljust(20) + f"(Status: {status}) [Size: {size}]"
    
    output += f"\n\n===============================================================\nFinished\n==============================================================="
    return output

def simulate_metasploit():
    """Simulate Metasploit console"""
    return """
       =[ metasploit v6.0.27-dev                          ]
+ -- --=[ 2096 exploits - 1127 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                        ]

Metasploit tip: Use sessions -x to list active sessions

msf6 > 
Available commands:
- use exploit/windows/smb/ms17_010_eternalblue
- use auxiliary/scanner/smb/smb_enumshares
- use auxiliary/scanner/smtp/smtp_enum
- set RHOSTS <target>
- exploit
- sessions -l
"""

def execute_command(command):
    """Execute simulated commands with realistic output"""
    cmd_parts = command.strip().split()
    if not cmd_parts:
        return ""
    
    base_cmd = cmd_parts[0]
    
    # File system commands
    if base_cmd == "ls":
        if st.session_state.current_directory in st.session_state.files_system:
            files = st.session_state.files_system[st.session_state.current_directory]
            if "-la" in command:
                output = "total 32\n"
                output += "drwxr-xr-x  5 root root 4096 Nov 15 10:23 .\n"
                output += "drwxr-xr-x 23 root root 4096 Nov 15 09:45 ..\n"
                for f in files:
                    if f.startswith('.'):
                        output += f"-rw-------  1 root root  220 Nov 15 09:45 {f}\n"
                    else:
                        output += f"-rw-r--r--  1 root root 1234 Nov 15 10:23 {f}\n"
            else:
                output = "  ".join([f for f in files if not f.startswith('.')])
            return output
        return "ls: cannot access: No such file or directory"
    
    elif base_cmd == "pwd":
        return st.session_state.current_directory
    
    elif base_cmd == "cd":
        if len(cmd_parts) > 1:
            new_dir = cmd_parts[1]
            if new_dir == "..":
                st.session_state.current_directory = "/".join(st.session_state.current_directory.split("/")[:-1]) or "/"
            elif new_dir.startswith("/"):
                if new_dir in st.session_state.files_system:
                    st.session_state.current_directory = new_dir
                else:
                    return f"cd: {new_dir}: No such file or directory"
            else:
                potential_path = f"{st.session_state.current_directory}/{new_dir}".replace("//", "/")
                if potential_path in st.session_state.files_system:
                    st.session_state.current_directory = potential_path
                else:
                    return f"cd: {new_dir}: No such file or directory"
        return ""
    
    elif base_cmd == "cat":
        if len(cmd_parts) > 1:
            filename = cmd_parts[1]
            # Check in various target files
            for target_ip, target_data in TARGETS.items():
                if 'files' in target_data and filename in target_data['files']:
                    return target_data['files'][filename]
            
            # Default file contents
            if filename == "passwd" or filename == "/etc/passwd":
                return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
john:x:1000:1000:John Doe,,,:/home/john:/bin/bash
sarah:x:1001:1001:Sarah Smith,,,:/home/sarah:/bin/bash"""
            elif filename == "config.php":
                return """<?php
$db_host = 'localhost';
$db_user = 'root';
$db_pass = 'MySQLR00t!';
$db_name = 'webapp';
?>"""
            return f"cat: {filename}: No such file or directory"
        return "cat: missing operand"
    
    # Network commands
    elif base_cmd == "nmap":
        if len(cmd_parts) < 2:
            return "Nmap 7.91 ( https://nmap.org )\nUsage: nmap [Scan Type(s)] [Options] {target specification}"
        
        target = cmd_parts[-1]
        options = " ".join(cmd_parts[1:-1])
        return simulate_realistic_nmap(target, options)
    
    elif base_cmd == "gobuster":
        if "dir" in command:
            for part in cmd_parts:
                if part.startswith("-u"):
                    url = part[2:] if len(part) > 2 else cmd_parts[cmd_parts.index(part) + 1]
                    ip = url.replace("http://", "").replace("https://", "").split("/")[0]
                    return simulate_gobuster(ip)
        return "Usage: gobuster dir -u <url> -w <wordlist>"
    
    elif base_cmd == "hydra":
        return """Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak

Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-c TIME] [-ISOuvVd46] [service://server[:PORT][/OPT]]

Example: hydra -l admin -P passwords.txt 172.16.0.20 ssh"""
    
    elif base_cmd == "smbclient":
        if "-L" in command:
            return """
        Sharename       Type      Comment
        ---------       ----      -------
        Public          Disk      Public Share - No Auth Required
        Users           Disk      User Directories
        Backup          Disk      Backup Files
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC

SMB1 disabled -- no workgroup available"""
        return "Usage: smbclient -L //host -N"
    
    elif base_cmd == "enum4linux":
        if len(cmd_parts) > 1:
            return f"""Starting enum4linux v0.8.9

 ========================== 
|    Target Information    |
 ========================== 
Target ........... {cmd_parts[1]}
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''

 ====================================== 
|    Share Enumeration on {cmd_parts[1]}    |
 ====================================== 
        Sharename       Type      Comment
        ---------       ----      -------
        Public          Disk      Public Share
        IPC$            IPC       IPC Service

 =========================================== 
|    Users on {cmd_parts[1]} via RID cycling    |
 =========================================== 
[+] Enumerating users using SID S-1-5-21-1234567890-1234567890-1234567890
S-1-5-21-1234567890-1234567890-1234567890-500 Administrator (Local User)
S-1-5-21-1234567890-1234567890-1234567890-501 Guest (Local User)
S-1-5-21-1234567890-1234567890-1234567890-1000 john.smith (Local User)
S-1-5-21-1234567890-1234567890-1234567890-1001 jane.doe (Local User)"""
        return "Usage: enum4linux [options] target"
    
    elif base_cmd == "msfconsole":
        return simulate_metasploit()
    
    elif base_cmd == "searchsploit":
        if len(cmd_parts) > 1:
            search = " ".join(cmd_parts[1:])
            return f"""---------------------------------------- ---------------------------------
 Exploit Title                          |  Path
---------------------------------------- ---------------------------------
Apache 2.4.x - Path Traversal          | linux/webapps/49973.py
MySQL 5.7.x - Authentication Bypass    | linux/remote/48978.txt
SMB MS17-010 - EternalBlue             | windows/remote/42315.py
---------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results"""
        return "Usage: searchsploit [options] term1 [term2] ... [termN]"
    
    elif base_cmd == "whoami":
        return "root"
    
    elif base_cmd == "id":
        return "uid=0(root) gid=0(root) groups=0(root)"
    
    elif base_cmd == "ifconfig" or base_cmd == "ip":
        return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.0.10  netmask 255.255.255.0  broadcast 172.16.0.255
        ether 02:42:ac:10:00:0a  txqueuelen 0  (Ethernet)"""
    
    elif base_cmd == "ping":
        if len(cmd_parts) > 1:
            target = cmd_parts[1]
            if any(target == ip for ip in TARGETS.keys()):
                return f"""PING {target} ({target}) 56(84) bytes of data.
64 bytes from {target}: icmp_seq=1 ttl=64 time=0.326 ms
64 bytes from {target}: icmp_seq=2 ttl=64 time=0.289 ms
64 bytes from {target}: icmp_seq=3 ttl=64 time=0.301 ms

--- {target} ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms"""
            return f"ping: {target}: Name or service not known"
        return "Usage: ping [options] destination"
    
    elif base_cmd == "nc" or base_cmd == "netcat":
        if len(cmd_parts) >= 3:
            host = cmd_parts[1]
            port = cmd_parts[2]
            if host in TARGETS:
                target = TARGETS[host]
                try:
                    port_num = int(port)
                    if port_num in target['services']:
                        service = target['services'][port_num]
                        if 'banner' in service:
                            return f"Connection to {host} {port} port [tcp/*] succeeded!\n{service['banner']}"
                except:
                    pass
            return f"nc: connect to {host} port {port} (tcp) failed: Connection refused"
        return "usage: nc [-options] hostname port[s]"
    
    elif base_cmd == "help":
        return """Available Commands:

File System:
  ls, cd, pwd, cat, find, grep

Network Scanning:
  nmap, ping, nc/netcat, traceroute

Web Enumeration:
  gobuster, nikto, dirb, wfuzz

Service Enumeration:
  smbclient, enum4linux, rpcclient, nbtscan

Exploitation:
  msfconsole, searchsploit, hydra

System:
  whoami, id, ifconfig, ps, netstat

Type 'man <command>' for detailed help"""
    
    else:
        return f"bash: {base_cmd}: command not found\nType 'help' for available commands"

# Main UI
st.title("🎯 OSCP Practice Lab - Realistic Environment")
st.markdown("### Interactive Penetration Testing Training")

# Sidebar
with st.sidebar:
    st.markdown("## 🖥️ Target Network")
    st.markdown("""
    **Available Targets:**
    - `172.16.0.20` - Linux Server
    - `172.16.0.60` - Windows SMB
    - `172.16.0.50` - Mail Server
    
    **Your IP:** `172.16.0.10`
    
    **Quick Commands:**
    ```
    nmap -sV 172.16.0.20
    gobuster dir -u http://172.16.0.20 -w /usr/share/wordlists/dirb/common.txt
    smbclient -L //172.16.0.60 -N
    enum4linux 172.16.0.60
    ```
    """)
    
    st.markdown("---")
    st.markdown("### 📊 Progress")
    progress = len(st.session_state.completed_exercises) / 10 * 100
    st.progress(progress / 100)
    st.write(f"Score: {st.session_state.score}")

# Main tabs
tab1, tab2, tab3, tab4 = st.tabs(["💻 Terminal", "📚 Methodology", "🎯 Challenges", "🛠️ Tools"])

with tab1:
    st.markdown("### Interactive Terminal")
    st.markdown(f"**Current Directory:** `{st.session_state.current_directory}`")
    
    # Command input
    col1, col2 = st.columns([5, 1])
    with col1:
        command = st.text_input("", placeholder="Enter command...", key="main_command", label_visibility="collapsed")
    with col2:
        execute_btn = st.button("Execute", key="exec_btn", use_container_width=True)
    
    # Execute command
    if execute_btn and command:
        output = execute_command(command)
        st.session_state.command_history.append(command)
        st.session_state.terminal_output.append(f"root@kali:{st.session_state.current_directory}# {command}")
        if output:
            st.session_state.terminal_output.append(output)
    
    # Terminal display
    terminal_content = "\n".join(st.session_state.terminal_output[-30:])  # Last 30 lines
    st.markdown(f'<div class="terminal">{terminal_content}</div>', unsafe_allow_html=True)
    
    # Quick commands
    st.markdown("### Quick Commands")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔍 Scan Network"):
            cmd = "nmap -sn 172.16.0.0/24"
            output = """Starting Nmap 7.91 ( https://nmap.org )
Nmap scan report for 172.16.0.10
Host is up (0.00010s latency).
Nmap scan report for 172.16.0.20
Host is up (0.00032s latency).
Nmap scan report for 172.16.0.50
Host is up (0.00028s latency).
Nmap scan report for 172.16.0.60
Host is up (0.00045s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.43 seconds"""
            st.session_state.terminal_output.append(f"root@kali:{st.session_state.current_directory}# {cmd}")
            st.session_state.terminal_output.append(output)
            st.experimental_rerun()
    
    with col2:
        if st.button("🌐 Scan Web"):
            cmd = "nmap -sV -p80,443 172.16.0.20"
            output = execute_command(cmd)
            st.session_state.terminal_output.append(f"root@kali:{st.session_state.current_directory}# {cmd}")
            st.session_state.terminal_output.append(output)
            st.experimental_rerun()
    
    with col3:
        if st.button("📁 Enum SMB"):
            cmd = "smbclient -L //172.16.0.60 -N"
            output = execute_command(cmd)
            st.session_state.terminal_output.append(f"root@kali:{st.session_state.current_directory}# {cmd}")
            st.session_state.terminal_output.append(output)
            st.experimental_rerun()
    
    with col4:
        if st.button("🗑️ Clear"):
            st.session_state.terminal_output = []
            st.experimental_rerun()

with tab2:
    st.markdown("### OSCP Methodology")
    
    methodology = st.selectbox("Select Phase:", 
                              ["1. Information Gathering", 
                               "2. Vulnerability Scanning", 
                               "3. Exploitation",
                               "4. Post-Exploitation"])
    
    if "Information" in methodology:
        st.markdown("""
        #### Information Gathering Checklist
        
        **Network Scanning:**
        ```bash
        # Host discovery
        nmap -sn 172.16.0.0/24
        
        # Port scanning
        nmap -sS -p- --min-rate=1000 <target>
        
        # Service enumeration
        nmap -sV -sC -p<ports> <target>
        
        # UDP scanning
        nmap -sU --top-ports 20 <target>
        ```
        
        **Web Enumeration:**
        ```bash
        # Directory brute force
        gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
        
        # Nikto scan
        nikto -h http://target
        
        # Technology detection
        whatweb http://target
        ```
        
        **SMB Enumeration:**
        ```bash
        # List shares
        smbclient -L //target -N
        
        # Detailed enumeration
        enum4linux -a target
        
        # Connect to share
        smbclient //target/share -N
        ```
        """)
    
    elif "Vulnerability" in methodology:
        st.markdown("""
        #### Vulnerability Scanning
        
        **Automated Scanning:**
        ```bash
        # Nmap vulnerability scripts
        nmap --script vuln <target>
        
        # Search for exploits
        searchsploit <service> <version>
        
        # OpenVAS/Nessus scanning
        # (Configure through web interface)
        ```
        
        **Manual Testing:**
        - Check default credentials
        - Test for SQL injection
        - Look for outdated services
        - Check for misconfigurations
        """)
    
    elif "Exploitation" in methodology:
        st.markdown("""
        #### Exploitation Phase
        
        **Metasploit:**
        ```bash
        msfconsole
        search <vulnerability>
        use exploit/path/to/exploit
        set RHOSTS <target>
        set LHOST <your_ip>
        exploit
        ```
        
        **Manual Exploitation:**
        ```bash
        # Compile exploit
        gcc exploit.c -o exploit
        
        # Python exploit
        python3 exploit.py <target>
        
        # Create reverse shell
        nc -lvnp 4444  # Listener
        ```
        """)
    
    elif "Post-Exploitation" in methodology:
        st.markdown("""
        #### Post-Exploitation
        
        **Linux Privilege Escalation:**
        ```bash
        # System enumeration
        uname -a
        cat /etc/passwd
        sudo -l
        find / -perm -u=s -type f 2>/dev/null
        
        # LinPEAS
        curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
        ```
        
        **Windows Privilege Escalation:**
        ```bash
        # System info
        systeminfo
        whoami /priv
        net users
        
        # WinPEAS
        .\winPEASany.exe
        ```
        """)

with tab3:
    st.markdown("### Challenges")
    
    # Challenge categories
    challenge_cat = st.selectbox("Select Challenge Category:", 
                                 ["Network Scanning", "Web Enumeration", "SMB Attacks", "Exploitation"])
    
    if challenge_cat == "Network Scanning":
        with st.expander("🏆 Challenge 1: Find All Services"):
            st.write("Scan 172.16.0.20 and identify all open ports")
            
            answer = st.text_input("Enter all port numbers (comma-separated):", key="ch1")
            
            if st.button("Submit", key="ch1_btn"):
                if set(answer.replace(" ", "").split(",")) == {"22", "80", "3306", "21"}:
                    st.success("✅ Correct! You found all services: SSH(22), HTTP(80), MySQL(3306), FTP(21)")
                    if "ch1" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("ch1")
                        st.session_state.score += 20
                else:
                    st.error("❌ Not all services found. Try: nmap -sV 172.16.0.20")
        
        with st.expander("🏆 Challenge 2: Identify Vulnerability"):
            st.write("Find a critical vulnerability on 172.16.0.60")
            
            answer = st.selectbox("Which vulnerability is present?", 
                                 ["", "Heartbleed", "EternalBlue", "Shellshock", "SQLi"],
                                 key="ch2")
            
            if st.button("Submit", key="ch2_btn"):
                if answer == "EternalBlue":
                    st.success("✅ Correct! MS17-010 EternalBlue is present on the SMB service!")
                    if "ch2" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("ch2")
                        st.session_state.score += 30
                else:
                    st.error("❌ Try scanning with: nmap --script vuln 172.16.0.60")
    
    elif challenge_cat == "Web Enumeration":
        with st.expander("🏆 Challenge 3: Find Hidden Directory"):
            st.write("There's a hidden admin panel on 172.16.0.20. Find it!")
            
            answer = st.text_input("Enter the path:", key="ch3")
            
            if st.button("Submit", key="ch3_btn"):
                if answer.strip("/").lower() in ["admin", "phpmyadmin"]:
                    st.success("✅ Correct! You found the admin panel!")
                    if "ch3" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("ch3")
                        st.session_state.score += 25
                else:
                    st.error("❌ Keep looking! Try: gobuster dir -u http://172.16.0.20 -w /path/to/wordlist")

with tab4:
    st.markdown("### Penetration Testing Tools")
    
    tool_category = st.selectbox("Tool Category:", 
                                ["Scanning", "Enumeration", "Exploitation", "Post-Exploitation"])
    
    if tool_category == "Scanning":
        st.markdown("""
        #### Scanning Tools
        
        **Nmap** - Network exploration and security auditing
        ```bash
        nmap -sV <target>          # Version detection
        nmap -sS <target>          # SYN scan
        nmap -sU <target>          # UDP scan
        nmap -A <target>           # Aggressive scan
        nmap --script vuln <target> # Vulnerability scan
        ```
        
        **Masscan** - Fast port scanner
        ```bash
        masscan -p1-65535 <target> --rate=1000
        ```
        
        **Netcat** - Network utility
        ```bash
        nc -nv <target> <port>     # Connect to port
        nc -lvnp <port>            # Listen on port
        ```
        """)
    
    elif tool_category == "Enumeration":
        st.markdown("""
        #### Enumeration Tools
        
        **Web Enumeration:**
        - Gobuster - Directory/file brute force
        - Nikto - Web vulnerability scanner
        - Dirb - Web content scanner
        - WFuzz - Web fuzzer
        
        **SMB Enumeration:**
        - enum4linux - SMB enumeration
        - smbclient - SMB client
        - rpcclient - RPC client
        - nbtscan - NetBIOS scanner
        
        **DNS Enumeration:**
        - dnsrecon - DNS enumeration
        - dnsenum - DNS enumeration
        - fierce - DNS scanner
        """)
    
    elif tool_category == "Exploitation":
        st.markdown("""
        #### Exploitation Tools
        
        **Metasploit Framework**
        ```bash
        msfconsole                 # Start Metasploit
        search <term>              # Search exploits
        use <exploit>              # Select exploit
        show options               # Show options
        set <option> <value>       # Set option
        exploit                    # Run exploit
        ```
        
        **Searchsploit** - Exploit database search
        ```bash
        searchsploit <term>        # Search exploits
        searchsploit -m <id>       # Mirror exploit
        ```
        
        **Hydra** - Password cracker
        ```bash
        hydra -l admin -P pass.txt <target> ssh
        ```
        """)

# Footer
st.markdown("---")
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("### 📊 Statistics")
    st.write(f"Commands Run: {len(st.session_state.command_history)}")
    st.write(f"Score: {st.session_state.score}")

with col2:
    st.markdown("### 🎯 Target Status")
    st.write("✅ Linux Server: Online")
    st.write("✅ SMB Server: Online")
    st.write("✅ Mail Server: Online")

with col3:
    st.markdown("### 💡 Hint")
    hints = [
        "Try 'nmap -sV' for version detection",
        "Check for default credentials",
        "Enumerate thoroughly before exploiting",
        "Document everything you find"
    ]
    st.write(random.choice(hints))

st.markdown("---")
st.markdown("*OSCP Practice Environment - Safe & Legal Training Platform*")