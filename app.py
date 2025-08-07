"""
OSCP Lab Practice Environment - Streamlit App
A safe, interactive environment to practice OSCP exercises
"""

import streamlit as st
import pandas as pd
import json
import subprocess
import re
import socket
import random
import time
from datetime import datetime
import hashlib
import base64

# Page configuration
st.set_page_config(
    page_title="OSCP Lab Practice",
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

# Custom CSS
st.markdown("""
<style>
    .terminal {
        background-color: #1e1e1e;
        color: #00ff00;
        font-family: 'Courier New', monospace;
        padding: 10px;
        border-radius: 5px;
        min-height: 200px;
        white-space: pre-wrap;
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
    .stButton > button {
        background-color: #4CAF50;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("🎯 OSCP Lab Navigator")
st.sidebar.markdown("---")

lab_selection = st.sidebar.selectbox(
    "Select Lab",
    ["Lab 1: Kali Fundamentals", 
     "Lab 2: Essential Tools",
     "Lab 3: Passive Recon",
     "Lab 4: Active Recon",
     "Lab 5: SMB/SMTP Enum"]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 Your Progress")
progress = len(st.session_state.completed_exercises) / 25 * 100
st.sidebar.progress(progress / 100)
st.sidebar.write(f"Score: {st.session_state.score} points")
st.sidebar.write(f"Completed: {len(st.session_state.completed_exercises)}/25 exercises")

# Simulated target systems
TARGETS = {
    "linux_target": {
        "ip": "172.16.0.20",
        "hostname": "target-linux",
        "services": {
            22: {"name": "SSH", "version": "OpenSSH 7.9", "banner": "SSH-2.0-OpenSSH_7.9"},
            80: {"name": "HTTP", "version": "Apache/2.4.38", "banner": "Apache/2.4.38 (Debian)"},
            3306: {"name": "MySQL", "version": "5.7.29", "banner": "5.7.29-0ubuntu0.18.04.1"}
        },
        "os": "Linux 4.19.0",
        "users": ["root", "admin", "user", "test", "service"],
        "files": ["passwords.txt", "config.php", "backup.sql"]
    },
    "smb_server": {
        "ip": "172.16.0.60",
        "hostname": "smb-server",
        "services": {
            139: {"name": "NetBIOS", "version": "Samba 4.9.5"},
            445: {"name": "SMB", "version": "SMBv2"}
        },
        "shares": ["public", "admin", "files", "backup"],
        "users": ["administrator", "guest", "john", "jane"]
    },
    "smtp_server": {
        "ip": "172.16.0.50",
        "hostname": "mail-server",
        "services": {
            25: {"name": "SMTP", "version": "Postfix 3.3.0"}
        },
        "users": ["postmaster", "admin", "info", "support", "sales"]
    }
}

def simulate_command(command):
    """Simulate command execution and return output"""
    output = ""
    
    # Parse command
    cmd_parts = command.strip().split()
    if not cmd_parts:
        return "No command entered"
    
    base_cmd = cmd_parts[0]
    
    # Simulate different commands
    if base_cmd == "nmap":
        output = simulate_nmap(cmd_parts)
    elif base_cmd == "ping":
        output = simulate_ping(cmd_parts)
    elif base_cmd == "nc" or base_cmd == "netcat":
        output = simulate_netcat(cmd_parts)
    elif base_cmd == "dig":
        output = simulate_dig(cmd_parts)
    elif base_cmd == "whois":
        output = simulate_whois(cmd_parts)
    elif base_cmd == "smbclient":
        output = simulate_smbclient(cmd_parts)
    elif base_cmd == "enum4linux":
        output = simulate_enum4linux(cmd_parts)
    elif base_cmd == "ls":
        output = "file1.txt\nfile2.conf\nsecret.key\nbackup.tar.gz"
    elif base_cmd == "cat":
        output = simulate_cat(cmd_parts)
    elif base_cmd == "help":
        output = """Available commands:
- nmap: Port scanning
- ping: Test connectivity
- nc/netcat: Network connections
- dig: DNS queries
- whois: Domain information
- smbclient: SMB enumeration
- enum4linux: SMB/Samba enumeration
- ls: List files
- cat: Read files"""
    else:
        output = f"Command '{base_cmd}' not found. Type 'help' for available commands."
    
    return output

def simulate_nmap(cmd_parts):
    """Simulate nmap output"""
    if len(cmd_parts) < 2:
        return "Usage: nmap [options] <target>"
    
    target_ip = cmd_parts[-1]
    
    # Check if it's a known target
    for target_name, target_data in TARGETS.items():
        if target_ip == target_data["ip"]:
            output = f"""Starting Nmap scan against {target_ip}
Host is up (0.00042s latency).

PORT     STATE SERVICE    VERSION"""
            for port, service in target_data["services"].items():
                output += f"\n{port}/tcp  open  {service['name'].lower():10} {service['version']}"
            
            if "os" in target_data:
                output += f"\n\nOS detection: {target_data['os']}"
            
            return output
    
    return f"Note: {target_ip} is not responding (simulated environment)"

def simulate_ping(cmd_parts):
    """Simulate ping output"""
    if len(cmd_parts) < 2:
        return "Usage: ping <target>"
    
    target = cmd_parts[1]
    for target_name, target_data in TARGETS.items():
        if target == target_data["ip"] or target == target_data["hostname"]:
            return f"""PING {target} ({target_data['ip']}): 56 data bytes
64 bytes from {target_data['ip']}: icmp_seq=0 ttl=64 time=0.432 ms
64 bytes from {target_data['ip']}: icmp_seq=1 ttl=64 time=0.398 ms
64 bytes from {target_data['ip']}: icmp_seq=2 ttl=64 time=0.412 ms

--- {target} ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss"""
    
    return f"ping: cannot resolve {target}: Unknown host"

def simulate_netcat(cmd_parts):
    """Simulate netcat banner grabbing"""
    if len(cmd_parts) < 3:
        return "Usage: nc <target> <port>"
    
    target = cmd_parts[1]
    try:
        port = int(cmd_parts[2])
    except:
        return "Invalid port number"
    
    for target_name, target_data in TARGETS.items():
        if target == target_data["ip"]:
            if port in target_data["services"]:
                service = target_data["services"][port]
                return f"Connected to {target}.\n{service.get('banner', service['name'] + ' Service Banner')}"
            else:
                return f"Connection to {target} {port} port failed: Connection refused"
    
    return f"nc: connect to {target} port {port} (tcp) failed: No route to host"

def simulate_dig(cmd_parts):
    """Simulate dig DNS queries"""
    domain = "megacorpone.com" if len(cmd_parts) < 2 else cmd_parts[1]
    
    return f"""; <<>> DiG 9.16.1 <<>> {domain}
;; QUESTION SECTION:
;{domain}.                    IN      A

;; ANSWER SECTION:
{domain}.             300     IN      A       172.16.0.40
{domain}.             300     IN      MX      10 mail.{domain}.
{domain}.             300     IN      NS      ns1.{domain}.
{domain}.             300     IN      NS      ns2.{domain}.

;; Query time: 28 msec
;; SERVER: 172.16.0.30#53(172.16.0.30)"""

def simulate_whois(cmd_parts):
    """Simulate whois output"""
    domain = "megacorpone.com" if len(cmd_parts) < 2 else cmd_parts[1]
    
    return f"""Domain Name: {domain.upper()}
Registrar: SimulatedRegistrar, Inc.
Creation Date: 2010-01-15T00:00:00Z
Registry Expiry Date: 2025-01-15T00:00:00Z

Registrant Organization: MegaCorp One
Registrant Street: 123 Corporate Blvd
Registrant City: Tech City
Registrant Country: US
Registrant Email: admin@{domain}

Name Server: ns1.{domain}
Name Server: ns2.{domain}

DNSSEC: unsigned"""

def simulate_smbclient(cmd_parts):
    """Simulate smbclient output"""
    target = TARGETS["smb_server"]
    
    return f"""
    Sharename       Type      Comment
    ---------       ----      -------
    public          Disk      Public Share
    admin           Disk      Admin Only
    files           Disk      Company Files
    backup          Disk      Backup Storage
    IPC$            IPC       IPC Service

SMB1 disabled -- no workgroup available"""

def simulate_enum4linux(cmd_parts):
    """Simulate enum4linux output"""
    target = TARGETS["smb_server"]
    
    return f"""Starting enum4linux v0.8.9
Target Information:
    Target ........... {target['ip']}
    Username ......... ''
    
Share Enumeration on {target['ip']}:
    public          Disk      Public Share
    admin           Disk      Admin Only (Access Denied)
    files           Disk      Company Files
    
Users on {target['ip']}:
    administrator
    guest
    john
    jane
    
Groups on {target['ip']}:
    Domain Users
    Domain Admins
    Domain Guests"""

def simulate_cat(cmd_parts):
    """Simulate reading files"""
    if len(cmd_parts) < 2:
        return "Usage: cat <filename>"
    
    filename = cmd_parts[1]
    
    files = {
        "passwords.txt": "admin:password123\nuser:letmein\ntest:test123",
        "config.php": "<?php\n$db_host = 'localhost';\n$db_user = 'root';\n$db_pass = 'toor';\n?>",
        "secret.key": base64.b64encode(b"SuperSecretKey123!").decode(),
        "users.txt": "\n".join(["root", "admin", "user", "test", "www-data"])
    }
    
    return files.get(filename, f"cat: {filename}: No such file or directory")

# Main content area
def main():
    st.title("🎯 OSCP Lab Practice Environment")
    st.markdown("### Safe, Interactive Penetration Testing Training")
    
    # Lab content based on selection
    if "Lab 1" in lab_selection:
        show_lab1()
    elif "Lab 2" in lab_selection:
        show_lab2()
    elif "Lab 3" in lab_selection:
        show_lab3()
    elif "Lab 4" in lab_selection:
        show_lab4()
    elif "Lab 5" in lab_selection:
        show_lab5()

def show_lab1():
    """Lab 1: Kali Linux Fundamentals"""
    st.header("Lab 1: Kali Linux Fundamentals")
    
    tab1, tab2, tab3, tab4 = st.tabs(["📚 Tutorial", "💻 Terminal", "🎯 Challenges", "📊 Progress"])
    
    with tab1:
        st.markdown("""
        ### Learning Objectives
        - Master Linux command line basics
        - Understand file system navigation
        - Learn service management
        - Write basic bash scripts
        
        ### Key Commands
        ```bash
        # Navigation
        ls -la          # List all files with details
        cd /path        # Change directory
        pwd             # Print working directory
        
        # File operations
        cat file.txt    # Read file content
        grep pattern    # Search for patterns
        find / -name    # Find files
        
        # Network basics
        ifconfig        # Network interfaces
        netstat -an     # Network connections
        ss -tlnp        # Socket statistics
        ```
        
        ### Exercise 1.1: File System Navigation
        Try these commands in the terminal:
        1. List all files: `ls -la`
        2. Read a file: `cat passwords.txt`
        3. Search for users: `cat users.txt | grep admin`
        """)
    
    with tab2:
        st.subheader("Interactive Terminal")
        
        # Command input
        command = st.text_input("Enter command:", key="lab1_cmd")
        
        if st.button("Execute", key="lab1_exec"):
            if command:
                output = simulate_command(command)
                st.session_state.terminal_output.append(f"$ {command}\n{output}")
        
        # Terminal display
        terminal_content = "\n".join(st.session_state.terminal_output[-10:])  # Show last 10 commands
        st.markdown(f'<div class="terminal">{terminal_content}</div>', unsafe_allow_html=True)
        
        if st.button("Clear Terminal", key="lab1_clear"):
            st.session_state.terminal_output = []
            st.experimental_rerun()
    
    with tab3:
        st.subheader("Challenges")
        
        # Challenge 1
        with st.expander("🏆 Challenge 1: Find the Password"):
            st.write("A password file exists in the system. Find and read it!")
            
            answer1 = st.text_input("Enter the password for 'admin':", key="lab1_c1")
            
            if st.button("Submit", key="lab1_c1_submit"):
                if answer1 == "password123":
                    st.success("✅ Correct! You found the admin password!")
                    if "lab1_c1" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("lab1_c1")
                        st.session_state.score += 10
                else:
                    st.error("❌ Try again! Hint: Use 'cat passwords.txt'")
        
        # Challenge 2
        with st.expander("🏆 Challenge 2: Count the Users"):
            st.write("How many users are in the users.txt file?")
            
            answer2 = st.number_input("Number of users:", min_value=0, max_value=10, key="lab1_c2")
            
            if st.button("Submit", key="lab1_c2_submit"):
                if answer2 == 5:
                    st.success("✅ Correct! There are 5 users in the file!")
                    if "lab1_c2" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("lab1_c2")
                        st.session_state.score += 10
                else:
                    st.error("❌ Try again! Hint: Use 'cat users.txt' and count")
    
    with tab4:
        st.subheader("Your Progress")
        
        lab1_exercises = ["lab1_c1", "lab1_c2"]
        completed = [ex for ex in lab1_exercises if ex in st.session_state.completed_exercises]
        
        progress_df = pd.DataFrame({
            "Exercise": ["Find Password", "Count Users"],
            "Status": ["✅ Completed" if f"lab1_c{i+1}" in completed else "⏳ Pending" for i in range(2)],
            "Points": [10, 10]
        })
        
        st.dataframe(progress_df)
        st.write(f"Lab 1 Completion: {len(completed)}/2 exercises")

def show_lab2():
    """Lab 2: Essential Tools"""
    st.header("Lab 2: Essential Tools Workshop")
    
    tab1, tab2, tab3, tab4 = st.tabs(["📚 Tutorial", "💻 Terminal", "🎯 Challenges", "📊 Progress"])
    
    with tab1:
        st.markdown("""
        ### Learning Objectives
        - Master Netcat for connections and transfers
        - Understand packet capture basics
        - Learn port scanning techniques
        - Use network analysis tools
        
        ### Key Tools
        
        #### Netcat - The Swiss Army Knife
        ```bash
        # Connect to a port
        nc target_ip 80
        
        # Listen on a port
        nc -lvnp 4444
        
        # Banner grabbing
        nc -nv target_ip 22
        ```
        
        #### Port Scanning
        ```bash
        # Basic nmap scan
        nmap target_ip
        
        # Service version scan
        nmap -sV target_ip
        
        # Full port scan
        nmap -p- target_ip
        ```
        
        ### Exercise 2.1: Banner Grabbing
        Use netcat to grab service banners from different ports!
        """)
    
    with tab2:
        st.subheader("Network Tools Terminal")
        
        command = st.text_input("Enter command:", key="lab2_cmd")
        
        if st.button("Execute", key="lab2_exec"):
            if command:
                output = simulate_command(command)
                st.session_state.terminal_output.append(f"$ {command}\n{output}")
        
        terminal_content = "\n".join(st.session_state.terminal_output[-10:])
        st.markdown(f'<div class="terminal">{terminal_content}</div>', unsafe_allow_html=True)
        
        if st.button("Clear Terminal", key="lab2_clear"):
            st.session_state.terminal_output = []
            st.experimental_rerun()
        
        # Quick commands
        st.markdown("### Quick Commands")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("Scan Linux Target"):
                output = simulate_command("nmap 172.16.0.20")
                st.session_state.terminal_output.append(f"$ nmap 172.16.0.20\n{output}")
                st.experimental_rerun()
        
        with col2:
            if st.button("Grab SSH Banner"):
                output = simulate_command("nc 172.16.0.20 22")
                st.session_state.terminal_output.append(f"$ nc 172.16.0.20 22\n{output}")
                st.experimental_rerun()
        
        with col3:
            if st.button("Test Connectivity"):
                output = simulate_command("ping 172.16.0.20")
                st.session_state.terminal_output.append(f"$ ping 172.16.0.20\n{output}")
                st.experimental_rerun()
    
    with tab3:
        st.subheader("Network Challenges")
        
        # Challenge 1
        with st.expander("🏆 Challenge 1: Identify the Web Server"):
            st.write("What web server software is running on 172.16.0.20?")
            
            answer = st.selectbox("Select the web server:", 
                                 ["", "nginx", "Apache", "IIS", "Tomcat"], 
                                 key="lab2_c1")
            
            if st.button("Submit", key="lab2_c1_submit"):
                if answer == "Apache":
                    st.success("✅ Correct! Apache/2.4.38 is running!")
                    if "lab2_c1" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("lab2_c1")
                        st.session_state.score += 15
                else:
                    st.error("❌ Try again! Hint: Use 'nmap -sV 172.16.0.20'")
        
        # Challenge 2
        with st.expander("🏆 Challenge 2: Count Open Ports"):
            st.write("How many ports are open on 172.16.0.20?")
            
            answer = st.number_input("Number of open ports:", 
                                    min_value=0, max_value=10, 
                                    key="lab2_c2")
            
            if st.button("Submit", key="lab2_c2_submit"):
                if answer == 3:
                    st.success("✅ Correct! Ports 22, 80, and 3306 are open!")
                    if "lab2_c2" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("lab2_c2")
                        st.session_state.score += 15
                else:
                    st.error("❌ Try again! Hint: Use 'nmap 172.16.0.20'")
    
    with tab4:
        st.subheader("Lab 2 Progress")
        
        lab2_exercises = ["lab2_c1", "lab2_c2"]
        completed = [ex for ex in lab2_exercises if ex in st.session_state.completed_exercises]
        
        progress_df = pd.DataFrame({
            "Exercise": ["Identify Web Server", "Count Open Ports"],
            "Status": ["✅ Completed" if f"lab2_c{i+1}" in completed else "⏳ Pending" for i in range(2)],
            "Points": [15, 15]
        })
        
        st.dataframe(progress_df)
        st.write(f"Lab 2 Completion: {len(completed)}/2 exercises")

def show_lab3():
    """Lab 3: Passive Reconnaissance"""
    st.header("Lab 3: Passive Information Gathering")
    
    tab1, tab2, tab3, tab4 = st.tabs(["📚 Tutorial", "🔍 OSINT Tools", "🎯 Challenges", "📊 Progress"])
    
    with tab1:
        st.markdown("""
        ### Learning Objectives
        - Perform passive reconnaissance
        - Use WHOIS and DNS queries
        - Gather information without touching the target
        - Build target profiles
        
        ### Passive Recon Techniques
        
        #### DNS Enumeration
        ```bash
        # DNS queries
        dig megacorpone.com
        dig megacorpone.com MX
        dig megacorpone.com NS
        
        # Reverse DNS
        dig -x 172.16.0.40
        ```
        
        #### WHOIS Lookups
        ```bash
        whois megacorpone.com
        whois 172.16.0.0
        ```
        
        ### Google Dorking
        ```
        site:megacorpone.com filetype:pdf
        site:megacorpone.com inurl:admin
        site:megacorpone.com intext:password
        ```
        """)
    
    with tab2:
        st.subheader("OSINT Tools")
        
        tool = st.selectbox("Select Tool:", ["WHOIS", "DIG", "Google Dorks Generator"])
        
        if tool == "WHOIS":
            domain = st.text_input("Enter domain:", "megacorpone.com")
            if st.button("Lookup"):
                output = simulate_whois(["whois", domain])
                st.code(output)
        
        elif tool == "DIG":
            domain = st.text_input("Enter domain:", "megacorpone.com")
            record_type = st.selectbox("Record Type:", ["A", "MX", "NS", "TXT", "ANY"])
            if st.button("Query"):
                output = simulate_dig(["dig", domain, record_type])
                st.code(output)
        
        elif tool == "Google Dorks Generator":
            st.write("Generate Google dork queries:")
            domain = st.text_input("Target domain:", "megacorpone.com")
            
            dork_type = st.multiselect("Select dork types:", 
                                       ["Files", "Login Pages", "Directories", "Errors"])
            
            if st.button("Generate Dorks"):
                dorks = []
                if "Files" in dork_type:
                    dorks.extend([
                        f"site:{domain} filetype:pdf",
                        f"site:{domain} filetype:doc",
                        f"site:{domain} filetype:xls"
                    ])
                if "Login Pages" in dork_type:
                    dorks.extend([
                        f"site:{domain} inurl:login",
                        f"site:{domain} inurl:admin",
                        f"site:{domain} intitle:login"
                    ])
                if "Directories" in dork_type:
                    dorks.extend([
                        f"site:{domain} intitle:index.of",
                        f"site:{domain} inurl:backup"
                    ])
                if "Errors" in dork_type:
                    dorks.extend([
                        f"site:{domain} intext:error",
                        f"site:{domain} intext:'sql syntax'"
                    ])
                
                st.code("\n".join(dorks))
    
    with tab3:
        st.subheader("OSINT Challenges")
        
        # Challenge 1
        with st.expander("🏆 Challenge 1: Find the Mail Server"):
            st.write("What is the mail server for megacorpone.com?")
            
            answer = st.text_input("Mail server:", key="lab3_c1")
            
            if st.button("Submit", key="lab3_c1_submit"):
                if "mail.megacorpone.com" in answer.lower():
                    st.success("✅ Correct! The MX record points to mail.megacorpone.com")
                    if "lab3_c1" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("lab3_c1")
                        st.session_state.score += 20
                else:
                    st.error("❌ Try again! Hint: Use 'dig megacorpone.com MX'")
        
        # Challenge 2
        with st.expander("🏆 Challenge 2: Identify the Registrar"):
            st.write("Who is the registrar for megacorpone.com?")
            
            answer = st.text_input("Registrar name:", key="lab3_c2")
            
            if st.button("Submit", key="lab3_c2_submit"):
                if "simulatedregistrar" in answer.lower():
                    st.success("✅ Correct! SimulatedRegistrar, Inc. is the registrar!")
                    if "lab3_c2" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("lab3_c2")
                        st.session_state.score += 20
                else:
                    st.error("❌ Try again! Hint: Use 'whois megacorpone.com'")
    
    with tab4:
        st.subheader("Lab 3 Progress")
        
        lab3_exercises = ["lab3_c1", "lab3_c2"]
        completed = [ex for ex in lab3_exercises if ex in st.session_state.completed_exercises]
        
        progress_df = pd.DataFrame({
            "Exercise": ["Find Mail Server", "Identify Registrar"],
            "Status": ["✅ Completed" if f"lab3_c{i+1}" in completed else "⏳ Pending" for i in range(2)],
            "Points": [20, 20]
        })
        
        st.dataframe(progress_df)
        st.write(f"Lab 3 Completion: {len(completed)}/2 exercises")

def show_lab4():
    """Lab 4: Active Reconnaissance"""
    st.header("Lab 4: Active Information Gathering")
    
    tab1, tab2, tab3, tab4 = st.tabs(["📚 Tutorial", "🔍 Scanning Tools", "🎯 Challenges", "📊 Progress"])
    
    with tab1:
        st.markdown("""
        ### Learning Objectives
        - Perform comprehensive port scanning
        - Identify running services
        - Detect operating systems
        - Map network topology
        
        ### Active Scanning Techniques
        
        #### Nmap Scanning
        ```bash
        # Basic scan
        nmap target_ip
        
        # Service version detection
        nmap -sV target_ip
        
        # OS detection
        nmap -O target_ip
        
        # Aggressive scan
        nmap -A target_ip
        
        # Full port scan
        nmap -p- target_ip
        
        # UDP scan
        nmap -sU target_ip
        ```
        
        #### Scan Types
        - **TCP Connect Scan** (-sT): Full connection
        - **SYN Scan** (-sS): Stealth scan
        - **UDP Scan** (-sU): UDP services
        - **Version Scan** (-sV): Service versions
        - **OS Scan** (-O): Operating system
        
        ### Target Network
        - Linux Target: 172.16.0.20
        - SMB Server: 172.16.0.60
        - SMTP Server: 172.16.0.50
        """)
    
    with tab2:
        st.subheader("Network Scanner")
        
        # Target selection
        target = st.selectbox("Select Target:", 
                            ["172.16.0.20 (Linux)", 
                             "172.16.0.60 (SMB)", 
                             "172.16.0.50 (SMTP)",
                             "172.16.0.0/24 (Full Network)"])
        
        scan_type = st.selectbox("Scan Type:", 
                                ["Quick Scan", 
                                 "Service Detection", 
                                 "OS Detection", 
                                 "Full Port Scan"])
        
        if st.button("Start Scan"):
            target_ip = target.split()[0]
            
            with st.spinner("Scanning... This may take a moment"):
                time.sleep(2)  # Simulate scan time
                
                if scan_type == "Quick Scan":
                    output = simulate_command(f"nmap {target_ip}")
                elif scan_type == "Service Detection":
                    output = simulate_command(f"nmap -sV {target_ip}")
                else:
                    output = simulate_command(f"nmap -A {target_ip}")
                
                st.code(output)
                
                # Save to session
                if "scan_results" not in st.session_state:
                    st.session_state.scan_results = []
                st.session_state.scan_results.append({
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "target": target_ip,
                    "type": scan_type
                })
        
        # Scan history
        if "scan_results" in st.session_state and st.session_state.scan_results:
            st.subheader("Scan History")
            history_df = pd.DataFrame(st.session_state.scan_results)
            st.dataframe(history_df)
    
    with tab3:
        st.subheader("Scanning Challenges")
        
        # Challenge 1
        with st.expander("🏆 Challenge 1: Find the MySQL Port"):
            st.write("What port is MySQL running on 172.16.0.20?")
            
            answer = st.number_input("Port number:", min_value=0, max_value=65535, key="lab4_c1")
            
            if st.button("Submit", key="lab4_c1_submit"):
                if answer == 3306:
                    st.success("✅ Correct! MySQL is on port 3306!")
                    if "lab4_c1" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("lab4_c1")
                        st.session_state.score += 25
                else:
                    st.error("❌ Try again! Hint: Scan 172.16.0.20")
        
        # Challenge 2
        with st.expander("🏆 Challenge 2: Identify the OS"):
            st.write("What operating system is running on 172.16.0.20?")
            
            answer = st.selectbox("Select OS:", 
                                 ["", "Windows", "Linux", "FreeBSD", "MacOS"], 
                                 key="lab4_c2")
            
            if st.button("Submit", key="lab4_c2_submit"):
                if answer == "Linux":
                    st.success("✅ Correct! It's running Linux!")
                    if "lab4_c2" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("lab4_c2")
                        st.session_state.score += 25
                else:
                    st.error("❌ Try again! Hint: Look at the service versions")
    
    with tab4:
        st.subheader("Lab 4 Progress")
        
        lab4_exercises = ["lab4_c1", "lab4_c2"]
        completed = [ex for ex in lab4_exercises if ex in st.session_state.completed_exercises]
        
        progress_df = pd.DataFrame({
            "Exercise": ["Find MySQL Port", "Identify OS"],
            "Status": ["✅ Completed" if f"lab4_c{i+1}" in completed else "⏳ Pending" for i in range(2)],
            "Points": [25, 25]
        })
        
        st.dataframe(progress_df)
        st.write(f"Lab 4 Completion: {len(completed)}/2 exercises")

def show_lab5():
    """Lab 5: SMB/SMTP Enumeration"""
    st.header("Lab 5: SMB/SMTP Enumeration")
    
    tab1, tab2, tab3, tab4 = st.tabs(["📚 Tutorial", "🔧 Enum Tools", "🎯 Challenges", "📊 Progress"])
    
    with tab1:
        st.markdown("""
        ### Learning Objectives
        - Enumerate SMB shares and users
        - Perform SMTP user enumeration
        - Use specialized enumeration tools
        - Identify service vulnerabilities
        
        ### SMB Enumeration
        ```bash
        # List shares
        smbclient -L //target_ip -N
        
        # Enumerate with enum4linux
        enum4linux -a target_ip
        
        # Connect to share
        smbclient //target_ip/share -N
        ```
        
        ### SMTP Enumeration
        ```bash
        # VRFY command
        nc target_ip 25
        VRFY username
        
        # EXPN command
        EXPN username
        
        # RCPT TO
        MAIL FROM: test@test.com
        RCPT TO: user@target.com
        ```
        
        ### Target Services
        - SMB Server: 172.16.0.60 (ports 139, 445)
        - SMTP Server: 172.16.0.50 (port 25)
        """)
    
    with tab2:
        st.subheader("Service Enumeration Tools")
        
        service = st.selectbox("Select Service:", ["SMB", "SMTP"])
        
        if service == "SMB":
            tool = st.selectbox("Select Tool:", ["smbclient", "enum4linux"])
            
            if tool == "smbclient":
                if st.button("List Shares"):
                    output = simulate_smbclient(["smbclient", "-L", "//172.16.0.60"])
                    st.code(output)
            
            elif tool == "enum4linux":
                if st.button("Run Enumeration"):
                    output = simulate_enum4linux(["enum4linux", "172.16.0.60"])
                    st.code(output)
        
        elif service == "SMTP":
            st.write("SMTP User Enumeration")
            
            users_to_test = st.text_area("Users to test (one per line):", 
                                         "admin\nroot\npostmaster\nsupport")
            
            if st.button("Enumerate Users"):
                users = users_to_test.split("\n")
                results = []
                
                smtp_users = TARGETS["smtp_server"]["users"]
                
                for user in users:
                    if user.strip() in smtp_users:
                        results.append(f"[+] {user}: Valid user")
                    else:
                        results.append(f"[-] {user}: User not found")
                
                st.code("\n".join(results))
    
    with tab3:
        st.subheader("Service Enumeration Challenges")
        
        # Challenge 1
        with st.expander("🏆 Challenge 1: Find SMB Shares"):
            st.write("How many shares are available on 172.16.0.60?")
            
            answer = st.number_input("Number of shares:", min_value=0, max_value=10, key="lab5_c1")
            
            if st.button("Submit", key="lab5_c1_submit"):
                if answer == 4:
                    st.success("✅ Correct! There are 4 shares (public, admin, files, backup)!")
                    if "lab5_c1" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("lab5_c1")
                        st.session_state.score += 30
                else:
                    st.error("❌ Try again! Hint: Use smbclient to list shares")
        
        # Challenge 2
        with st.expander("🏆 Challenge 2: Find Valid SMTP User"):
            st.write("Which of these is a valid SMTP user: admin, postmaster, or root?")
            
            answer = st.selectbox("Select valid user:", 
                                 ["", "admin", "postmaster", "root"], 
                                 key="lab5_c2")
            
            if st.button("Submit", key="lab5_c2_submit"):
                if answer == "postmaster":
                    st.success("✅ Correct! Postmaster is a valid user!")
                    if "lab5_c2" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("lab5_c2")
                        st.session_state.score += 30
                else:
                    st.error("❌ Try again! Hint: Test users with SMTP enumeration")
        
        # Final Challenge
        with st.expander("🏆 Final Challenge: Complete Assessment"):
            st.write("Based on all your reconnaissance, answer these questions:")
            
            q1 = st.selectbox("1. Primary web server software?", 
                            ["", "Apache", "nginx", "IIS"], key="final_q1")
            
            q2 = st.number_input("2. Total open ports on 172.16.0.20?", 
                                min_value=0, max_value=10, key="final_q2")
            
            q3 = st.selectbox("3. SMB server has public share?", 
                            ["", "Yes", "No"], key="final_q3")
            
            if st.button("Submit Final Assessment"):
                score = 0
                if q1 == "Apache":
                    score += 1
                if q2 == 3:
                    score += 1
                if q3 == "Yes":
                    score += 1
                
                if score == 3:
                    st.success(f"🎉 Perfect! You've mastered all enumeration techniques!")
                    if "final_assessment" not in st.session_state.completed_exercises:
                        st.session_state.completed_exercises.append("final_assessment")
                        st.session_state.score += 50
                else:
                    st.warning(f"You got {score}/3 correct. Review previous labs and try again!")
    
    with tab4:
        st.subheader("Lab 5 Progress")
        
        lab5_exercises = ["lab5_c1", "lab5_c2", "final_assessment"]
        completed = [ex for ex in lab5_exercises if ex in st.session_state.completed_exercises]
        
        progress_df = pd.DataFrame({
            "Exercise": ["Find SMB Shares", "Find SMTP User", "Final Assessment"],
            "Status": ["✅ Completed" if ex in completed else "⏳ Pending" for ex in lab5_exercises],
            "Points": [30, 30, 50]
        })
        
        st.dataframe(progress_df)
        st.write(f"Lab 5 Completion: {len(completed)}/3 exercises")
        
        if len(completed) == 3:
            st.balloons()
            st.success("🎉 Congratulations! You've completed all OSCP labs!")

# Footer
def footer():
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("### 📊 Overall Statistics")
        total_exercises = 11
        completed = len(st.session_state.completed_exercises)
        st.write(f"Completed: {completed}/{total_exercises}")
        st.write(f"Total Score: {st.session_state.score} points")
    
    with col2:
        st.markdown("### 🏆 Achievements")
        if st.session_state.score >= 200:
            st.write("🥇 OSCP Master")
        elif st.session_state.score >= 150:
            st.write("🥈 Advanced Pentester")
        elif st.session_state.score >= 100:
            st.write("🥉 Security Analyst")
        else:
            st.write("🎯 Keep practicing!")
    
    with col3:
        st.markdown("### 💡 Tips")
        tips = [
            "Try different scanning techniques",
            "Always enumerate thoroughly",
            "Document your findings",
            "Practice makes perfect!"
        ]
        st.write(random.choice(tips))
    
    st.markdown("---")
    st.markdown("*Built with ❤️ for OSCP preparation | Safe practice environment*")

if __name__ == "__main__":
    main()
    footer()