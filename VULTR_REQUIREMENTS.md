# 📊 Vultr Server Requirements for Realistic OSCP Lab

## Current Setup vs. Recommended Setup

### Your Current Vultr Server
- **Plan**: $12/month (if you chose the 2GB RAM option)
- **RAM**: 2GB
- **CPU**: 1 vCPU
- **Storage**: 50GB SSD
- **Network**: 2TB transfer

### What You Need for 10 Containers + 4 Kali

#### Minimum Requirements (Will Work But Slower)
- **Plan**: $12/month
- **RAM**: 2GB (tight but manageable)
- **CPU**: 1 vCPU
- **What to expect**:
  - Containers will run but may be sluggish
  - Scanning might take longer
  - Limited to 2 users at a time actively scanning

#### Recommended Requirements (Smooth Experience)
- **Plan**: $24/month ⭐ RECOMMENDED
- **RAM**: 4GB
- **CPU**: 2 vCPUs  
- **Storage**: 80GB SSD
- **What to expect**:
  - All 4 users can work simultaneously
  - Fast scanning and responses
  - No lag or timeouts

#### Optimal Requirements (Best Performance)
- **Plan**: $48/month
- **RAM**: 8GB
- **CPU**: 4 vCPUs
- **What to expect**:
  - Enterprise-level performance
  - Can add more services
  - Room for expansion

## 🔧 How to Upgrade Your Vultr Server

### Option 1: Resize Existing Server (Recommended)
```bash
# 1. Stop all containers first
docker-compose down

# 2. Go to Vultr dashboard
# 3. Click your server
# 4. Click "Settings" → "Change Plan"
# 5. Select $24/month (4GB RAM) plan
# 6. Click "Change Plan"
# 7. Server will resize (takes ~5 minutes)
# 8. Restart containers
docker-compose up -d
```

### Option 2: Create New Server
If resizing isn't available:
1. Create snapshot of current server
2. Deploy new $24/month server
3. Restore from snapshot
4. Update DNS/IPs as needed

## 💰 Cost Analysis

| Plan | Hourly | Daily | Weekly | Monthly | Performance |
|------|--------|-------|--------|---------|-------------|
| $12/month | $0.018 | $0.43 | $3.01 | $12 | Basic - Works |
| $24/month | $0.036 | $0.86 | $6.02 | $24 | **Recommended** |
| $48/month | $0.071 | $1.70 | $11.90 | $48 | Premium |

## 📈 Resource Usage by Component

### Per Container (Approximate)
| Container Type | RAM Usage | CPU Usage |
|----------------|-----------|-----------|
| Kali (x4) | 200MB each | 5-10% each |
| SSH Server | 50MB | 1% |
| DVWA | 150MB | 2-5% |
| FTP Server | 30MB | 1% |
| MySQL | 200MB | 2-5% |
| SMB/Samba | 100MB | 2% |
| Tomcat | 200MB | 5% |
| Redis | 50MB | 1% |
| PostgreSQL | 150MB | 2-5% |
| WordPress | 150MB | 3-5% |
| WebGoat | 300MB | 5-10% |
| **TOTAL** | **~2.5GB** | **~40-60%** |

## 🚀 Quick Upgrade Commands

### If you decide to upgrade to $24/month plan:

```bash
# After upgrading on Vultr dashboard, verify new resources:
free -h  # Should show 4GB RAM
nproc    # Should show 2 CPUs

# Then deploy the realistic lab:
cd /root
wget https://raw.githubusercontent.com/wonkastocks/oscp-vultr-lab/main/realistic-lab-setup.sh
chmod +x realistic-lab-setup.sh
./realistic-lab-setup.sh
```

## ⚡ Optimization Tips for $12/month Plan

If you want to stay with $12/month plan:

### Option 1: Run Fewer Targets
```bash
# Edit docker-compose.yml and comment out some targets
# Keep only 5-6 essential targets instead of 10
```

### Option 2: Limit Simultaneous Users
```bash
# Only start 2 Kali containers at a time
docker stop kali-user3 kali-user4
```

### Option 3: Use Lightweight Alternatives
Replace heavy containers with lighter versions:
- Use Alpine-based images where possible
- Reduce MySQL/PostgreSQL memory limits
- Disable unnecessary services

## 🎯 My Recommendation

**For learning OSCP with 4 users:**

1. **Upgrade to $24/month plan** (4GB RAM, 2 vCPUs)
   - Cost: $0.86/day
   - Smooth experience for all users
   - Room for all 10 targets
   - No performance issues

2. **Run the realistic lab setup**
   - 10 diverse targets
   - Multiple services per target
   - Realistic scanning experience
   - Various attack vectors

3. **Remember to destroy when done**
   - Don't forget to destroy the server
   - You only pay for hours used
   - Set a calendar reminder!

## 📞 Need Help?

If your server is struggling:
```bash
# Check resource usage
htop  # See RAM and CPU usage
docker stats  # See per-container usage
df -h  # Check disk space

# Restart containers if needed
docker-compose restart

# Or reduce load
docker stop [container-name]
```

## Summary

- **Current $12 plan**: Can work but will be tight with 14 containers
- **Recommended $24 plan**: Smooth experience for all users
- **Upgrade takes**: 5 minutes on Vultr dashboard
- **Extra cost**: Just $0.43 more per day
- **Worth it**: Yes, for realistic OSCP practice!