# 📦 Push to GitHub - Quick Setup

## Step 1: Create GitHub Repository

1. Go to [github.com](https://github.com)
2. Click the **"+"** icon (top right) → **"New repository"**
3. Name it: `oscp-vultr-lab` (or any name you want)
4. Set to **Public** (so you can access from Vultr)
5. DON'T initialize with README (we already have files)
6. Click **"Create repository"**

## Step 2: Connect and Push

After creating, GitHub will show you commands. Run these in your terminal:

```bash
cd ~/oscp-streamlit-deploy

# Add your GitHub repository as remote
git remote add origin https://github.com/YOUR_USERNAME/oscp-vultr-lab.git

# Push your code
git push -u origin main
```

If you get an authentication error, you might need a personal access token:
1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate new token (classic)
3. Use the token as your password when pushing

## Step 3: Your Files on GitHub

After pushing, you'll have these files available:

### Setup Scripts
- `quick-multi-user-deploy.sh` - Main setup script for Vultr
- `multi-user-setup.sh` - Detailed multi-user configuration
- `test-lab-setup.sh` - Validation script

### Documentation
- `USER_CREDENTIALS.txt` - User login information
- `SHARE_WITH_USERS.md` - Pretty version to share with students
- `MULTI_USER_INSTRUCTIONS.md` - Complete setup guide
- `STUDENT_WALKTHROUGH_LIVE.md` - What students will experience

### Apps
- `app.py` - Basic Streamlit app
- `app_enhanced.py` - Enhanced realistic simulation

## Step 4: Use from Vultr

Once on GitHub, you can easily deploy on your Vultr server:

```bash
ssh root@155.138.197.128

# Clone your repository
git clone https://github.com/YOUR_USERNAME/oscp-vultr-lab.git
cd oscp-vultr-lab

# Run setup
chmod +x quick-multi-user-deploy.sh
./quick-multi-user-deploy.sh

# Test everything
chmod +x test-lab-setup.sh
./test-lab-setup.sh
```

## Quick Commands

### If you want to use GitHub CLI instead:
```bash
# Install GitHub CLI (if not installed)
brew install gh

# Authenticate
gh auth login

# Create repo and push
gh repo create oscp-vultr-lab --public --source=. --push
```

## What's Next?

1. Create the GitHub repo
2. Push your code
3. SSH to Vultr
4. Clone and run setup
5. Share credentials with your 4 users
6. Start practicing!

---

Need the exact command? After creating your GitHub repo, just run:

```bash
git remote add origin https://github.com/YOUR_USERNAME/oscp-vultr-lab.git
git push -u origin main
```

Replace YOUR_USERNAME with your actual GitHub username!