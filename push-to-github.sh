#!/bin/bash

echo "================================================"
echo "     Push to GitHub - Manual Steps"
echo "================================================"
echo ""

# Check if we have the remote
if git remote | grep -q origin; then
    echo "✓ Remote 'origin' already exists"
else
    echo "Adding GitHub remote..."
    git remote add origin https://github.com/wonkastocks/oscp-vultr-lab.git
fi

echo ""
echo "Files ready to push:"
echo "-------------------"
git status --short

echo ""
echo "================================================"
echo "     AUTHENTICATION REQUIRED"
echo "================================================"
echo ""
echo "GitHub now requires a Personal Access Token (PAT) instead of password."
echo ""
echo "Steps to create a token:"
echo "1. Go to: https://github.com/settings/tokens"
echo "2. Click 'Generate new token (classic)'"
echo "3. Give it a name like 'oscp-lab-push'"
echo "4. Select scopes: 'repo' (full control)"
echo "5. Click 'Generate token'"
echo "6. COPY THE TOKEN (you won't see it again!)"
echo ""
echo "================================================"
echo ""
echo "Once you have your token, run:"
echo ""
echo "git push -u origin main"
echo ""
echo "When prompted:"
echo "  Username: wonkastocks"
echo "  Password: [PASTE YOUR TOKEN HERE]"
echo ""
echo "================================================"
echo ""
echo "Alternative: Use GitHub CLI"
echo "----------------------------"
echo "brew install gh"
echo "gh auth login"
echo "git push -u origin main"
echo ""
echo "================================================"