#!/bin/bash

# Script to run the automated demo as root inside the Kali containers
# This ensures the demo has full privileges for all commands

echo "================================================"
echo "   OSCP Lab Demo Runner (Root Only)"
echo "================================================"
echo ""

# Check which container to run in
echo "Select which Kali container to run the demo in:"
echo "1) kali-user1"
echo "2) kali-user2" 
echo "3) kali-user3"
echo "4) kali-user4"
echo ""
read -p "Enter number (1-4): " CHOICE

case $CHOICE in
    1) CONTAINER="kali-user1" ;;
    2) CONTAINER="kali-user2" ;;
    3) CONTAINER="kali-user3" ;;
    4) CONTAINER="kali-user4" ;;
    *) echo "Invalid choice!"; exit 1 ;;
esac

echo ""
echo "Running demo in $CONTAINER as root..."
echo ""

# Check if container is running
if ! docker ps | grep -q $CONTAINER; then
    echo "❌ Container $CONTAINER is not running!"
    echo "Please start it first with: docker start $CONTAINER"
    exit 1
fi

# Download latest demo script into container
echo "📥 Downloading latest demo script from GitHub..."
docker exec $CONTAINER bash -c "
    cd /tmp
    wget -q https://raw.githubusercontent.com/wonkastocks/oscp-vultr-lab/main/automated-demo-with-explanations.sh
    chmod +x automated-demo-with-explanations.sh
"

if [ $? -ne 0 ]; then
    echo "❌ Failed to download demo script"
    exit 1
fi

echo "✅ Demo script ready"
echo ""
echo "🎬 Starting automated demonstration as root..."
echo "================================================"
echo ""

# Run the demo as root (containers run as root by default)
docker exec -it $CONTAINER /tmp/automated-demo-with-explanations.sh

echo ""
echo "================================================"
echo "   Demo Complete!"
echo "================================================"