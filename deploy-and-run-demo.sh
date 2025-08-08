#!/bin/bash

# Deploy and run the automated demonstration on the Vultr server
# This script uploads and executes the demo for students to watch

echo "================================================"
echo "   Deploying Automated Demo to OSCP Lab"
echo "================================================"
echo ""

# Get the user number
read -p "Which user should run the demo? (1-4): " USER_NUM

if [[ ! "$USER_NUM" =~ ^[1-4]$ ]]; then
    echo "Invalid user number. Please enter 1, 2, 3, or 4"
    exit 1
fi

USER="oscpuser${USER_NUM}"
CONTAINER="kali-user${USER_NUM}"
PASSWORD="OscpLab${USER_NUM}!2024"

echo "Using $USER with container $CONTAINER"
echo ""

# Copy the demo script to the server
echo "📤 Uploading demo script to server..."
scp automated-demo-with-explanations.sh ${USER}@155.138.197.128:/home/${USER}/

if [ $? -ne 0 ]; then
    echo "❌ Failed to upload script. Please check your connection."
    echo "Password should be: $PASSWORD"
    exit 1
fi

# SSH to server and run the demo
echo "🚀 Starting automated demonstration..."
echo "Password: $PASSWORD"
echo ""

ssh ${USER}@155.138.197.128 << EOF
echo "📋 Copying demo script to container..."
docker cp /home/${USER}/automated-demo-with-explanations.sh ${CONTAINER}:/tmp/demo.sh

echo "🎬 Starting demonstration inside container..."
echo ""
docker exec -it ${CONTAINER} bash -c "chmod +x /tmp/demo.sh && /tmp/demo.sh"
EOF

echo ""
echo "================================================"
echo "   Demo Complete!"
echo "================================================"
echo ""
echo "Students can now try the commands manually by:"
echo "1. SSH to ${USER}@155.138.197.128"
echo "2. Run: ./start-lab.sh"
echo "3. Follow the commands they just saw!"