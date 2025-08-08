#!/bin/bash

# Script to run real walkthrough demonstration
# Executes actual commands against the lab environment

echo "================================================"
echo "   Running Real Lab Demonstration"
echo "   This will perform actual scans and exploits"
echo "================================================"
echo ""

# First, copy the walkthrough script to the server
echo "Uploading walkthrough script to server..."
scp real-lab-walkthrough.sh oscpuser2@155.138.197.128:/tmp/

# Now run it inside the container
echo "Executing walkthrough inside Kali container..."
ssh oscpuser2@155.138.197.128 << 'ENDSSH'
# Copy script into container
docker cp /tmp/real-lab-walkthrough.sh kali-user2:/tmp/

# Execute the walkthrough
docker exec -it kali-user2 bash -c "chmod +x /tmp/real-lab-walkthrough.sh && /tmp/real-lab-walkthrough.sh"
ENDSSH

echo ""
echo "Demonstration complete!"