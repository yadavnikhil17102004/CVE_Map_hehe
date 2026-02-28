#!/bin/bash

# Define colors for output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}[*] Starting CVE Map Local Testing Server...${NC}"
echo -e "${GREEN}[+] Serving files at http://localhost:8000${NC}"
echo -e "${CYAN}[*] Press Ctrl+C to stop the server.${NC}"

# Open the browser automatically (works on macOS)
sleep 1 && open "http://localhost:8000" &

# Start the Python 3 built-in HTTP server
python3 -m http.server 8000
