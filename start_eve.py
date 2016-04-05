# This script starts Eve, the packet detector
import os

# Basic iptables set-up
os.system("sudo ./stoptables.sh")

# Configure the UNIX Kernel to queue all input packets from $HOST
# on queue 0.
arg = "127.0.0.1"
os.system("sudo iptables -A INPUT -s " + arg + " -j NFQUEUE --queue-num 0")

try:
    f = open("inject")
    f.close()
except IOError as e:
    os.system("make")
os.system("sudo ./inject 0 detect")
