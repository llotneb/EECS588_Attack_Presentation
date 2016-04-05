# This script starts Mallory, the packet injector

# Basic iptables set-up
sudo ./stoptables.sh

# Using the iptables API, tell the UNIX Kernel to take all packets
# leaving from tcp port 80 (HTTP) and queue them on queue 0
# for analysis.

if [ ! -e "inject" ]
then
    make
fi

# Queue 0, inject, two client connections, period of 1(s).
# Slow speed is 10, fast speed is 150.
# Look for the username Satoshi in log files.
sudo ./inject 0 inject 2 1 10 150 satoshi
