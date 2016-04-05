# This script starts Mallory, the packet injector

# Using the iptables API, tell the UNIX Kernel to take all packets
# leaving from tcp port 80 (HTTP) and queue them on queue 0
# for analysis.
sudo iptables -A OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0

if [ ! -e "inject" ]
then
    make
fi

# Queue 0, inject, two client connections, period of 1(s).
# Slow speed is 10, fast speed is 150.
# Look for the username Satoshi in log files.
./inject 0 inject 2 1 10 150 satoshi
