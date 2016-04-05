# This script starts Eve, the packet detector

# Configure the UNIX Kernel to queue all input packets from $HOST
# on queue 0.
HOST="127.0.0.1"
sudo iptables -A INPUT -s $HOST -j NFQUEUE --queue-num 0

if [ ! -e "inject" ]
then
    make
fi
./inject 0 detect
