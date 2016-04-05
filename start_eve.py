#!/usr/bin/python
# This script starts Eve, the packet detector
import os
import re

# Basic iptables set-up
os.system("sudo ./stoptables.sh")

# Configure the UNIX Kernel to queue all input packets from $HOST
# on queue 0.

os.system('sudo netstat -tupn | grep tor > guardnodes')
guardf = open('guardnodes')
for line in guardf:
  m = re.match(r'tcp\s+\S+\s+\S+\s+\S+\s+([^\s:]+):\S+\s+', line)
  if m:
    ip = m.group(1)
    if ip != '127.0.0.1':
      print 'capturing ip ' + ip
      os.system("sudo iptables -A INPUT -s " + ip + " -j NFQUEUE --queue-num 0")
guardf.close()

try:
    f = open("inject")
    f.close()
except IOError as e:
    os.system("make")
os.system("sudo ./inject 0 detect")
