Tor Deanonymizer

Install dependency:

    apt-get install libnetfilter-queue-dev

Find what packets to intercept with

    sudo netstat -tup | grep tor

or

    sudo netstat -tupn | grep tor

Then intercept packets with

    sudo iptables -A OUTPUT -d guard_node_ip -j NFQUEUE --queue-num 0

Intercept stuff to the server with

    sudo iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0


