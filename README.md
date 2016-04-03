#Tor Deanonymizer
Mallory (injector) and Eve (detector) have been tested on Ubuntu 14.04.

## Dependencies
g++ 4.8.4

libnetfilter-queue-dev 1.0.2

## Starting client
The victim of our traffic analysis attack starts his Tor browser.

## Starting "Mallory"
On the server, run:
```
    ./capoutput.sh
    sudo ./inject 0 inject 0.1 0.05 0
```

## Starting "Eve"
Find the guard node, the client's entry point into the tor network.
```
    sudo netstat -tup | grep tor
    sudo netstat -tupn | grep tor
```

Run the following commands to detect packets.
```
    sudo iptables -A INPUT -p tcp -s [IP_ADDRESS] -j NFQUEUE --queue-num 0
    sudo ./inject 0 detect
```    
