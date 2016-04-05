# This script starts Mallory, the packet injector
#     Queue 0, inject, two client connections, period of 1(s).
#     Slow speed is 10, fast speed is 150.
#     Look for the username Satoshi in log files.
sudo ./inject 0 inject 2 1 10 150 Satoshi
