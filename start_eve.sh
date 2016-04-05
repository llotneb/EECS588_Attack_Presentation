# This script starts Eve, the packet detector
if [ ! -e "inject" ]
then
    make
fi
./inject 0 detect
