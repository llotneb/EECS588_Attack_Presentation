inject: inject.cpp process_packet.cpp process_packet.h Makefile
	g++ inject.cpp process_packet.cpp -pthread --std=c++11 -lnetfilter_queue -o inject -g

clean:
	rm -f inject
