inject: inject.cpp process_packet.cpp process_packet.h
	g++ inject.cpp process_packet.cpp --std=c++11 -lnetfilter_queue -o inject
