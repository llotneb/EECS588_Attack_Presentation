inject: inject.cpp
	g++ inject.cpp --std=c++11 -lnetfilter_queue -o inject
