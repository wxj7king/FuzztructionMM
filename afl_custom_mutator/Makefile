CXX = g++
CXXFLAGS = -shared -Wall -g -O3 -fPIC -std=c++2a #-fsanitize=address

inject_ts.so: inject_ts.cc
	$(CXX) $(CXXFLAGS) $(AFLPP_INCLUDE) -o $@ inject_ts.cc

clean:
	rm ./inject_ts.so