CXX = g++
CXXFLAGS = -shared -Wall -g -O3 -fPIC #-fsanitize=address
AFLPP_INCLUDE = -I /home/proj/proj/AFLplusplus/include

inject_ts.so: inject_ts.cc
	$(CXX) $(CXXFLAGS) $(AFLPP_INCLUDE) -o $@ inject_ts.cc

clean:
	rm ./inject_ts.so