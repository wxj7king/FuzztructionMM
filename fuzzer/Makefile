CXX = g++
CXXFLAGS = -Wall -g -O3 -std=c++2a #-fsanitize=address
LIBS = -lssl -lcrypto -lpthread -lrt

MYHEADERS_H = -I.

fuzzer: src/worker.o src/main.o 
	$(CXX) $(CXXFLAGS) -o $@ src/main.o src/worker.o $(LIBS)

src/worker.o: src/worker.cc
	$(CXX) $(CXXFLAGS) $(MYHEADERS_H) -c -o $@ src/worker.cc 

src/main.o: src/main.cc
	$(CXX) $(CXXFLAGS) $(MYHEADERS_H) -c -o $@ src/main.cc

clean: 
	rm -f ./fuzzer
	rm -f src/worker.o
	rm -f src/main.o
	rm -f dep_config.json
	rm -f pin.log
