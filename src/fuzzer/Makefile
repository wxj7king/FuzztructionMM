CXX = g++
CXXFLAGS = -Wall -O3 -std=c++2a
LIBS = -lssl -lcrypto

MYHEADERS_H = -I.
OPENSSL_INCLUDE_DIR = -I/home/proj/proj/uninstrumented/openssl/include
OPENSSL_LIB_DIR = -L/home/proj/proj/uninstrumented/openssl

fuzzer: src/worker.o src/main.o 
	$(CXX) $(CXXFLAGS) $(OPENSSL_INCLUDE_DIR) $(OPENSSL_LIB_DIR) -o $@ src/main.o src/worker.o $(LIBS)

src/worker.o: src/worker.cc
	$(CXX) $(CXXFLAGS) $(MYHEADERS_H) -c -o $@ src/worker.cc 

src/main.o: src/main.cc
	$(CXX) $(CXXFLAGS) $(MYHEADERS_H) -c -o $@ src/main.cc

clean: 
	rm -f ./fuzzer
	rm -f src/worker.o
	rm -f src/main.o
