#g++ -O3 -o worker_afl_thread worker_withafl_thread.cc -I/home/proj/proj/uninstrumented/openssl/include/ -L/home/proj/proj/uninstrumented/openssl -lssl -lcrypto
g++ -O3 -o worker_afl_thread2 worker_withafl_thread2.cc -I/home/proj/proj/uninstrumented/openssl/include/ -L/home/proj/proj/uninstrumented/openssl -lssl -lcrypto
