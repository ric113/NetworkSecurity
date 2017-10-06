CC = g++

all:main

main:main.cpp
	$(CC) main.cpp -o main -lssl -lcrypto -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include 

clean:
	rm main