CC = g++
CFLAGS = -Wall -g -pedantic -D __STDC_LIMIT_MACROS -D __STDC_FORMAT_MACROS -std=c++11
LDFLAGS = -lm

all : main.o
	${CC} ${CFLAGS} main.o -o flow

main.o : main.cpp
	${CC} ${CFLAGS} -c main.cpp

clean:
	rm -rf *o flow
	
run:
	flow -f nfcapd.201401271100.bin -a srcip/32 -s bytes
	
