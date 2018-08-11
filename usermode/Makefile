CFLAGS :=-g -ggdb -O0 -w -I$(PWD)/../include/ -std=c11 -DPOSIX_BUILD

all: code_analizator

code_analizator: code_analizator.o
	gcc -o  $@ $< $(CFLAGS) -lsqlite3
	
code_analozator.o: code_analizator.c crc16.h $(PWD)/../include/verificator.h
	gcc -c code_analizator.c $(CFLAGS)

crc16.o: crc16.c crc16.h
	gcc -c crc16.c -o crc16.o $(CFLAGS)

.PHONY: clean
clean:
	rm -rf *.o code_analizator
