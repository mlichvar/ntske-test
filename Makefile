CFLAGS=-O2 -Wall -g $(shell pkg-config --cflags gnutls) -pthread
LDFLAGS=$(shell pkg-config --libs gnutls)

all: ntske-test

ntske-test: ntske-test.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o ntske-test
