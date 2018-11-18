CFLAGS = -std=c99 -pedantic -Wall -Wextra -O0 -g
LDFLAGS += -ltls -lssl -lcrypto

geomys: main.o
	gcc -o geomys main.o $(CFLAGS) $(LDFLAGS)

main.o: main.c
	gcc -o main.o main.c -c $(CFLAGS)

key: 
	openssl req -newkey rsa:4096 -nodes -sha512 -x509 -days 3650 -nodes -subj "/C=UK/ST=London/O=Geomys/OU=gopherd/CN=localhost" -out geomys.pem -keyout geomys.key

clean:
	/bin/rm -f geomys *.o *.core geomys.pem geomys.key
