INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	g++ -I$(INC) -L$(LIB) tunclient.cpp -o tunclient -lssl -lcrypto -ldl -fpermissive
	g++ -I$(INC) -L$(LIB) tunserver.cpp -o tunserver -lssl -lcrypto -ldl -fpermissive

clean:
	rm -rf *~ tunclient tunserver
