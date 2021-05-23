crypttxt: crypttxt.c
	gcc -o crypttxt crypttxt.c -L/usr/local/opt/openssl@1.1/lib -I/usr/local/opt/openssl@1.1/include -lssl -lcrypto -lgmp
