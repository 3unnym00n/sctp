sctp_proxy:sctp_proxy.c
	gcc -o sctp_proxy sctp_proxy.c hexdump.c -L/usr/local/lib/ -lsctp -Wl,-rpath=/usr/local/lib/
.PHONY: clean
clean: 
	rm -rf *.o sctp_proxy
