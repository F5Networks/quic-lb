quic_lb_test: quic_lb.c quic_lb_test.c
	gcc -g -o lb_test -D NOBIGIP quic_lb.c quic_lb_test.c -lcrypto -lssl -I. -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib/ -fsanitize=address  -O0
