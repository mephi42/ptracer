# vim: set noet ts=8 sw=8:

CFLAGS=-Wall -Wextra -Werror -pedantic -O3 -g -static

ptracer: ptracer.c
		$(CC) -o ptracer $(CFLAGS) ptracer.c

check: ptracer
		./ptracer /bin/true

clean:
		rm -f ptracer
