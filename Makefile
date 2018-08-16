# vim: set noet ts=8 sw=8:

CFLAGS=-Wall -Wextra -Werror -pedantic -O3 -g -static

ptracer: ptracer.c
		$(CC) -o ptracer $(CFLAGS) ptracer.c

check: ptracer
		time -p ./ptracer /bin/true
		time -p ./pformatter >ptracer.txt

clean:
		rm -f ptracer
