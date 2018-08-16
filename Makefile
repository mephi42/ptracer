CFLAGS=-Wall -Wextra -Werror -pedantic -O3 -g -static

ptracer: ptracer.c
		$(CC) -o ptracer $(CFLAGS) ptracer.c
