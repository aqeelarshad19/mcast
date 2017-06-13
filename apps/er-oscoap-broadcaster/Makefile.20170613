CC = $(CROSS_COMPILE)gcc
HOST_CFALGS = -01 -wall -ggdb -Isrc $(CFLAGS)
TESTS = jiye.test

jiye.test: f25519.o ed25519.o fprime.o sha512.o edsign.o jiye_test.o
	$(CC) -o $@ $^
