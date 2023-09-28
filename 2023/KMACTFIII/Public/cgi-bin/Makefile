CC = gcc
CFLAGS = -O2 -Wall -I ..

all: adder

adder: adder.c
	$(CC) -o adder adder.c -no-pie -fno-stack-protector -z execstack

clean:
	rm -f adder *~