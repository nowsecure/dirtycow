IOCOW=io_dirtycow

all:
	$(CC) -shared -fPIC -o $(IOCOW).so $(IOCOW).c $(shell pkg-config --cflags --libs r_util r_io)
	$(CC) -pie -fPIC -o cowpy cowpy.c -lpthread

android and:
	ndk-gcc -pie -o cowpy cowpy.c

clean:
	rm -f io_dirtycow.so cowpy
