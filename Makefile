IOCOW=io_dirtycow

all:
	$(CC) -o $(IOCOW).so $(IOCOW).c $(shell pkg-config --cflags --libs r_util r_io)
	$(CC) -o cowpy cowpy.c

clean:
	rm -f io_dirtycow.so cowpy
