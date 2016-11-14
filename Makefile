IOCOW=io_dirtycow

TARGET_OS=$(shell uname -o 2> /dev/null || uname)

ifeq ($(TARGET_OS),GNU/Linux)
LDFLAGS+=-lpthread
endif

all:
	$(CC) -shared -fPIC -o $(IOCOW).so $(IOCOW).c $(shell pkg-config --cflags --libs r_util r_io)
	$(CC) -pie -fPIC -o cowpy cowpy.c $(LDFLAGS)

android and:
	ndk-gcc -pie -o cowpy cowpy.c

clean:
	rm -f io_dirtycow.so cowpy
