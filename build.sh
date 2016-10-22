#!/system/bin/sh
#
# script to build dirtycow on Termux
#
export T=/data/data/com.termux/files/usr
gcc -o io_dirtycow.so io_dirtycow.c -I $T/include/libr -L $T/lib -lr_util -lr_io -shared -fPIC
cp io_dirtycow.so .config/radare2/plugins
gcc -o cowpy cowpy.c
