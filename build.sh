#!/system/bin/sh
#
# script to build dirtycow on Termux
#
export T=/data/data/com.termux/files/usr
if [ -d "$T" ]; then
	echo "This script must be run in a native Android inside the Termux shell"
	exit 1
fi
gcc -o io_dirtycow.so io_dirtycow.c -I $T/include/libr -L $T/lib -lr_util -lr_io -shared -fPIC
mkdir -p ~/.config/radare2/plugins
cp -f io_dirtycow.so ~/.config/radare2/plugins
gcc -o cowpy cowpy.c
