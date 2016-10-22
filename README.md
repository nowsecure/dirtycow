dirtycow
========

radare2 IO plugin that uses the Linux's dirtycow vulnerability
to allow the user to modify files owned by other users by
messing up the Copy-On-Write cache.


This plugin works on all linux kernels from 2007 (>= 2.6.22) til 2016.


Usage
-----

To compile it, just run `build.sh` from inside a Termux shell in your Android device. You can also crosscompile it using the NDK, or just build it natively on your favourite Linux distro using `make`.

After that, r2 may list the new plugin:

	$ r2 -L | grep cow

And we can use it like this to patch any system bin.

	$ r2 dcow:///system/bin/sh


--pancake
