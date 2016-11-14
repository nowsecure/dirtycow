dirtycow
========

radare2 IO plugin that uses the Linux's dirtycow vulnerability
to allow the user to modify files owned by other users by
messing up the Copy-On-Write cache.


This plugin works on all linux kernels from 2007 (>= 2.6.22) until 2016 (< 4.8.3).

Details
-------

For more details about this exploit checkout [https://dirtycow.ninja](https://dirtycow.ninja)

Author
------

Written by Sergi Alvarez <pancake@nowsecure.com> at NowSecure


License
-------

This plugin and the cowpy tool are distributed under the terms of the LGPL, Copyright NowSecure 2016.


Installation
------------

The easiest way to install this r2 plugin is by using r2pm like this:

	$ r2pm -i dirtycow

The repository contains also a program named `cowpy` that will copy
the contents of one file into another one. Bear in mind that dirtycow
can't resize files, so you will not be able to write more bytes than
the ones in the destination file and your contents should be self
contained and properly terminated by an exit 0 if it's a script.


Usage
-----

To compile it, just run `build.sh` from inside a Termux shell in your Android device. You can also crosscompile it using the NDK, or just build it natively on your favourite Linux distro using `make`.

After that, r2 may list the new plugin:

	$ r2 -L | grep cow

And we can use it like this to patch any system bin.

	$ r2 dcow:///system/bin/sh


--pancake
