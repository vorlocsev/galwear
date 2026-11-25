/* fsfreeze <-f|-u> <mountpoint>: FIFREEZE / FITHAW */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#define FIFREEZE 0xC0045877
#define FITHAW 0xC0045878
int main(int c, char **v)
{
	int fd, r;
	if (c != 3 || (strcmp(v[1], "-f") && strcmp(v[1], "-u"))) { fprintf(stderr, "usage: fsfreeze -f|-u <mnt>\n"); return 2; }
	fd = open(v[2], O_RDONLY);
	if (fd < 0) { perror("open"); return 1; }
	r = ioctl(fd, strcmp(v[1], "-f") ? FITHAW : FIFREEZE, 0);
	if (r) perror("ioctl");
	close(fd);
	return r ? 1 : 0;
}
