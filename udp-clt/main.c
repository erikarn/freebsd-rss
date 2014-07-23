#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>


int
main(int argc, const char *argv[])
{
	const char *lcl_host, *rem_host;
	int port;
	struct sockaddr_in sin;
	int r;
	char buf[16384];
	int fd;
	struct in_addr lcl_addr;
	struct in_addr rem_addr;
	int i = 0;
	int cnt;

	/* XXX validate args */
	lcl_host = strdup(argv[1]);
	rem_host = strdup(argv[2]);
	port = atoi(argv[3]);
	cnt = atoi(argv[4]);

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		err(1, "socket");

	r = inet_aton(lcl_host, &lcl_addr);
	if (r < 0)
		err(1, "inet_aton");
	r = inet_aton(rem_host, &rem_addr);
	if (r < 0)
		err(1, "inet_aton");

	/* Local bind */
	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr = lcl_addr;

	r = bind(fd, (struct sockaddr *) &sin, sizeof(sin));
	if (r < 0)
		err(1, "bind");

	/* Remote bind */
	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr = rem_addr;

	/* XXX randomize buf contents */
	for (r = 0; r < sizeof(buf); r++) {
		buf[r] = r;
	}

	/* Loop sending */
	while (1) {
		int len;

		len = random() % 2048;
		len = 510;

		r = sendto(fd, buf, len, 0, (struct sockaddr *) &sin, sizeof(sin));
		if (r < 0) {
			if (errno == EWOULDBLOCK || errno == ENOBUFS) {
				usleep(10);
				continue;
			}
			warn("%s: sendto", __func__);
		}
		i++;
		if (i > cnt)
			break;
	}

	exit(0);
}
